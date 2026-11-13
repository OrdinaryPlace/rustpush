//! Request-bound receive descriptors. Only an explicit host command downloads data.
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustpush::{APSConnectionResource, AttachmentType, MMCSFile, Message, MessageInst,
    MessagePart, MessageType, NormalMessage};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use buddy_imessage::{Result, WorkerError, atomic_private_write, require_private_directory, valid_handle};
use buddy_imessage::media::{self, MAX_MEDIA_BYTES, MediaType};

const MAX_PENDING: usize = 32;
const MAX_INLINE_BYTES: usize = 20 * 1024 * 1024;
const RETENTION: Duration = Duration::from_secs(600);
const STAGED_RETENTION: Duration = Duration::from_secs(120);
const MAX_STAGED_BYTES: u64 = 50 * 1024 * 1024;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(25);
const UNAVAILABLE: WorkerError = WorkerError("inbound_image_unavailable");

enum Source {
    Inline(Vec<u8>),
    Remote(MMCSFile),
}

pub struct PendingImage {
    message_guid: String,
    artifact_id: String,
    mime: MediaType,
    source: Source,
    received: Instant,
}

impl PendingImage {
    fn inline_bytes(&self) -> usize {
        match &self.source { Source::Inline(bytes) => bytes.len(), Source::Remote(_) => 0 }
    }
}

#[derive(Default)]
pub struct PendingImages(VecDeque<PendingImage>);

impl PendingImages {
    pub fn prune(&mut self) { self.expire(Instant::now()); }

    fn expire(&mut self, now: Instant) {
        while self.0.front().is_some_and(|item| now.saturating_duration_since(item.received) >= RETENTION) {
            self.0.pop_front();
        }
    }

    fn remember(&mut self, mut image: PendingImage) -> Option<String> {
        self.expire(image.received);
        if self.0.iter().any(|item| item.message_guid == image.message_guid) {
            return None;
        }
        let inline_bytes = image.inline_bytes();
        let mut retained = self.0.iter().map(PendingImage::inline_bytes).sum::<usize>();
        while self.0.len() >= MAX_PENDING || retained + inline_bytes > MAX_INLINE_BYTES {
            retained -= self.0.pop_front()?.inline_bytes();
        }
        let artifact_id = format!("incoming_{}", Uuid::new_v4().simple());
        image.artifact_id = artifact_id.clone();
        self.0.push_back(image);
        Some(artifact_id)
    }

    pub fn take(&mut self, message_guid: &str, artifact_id: &str) -> Result<PendingImage> {
        self.prune();
        let index = self.0.iter().position(|item| item.message_guid == message_guid && item.artifact_id == artifact_id)
            .ok_or(UNAVAILABLE)?;
        self.0.remove(index).ok_or(UNAVAILABLE)
    }
}

pub fn valid_binding(message_guid: &str, artifact_id: &str) -> bool {
    Uuid::parse_str(message_guid).is_ok_and(|id| id.to_string().to_uppercase() == message_guid)
        && artifact_id.strip_prefix("incoming_").is_some_and(valid_token)
}

fn valid_token(token: &str) -> bool {
    token.len() == 32 && token.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn spool_file(name: &str) -> bool {
    let image = name.strip_prefix("incoming_").and_then(|name| name.strip_suffix(".bin"));
    let temp = name.strip_prefix(".worker-").and_then(|name| name.strip_suffix(".tmp"));
    image.is_some_and(valid_token) || temp.is_some_and(|id| Uuid::parse_str(id)
        .is_ok_and(|uuid| uuid.to_string() == id))
}

fn clean_spool(spool: &Path) -> Result<(usize, u64)> {
    const SPOOL_UNAVAILABLE: WorkerError = WorkerError("inbound_image_spool_unavailable");
    require_private_directory(spool)?;
    let mut retained = (0usize, 0u64);
    for entry in fs::read_dir(spool).map_err(|_| SPOOL_UNAVAILABLE)? {
        let entry = entry.map_err(|_| SPOOL_UNAVAILABLE)?;
        if !entry.file_name().to_str().is_some_and(spool_file) { continue; }
        let info = match fs::symlink_metadata(entry.path()) {
            Ok(info) => info,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return Err(SPOOL_UNAVAILABLE),
        };
        if !info.is_file() || info.mode() & 0o777 != 0o600
            || info.uid() != unsafe { libc::geteuid() } || info.nlink() != 1 {
            continue;
        }
        if info.modified().ok().and_then(|time| time.elapsed().ok()).is_some_and(|age| age >= STAGED_RETENTION) {
            match fs::remove_file(entry.path()) {
                Ok(()) => {},
                Err(error) if error.kind() == io::ErrorKind::NotFound => {},
                Err(_) => return Err(SPOOL_UNAVAILABLE),
            }
        } else {
            retained.0 += 1;
            retained.1 = retained.1.saturating_add(info.len());
        }
    }
    Ok(retained)
}

pub fn clean_if_present(directory: &Path) {
    let _ = clean_spool(&directory.join("inbound-media"));
}

fn source(normal: &NormalMessage) -> Option<(Source, MediaType)> {
    let mut parts = normal.parts.0.iter().filter_map(|item| {
        match &item.part { MessagePart::Attachment(file) => Some(file), _ => None }
    });
    let attachment = parts.next()?;
    if parts.next().is_some() || attachment.iris { return None; }
    let mime = match attachment.mime.as_str() {
        "image/png" => MediaType::Png,
        "image/jpeg" => MediaType::Jpeg,
        _ => return None,
    };
    let source = match &attachment.a_type {
        AttachmentType::Inline(bytes) if !bytes.is_empty() && bytes.len() <= MAX_MEDIA_BYTES =>
            Source::Inline(bytes.clone()),
        AttachmentType::MMCS(files) if files.len() == 1 && files[0].is_bounded_attachment(MAX_MEDIA_BYTES) =>
            Source::Remote(files[0].clone()),
        _ => return None,
    };
    Some((source, mime))
}

pub fn describe(handles: &[String], message: &MessageInst, pending: &Mutex<PendingImages>, current: bool) -> Option<Value> {
    let Message::Message(normal) = &message.message else { return None; };
    if !normal.parts.has_attachments() || normal.service != MessageType::IMessage || normal.app.is_some()
        || message.verification_failed {
        return None;
    }
    let sender = message.sender.as_ref()?;
    let audience = &message.conversation.as_ref()?.participants;
    if handles.contains(sender) || !valid_handle(sender) || audience.len() != 2
        || !audience.contains(sender) || audience.iter().filter(|handle| handles.contains(handle)).count() != 1
        || !audience.iter().all(|handle| valid_handle(handle))
        || !Uuid::parse_str(&message.id).is_ok_and(|id| id.to_string().to_uppercase() == message.id) {
        return None;
    }
    let Some((source, mime)) = (if current { source(normal) } else { None }) else {
        return Some(json!({"status":"unsupported"}));
    };
    let image = PendingImage { message_guid: message.id.clone(), artifact_id: String::new(),
        mime, source, received: Instant::now() };
    Some(match pending.lock().ok()?.remember(image) {
        Some(artifact_id) => json!({"status":"available","artifact_id":artifact_id}),
        None => json!({"status":"unsupported"}),
    })
}

#[derive(Clone)]
struct BoundedBytes {
    limit: usize,
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl Write for BoundedBytes {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut bytes = self.bytes.lock().map_err(|_| io::ErrorKind::Other)?;
        if data.len() > self.limit.saturating_sub(bytes.len()) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        bytes.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

pub async fn fetch(image: PendingImage, directory: &Path, connection: &APSConnectionResource, request_id: &str) -> Result<Value> {
    let bytes = match image.source {
        Source::Inline(bytes) => bytes,
        Source::Remote(file) => {
            let buffer = BoundedBytes { limit: file.size, bytes: Arc::new(Mutex::new(Vec::new())) };
            tokio::time::timeout(DOWNLOAD_TIMEOUT, file.get_attachment_bounded(connection, buffer.clone(), MAX_MEDIA_BYTES))
                .await.map_err(|_| WorkerError("inbound_image_timeout"))?.map_err(|_| UNAVAILABLE)?;
            let bytes = std::mem::take(&mut *buffer.bytes.lock().map_err(|_| UNAVAILABLE)?);
            if bytes.len() != file.size { return Err(UNAVAILABLE); }
            bytes
        }
    };
    stage(directory, &image.message_guid, &image.artifact_id, image.mime, &bytes, request_id)
}

fn stage(directory: &Path, message_guid: &str, artifact_id: &str, mime: MediaType, bytes: &[u8], request_id: &str) -> Result<Value> {
    media::validate_image(bytes, mime)?;
    require_private_directory(directory)?;
    let spool = directory.join("inbound-media");
    match fs::DirBuilder::new().mode(0o700).create(&spool) {
        Ok(()) => {},
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {},
        Err(_) => return Err(WorkerError("inbound_image_spool_unavailable")),
    }
    let (count, retained_bytes) = clean_spool(&spool)?;
    if count >= MAX_PENDING || retained_bytes.saturating_add(bytes.len() as u64) > MAX_STAGED_BYTES {
        return Err(WorkerError("inbound_image_spool_unavailable"));
    }
    let path = spool.join(format!("{artifact_id}.bin"));
    let reservation = OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW)
        .open(&path).map_err(|_| WorkerError("inbound_image_spool_unavailable"))?;
    drop(reservation);
    if let Err(error) = atomic_private_write(&path, bytes) {
        let _ = fs::remove_file(&path);
        return Err(error);
    }
    Ok(json!({"event":"inbound_image","request_id":request_id,"message_guid":message_guid,
        "artifact_id":artifact_id,"mime":mime.mime(),"size":bytes.len(),"sha256":format!("{:x}",Sha256::digest(bytes))}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use rustpush::{Attachment, ConversationData, IndexedMessagePart};
    use std::os::unix::fs::symlink;

    const GUID: &str = "12345678-1234-4ABC-8ABC-123456789ABC";

    fn png() -> Vec<u8> {
        STANDARD.decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAAAAAA6fptVAAAACklEQVR4nGNgAAAAAgABSK+kcQAAAABJRU5ErkJggg==").unwrap()
    }

    fn inline_message(bytes: Vec<u8>) -> (Vec<String>, MessageInst) {
        let own = vec!["mailto:local@example.test".into()];
        let sender = "mailto:remote@example.test";
        let audience = ConversationData { participants: vec![own[0].clone(), sender.into()],
            sender_guid: None, cv_name: None, after_guid: None };
        let mut message = NormalMessage::new("Describe this image".into(), MessageType::IMessage);
        message.parts.0.insert(0, IndexedMessagePart { part: MessagePart::Attachment(Attachment {
            a_type: AttachmentType::Inline(bytes), part: 0, uti_type: "public.png".into(),
            mime: "image/png".into(), name: "unused.png".into(), iris: false,
        }), idx: Some(0), ext: None });
        let mut event = MessageInst::new(audience, sender, Message::Message(message));
        event.id = GUID.into();
        (own, event)
    }

    #[test]
    fn pending_descriptor_exposes_no_bytes_and_is_bound_to_exact_guid_and_opaque_token() {
        let (own, event) = inline_message(png());
        let pending = Mutex::new(PendingImages::default());
        let value = describe(&own, &event, &pending, true).unwrap();
        assert_eq!(value["status"], "available");
        assert_eq!(value.as_object().unwrap().len(), 2);
        let token = value["artifact_id"].as_str().unwrap();
        assert!(valid_binding(GUID, token));
        assert_eq!(describe(&own, &event, &pending, true), Some(json!({"status":"unsupported"})));
        let mut pending = pending.lock().unwrap();
        assert!(pending.take(GUID, "incoming_00000000000000000000000000000000").is_err());
        assert!(pending.take("00000000-0000-0000-0000-000000000000", token).is_err());
        assert!(matches!(pending.take(GUID, token).unwrap().source, Source::Inline(bytes) if bytes == png()));
        assert!(pending.take(GUID, token).is_err());
    }

    #[test]
    fn history_oversized_and_unverified_images_never_become_fetchable() {
        let (own, mut event) = inline_message(vec![0; MAX_MEDIA_BYTES + 1]);
        let pending = Mutex::new(PendingImages::default());
        assert_eq!(describe(&own, &event, &pending, true), Some(json!({"status":"unsupported"})));
        let (_, current) = inline_message(png());
        assert_eq!(describe(&own, &current, &pending, false), Some(json!({"status":"unsupported"})));
        event.verification_failed = true;
        assert!(describe(&own, &event, &pending, true).is_none());
        assert!(pending.lock().unwrap().0.is_empty());
    }

    #[test]
    fn remote_descriptor_rejects_non_apple_urls_and_mismatched_object_without_network() {
        let file = MMCSFile { signature: vec![1; 21], key: vec![2; 32], object: "12345".into(),
            url: "https://content.example.icloud.com/12345".into(), size: 42 };
        assert!(file.is_bounded_attachment(42));
        assert!(!file.is_bounded_attachment(41));
        for url in [
            "https://content.example.icloud.com/9999",
            "http://content.example.icloud.com/12345",
            "https://content.example.icloud.com:444/12345",
            "https://content.example.icloud.com.example.test/12345",
            "https://content.example.icloud.com/12345?query",
            "https://user@content.example.icloud.com/12345",
        ] {
            assert!(!MMCSFile { url: url.into(), ..file.clone() }.is_bounded_attachment(42));
        }
    }

    #[test]
    fn only_validated_bytes_are_written_to_private_spool() {
        let directory = std::env::temp_dir().join(format!("receive-fixture-{}", Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let token = "incoming_12345678123412341234123456789012";
        assert!(stage(&directory, GUID, token, MediaType::Png, b"not an image", "request").is_err());
        assert!(!directory.join("inbound-media").exists());
        symlink(&directory, directory.join("inbound-media")).unwrap();
        assert!(stage(&directory, GUID, token, MediaType::Png, &png(), "request").is_err());
        fs::remove_file(directory.join("inbound-media")).unwrap();
        let evidence = stage(&directory, GUID, token, MediaType::Png, &png(), "request").unwrap();
        assert_eq!(evidence["request_id"], "request");
        assert_eq!(evidence["message_guid"], GUID);
        assert_eq!(evidence["artifact_id"], token);
        assert_eq!(evidence["mime"], "image/png");
        assert_eq!(evidence["size"], png().len());
        assert_eq!(evidence["sha256"], format!("{:x}", Sha256::digest(png())));
        assert!(evidence.get("path").is_none());
        let file = directory.join("inbound-media").join(format!("{token}.bin"));
        assert_eq!(fs::read(&file).unwrap(), png());
        assert_eq!(fs::metadata(file).unwrap().mode() & 0o777, 0o600);
        assert!(stage(&directory, GUID, token, MediaType::Png, &png(), "request").is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
