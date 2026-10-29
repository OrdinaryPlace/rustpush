//! Fixed-spool image artifacts. Callers never choose a filesystem path or URL.
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::{Conversation, Result, WorkerError, require_private_directory};

pub const MAX_IMAGE_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_IMAGE_DIMENSION: u32 = 8192;
pub const MAX_IMAGE_PIXELS: u64 = 16_000_000;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ImageBinding {
    pub artifact_id: String,
    pub sha256: String,
    pub mime: String,
    pub size: u64,
    pub width: u32,
    pub height: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u32,
    artifact_id: String,
    sha256: String,
    mime: String,
    size: u64,
    participants: Vec<String>,
}

fn artifact_id(value: &str) -> bool {
    (16..=64).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn read_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)
        .map_err(|_| WorkerError("invalid_image_artifact"))?;
    let info = file.metadata().map_err(|_| WorkerError("invalid_image_artifact"))?;
    if !info.is_file() || info.uid() != unsafe { libc::geteuid() } || info.mode() & 0o777 != 0o600
        || info.nlink() != 1 || info.len() > limit as u64 {
        return Err(WorkerError("invalid_image_artifact"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)
        .map_err(|_| WorkerError("invalid_image_artifact"))?;
    if bytes.len() > limit { return Err(WorkerError("invalid_image_artifact")); }
    Ok(bytes)
}

fn dimensions(width: u32, height: u32) -> Result<(u32, u32)> {
    if width == 0 || height == 0 || width > MAX_IMAGE_DIMENSION || height > MAX_IMAGE_DIMENSION
        || u64::from(width) * u64::from(height) > MAX_IMAGE_PIXELS {
        return Err(WorkerError("invalid_image_dimensions"));
    }
    Ok((width, height))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 { crc = (crc >> 1) ^ (0xedb88320u32 & (0u32.wrapping_sub(crc & 1))); }
    }
    !crc
}

fn png(bytes: &[u8]) -> Result<(u32, u32)> {
    if !bytes.starts_with(b"\x89PNG\r\n\x1a\n") { return Err(WorkerError("invalid_image_format")); }
    let mut offset = 8usize;
    let mut result = None;
    let mut image_data = false;
    while offset.checked_add(12).is_some_and(|end| end <= bytes.len()) {
        let length = u32::from_be_bytes(bytes[offset..offset+4].try_into().unwrap()) as usize;
        let end = offset.checked_add(length).and_then(|v| v.checked_add(12)).filter(|v| *v <= bytes.len())
            .ok_or(WorkerError("invalid_image_format"))?;
        let kind = &bytes[offset+4..offset+8];
        let data = &bytes[offset+8..end-4];
        if crc32(&bytes[offset+4..end-4]) != u32::from_be_bytes(bytes[end-4..end].try_into().unwrap()) {
            return Err(WorkerError("invalid_image_format"));
        }
        if offset == 8 {
            if kind != b"IHDR" || length != 13 || data[10] != 0 || data[11] != 0 || data[12] > 1
                || !matches!((data[8], data[9]), (1|2|4|8|16, 0) | (8|16, 2) | (1|2|4|8, 3) | (8|16, 4|6)) {
                return Err(WorkerError("invalid_image_format"));
            }
            result = Some(dimensions(u32::from_be_bytes(data[..4].try_into().unwrap()), u32::from_be_bytes(data[4..8].try_into().unwrap()))?);
        } else if kind == b"IHDR" { return Err(WorkerError("invalid_image_format")); }
        if kind == b"IDAT" && length > 0 { image_data = true; }
        if kind == b"IEND" {
            return if length == 0 && end == bytes.len() && image_data { result.ok_or(WorkerError("invalid_image_format")) }
                else { Err(WorkerError("invalid_image_format")) };
        }
        offset = end;
    }
    Err(WorkerError("invalid_image_format"))
}

fn jpeg(bytes: &[u8]) -> Result<(u32, u32)> {
    if !bytes.starts_with(&[0xff,0xd8]) || !bytes.ends_with(&[0xff,0xd9]) { return Err(WorkerError("invalid_image_format")); }
    let mut offset = 2usize;
    let mut result = None;
    while offset + 4 <= bytes.len() {
        if bytes[offset] != 0xff { return Err(WorkerError("invalid_image_format")); }
        while offset < bytes.len() && bytes[offset] == 0xff { offset += 1; }
        let marker = *bytes.get(offset).ok_or(WorkerError("invalid_image_format"))?;
        offset += 1;
        if marker == 0xd8 || marker == 0xd9 || marker == 0x00 || (0xd0..=0xd7).contains(&marker) { return Err(WorkerError("invalid_image_format")); }
        let length = bytes.get(offset..offset+2).map(|v| u16::from_be_bytes(v.try_into().unwrap()) as usize)
            .filter(|v| *v >= 2).ok_or(WorkerError("invalid_image_format"))?;
        let end = offset.checked_add(length).filter(|v| *v <= bytes.len()-2).ok_or(WorkerError("invalid_image_format"))?;
        if matches!(marker, 0xc0|0xc1|0xc2) {
            if length < 8 || bytes[offset+2] != 8 || result.is_some() { return Err(WorkerError("invalid_image_format")); }
            result = Some(dimensions(u16::from_be_bytes(bytes[offset+5..offset+7].try_into().unwrap()) as u32,
                u16::from_be_bytes(bytes[offset+3..offset+5].try_into().unwrap()) as u32)?);
        }
        if marker == 0xda {
            return if end < bytes.len()-2 { result.ok_or(WorkerError("invalid_image_format")) } else { Err(WorkerError("invalid_image_format")) };
        }
        offset = end;
    }
    Err(WorkerError("invalid_image_format"))
}

pub fn read_artifact(directory: &Path, id: &str, conversation: &Conversation) -> Result<(ImageBinding, Vec<u8>)> {
    if !artifact_id(id) { return Err(WorkerError("invalid_image_artifact")); }
    require_private_directory(directory)?;
    let spool = directory.join("outbound-media");
    require_private_directory(&spool)?;
    let manifest: Manifest = serde_json::from_slice(&read_file(&spool.join(format!("{id}.json")), 16 * 1024)?)
        .map_err(|_| WorkerError("invalid_image_artifact"))?;
    let mut recipients = manifest.participants.clone(); recipients.sort();
    let mut expected = conversation.participants.clone(); expected.sort();
    if manifest.format != 1 || manifest.artifact_id != id || recipients != expected || recipients.len() != 2
        || recipients[0] == recipients[1] || manifest.size == 0 || manifest.size > MAX_IMAGE_BYTES as u64
        || manifest.sha256.len() != 64 || !manifest.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(WorkerError("invalid_image_artifact"));
    }
    let bytes = read_file(&spool.join(format!("{id}.bin")), MAX_IMAGE_BYTES)?;
    if bytes.len() as u64 != manifest.size || format!("{:x}", Sha256::digest(&bytes)) != manifest.sha256 {
        return Err(WorkerError("image_artifact_changed"));
    }
    let (width,height) = match manifest.mime.as_str() {
        "image/png" => png(&bytes)?, "image/jpeg" => jpeg(&bytes)?, _ => return Err(WorkerError("invalid_image_format")),
    };
    Ok((ImageBinding { artifact_id: id.into(), sha256: manifest.sha256, mime: manifest.mime, size: manifest.size, width, height }, bytes))
}

impl ImageBinding {
    pub fn uti(&self) -> &'static str { if self.mime == "image/png" { "public.png" } else { "public.jpeg" } }
    pub fn name(&self) -> &'static str { if self.mime == "image/png" { "image.png" } else { "image.jpg" } }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    const ID: &str = "image_0123456789abcdef";
    const PNG: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAAAAAA6fptVAAAACklEQVR4nGNgAAAAAgABSK+kcQAAAABJRU5ErkJggg==";
    struct Fixture(std::path::PathBuf);
    impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
    fn fixture() -> (Fixture, Conversation, serde_json::Value) {
        let path = std::env::temp_dir().join(format!("buddy-media-test-{}", uuid::Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        fs::DirBuilder::new().mode(0o700).create(path.join("outbound-media")).unwrap();
        let conversation = Conversation { participants: vec!["mailto:buddy@example.test".into(), "tel:+15555550100".into()],
            sender_guid: None, cv_name: None, after_guid: None };
        let bytes = STANDARD.decode(PNG).unwrap();
        crate::atomic_private_write(&path.join(format!("outbound-media/{ID}.bin")), &bytes).unwrap();
        let manifest = serde_json::json!({"format":1,"artifact_id":ID,"sha256":format!("{:x}",Sha256::digest(&bytes)),
            "mime":"image/png","size":bytes.len(),"participants":conversation.participants});
        write_manifest(&path, &manifest);
        (Fixture(path), conversation, manifest)
    }
    fn write_manifest(path: &Path, value: &serde_json::Value) {
        crate::atomic_private_write(&path.join(format!("outbound-media/{ID}.json")), &serde_json::to_vec(value).unwrap()).unwrap();
    }
    #[test]
    fn approved_png_binding_is_content_and_audience_bound() {
        let (directory, mut conversation, _) = fixture();
        conversation.participants.reverse();
        let (binding, bytes) = read_artifact(&directory.0, ID, &conversation).unwrap();
        assert_eq!((binding.width,binding.height,binding.size), (1,1,bytes.len() as u64));
        assert_eq!((binding.uti(),binding.name()), ("public.png","image.png"));
        conversation.participants[0] = "tel:+15555550999".into();
        assert!(read_artifact(&directory.0, ID, &conversation).is_err());
    }
    #[test]
    fn rejects_paths_urls_unknown_fields_duplicates_hash_size_and_mime_changes() {
        let (directory, conversation, manifest) = fixture();
        for id in ["../secret", "https://example.test/image", "/state/auth.json", "IMAGE_0123456789ABCDEF", "small"] {
            assert!(read_artifact(&directory.0, id, &conversation).is_err());
        }
        for (key,value) in [("path", serde_json::json!("/state/auth.json")), ("sha256", serde_json::json!("0".repeat(64))),
            ("size", serde_json::json!(0)), ("size", serde_json::json!(MAX_IMAGE_BYTES+1)),
            ("mime", serde_json::json!("image/jpeg")), ("mime", serde_json::json!("image/svg+xml"))] {
            let mut changed = manifest.clone(); changed[key] = value;
            write_manifest(&directory.0, &changed);
            assert!(read_artifact(&directory.0, ID, &conversation).is_err());
        }
        let path = directory.0.join(format!("outbound-media/{ID}.json"));
        crate::atomic_private_write(&path, b"{\"format\":1,\"format\":1}").unwrap();
        assert!(read_artifact(&directory.0, ID, &conversation).is_err());
    }
    #[test]
    fn rejects_public_modes_symlinks_hardlinks_and_special_files() {
        let (directory, conversation, _) = fixture();
        let path = directory.0.join(format!("outbound-media/{ID}.bin"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_artifact(&directory.0, ID, &conversation).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let other = directory.0.join("private-image"); fs::rename(&path, &other).unwrap();
        symlink(&other, &path).unwrap();
        assert!(read_artifact(&directory.0, ID, &conversation).is_err()); fs::remove_file(&path).unwrap();
        fs::hard_link(&other, &path).unwrap();
        assert!(read_artifact(&directory.0, ID, &conversation).is_err()); fs::remove_file(&path).unwrap();
        let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        assert!(read_artifact(&directory.0, ID, &conversation).is_err());
    }
    #[test]
    fn dimensions_and_headers_reject_bombs_corruption_and_trailing_bytes() {
        for (width,height) in [(0,1),(1,0),(8193,1),(8192,8192)] { assert!(dimensions(width,height).is_err()); }
        let original = STANDARD.decode(PNG).unwrap();
        assert_eq!(png(&original).unwrap(), (1,1));
        let mut bytes = original.clone(); bytes[30] ^= 1; assert!(png(&bytes).is_err());
        let mut bytes = original.clone(); bytes.push(0); assert!(png(&bytes).is_err());
        assert!(png(&original[..original.len()-1]).is_err());
        let jpeg = vec![0xff,0xd8,0xff,0xc0,0,11,8,0,1,0,1,1,1,0x11,0,0xff,0xda,0,8,1,1,0,0,63,0,0,0xff,0xd9];
        assert_eq!(super::jpeg(&jpeg).unwrap(), (1,1));
        assert!(super::jpeg(&jpeg[..jpeg.len()-1]).is_err());
        assert!(super::jpeg(&original).is_err());
    }
}
