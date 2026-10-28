// Modified 2026-10-27 for OrdinaryPlace Buddy. SSPL v1; see repository LICENSE.
//! Private state and JSONL protocol helpers. Validation never connects to Apple.

use std::collections::{BTreeSet, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const MAX_EXPORT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_COMMAND_BYTES: usize = 128 * 1024;

/// Static categories only. Never format a source parser/crypto/network error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkerError(pub &'static str);

pub type Result<T> = std::result::Result<T, WorkerError>;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionExport {
    pub version: u32,
    pub aps_state: String,
    pub ids_users: String,
    pub ids_identity: String,
    pub preferred_handle: String,
    pub hardware_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

#[derive(Serialize)]
pub struct Validation {
    pub version_supported: bool,
    pub aps_format_valid: bool,
    pub ids_users_format_valid: bool,
    pub ids_identity_format_valid: bool,
    pub hardware_format_valid: bool,
    pub preferred_handle_matches: bool,
    pub registered_user_count: usize,
    pub own_handle_count: usize,
    pub keystore_format_valid: bool,
    pub keystore_references_present: bool,
    pub network_contacted: bool,
}

/// Only parses outer plist values, never resolves cryptographic key references
/// or initializes any transport, registration, or keystore global.
pub fn validate_export(bundle: &SessionExport, keystore_bytes: &[u8]) -> Result<Validation> {
    if bundle.version != 1 { return Err(WorkerError("unsupported_export_version")); }
    let aps: plist::Value = plist::from_bytes(bundle.aps_state.as_bytes()).map_err(|_| WorkerError("invalid_aps_format"))?;
    let users: plist::Value = plist::from_bytes(bundle.ids_users.as_bytes()).map_err(|_| WorkerError("invalid_ids_users_format"))?;
    let identity: plist::Value = plist::from_bytes(bundle.ids_identity.as_bytes()).map_err(|_| WorkerError("invalid_ids_identity_format"))?;
    let store: plist::Value = plist::from_bytes(keystore_bytes).map_err(|_| WorkerError("invalid_keystore_format"))?;
    let aps_dict = aps.as_dictionary().ok_or(WorkerError("invalid_aps_format"))?;
    if aps_dict.get("token").and_then(plist::Value::as_data).is_none_or(|token| token.len() != 32)
        || !aps_dict.contains_key("keypair") {
        return Err(WorkerError("incomplete_registered_aps_state"));
    }
    if identity.as_dictionary().is_none() || store.as_dictionary().is_none() {
        return Err(WorkerError("invalid_private_state_shape"));
    }
    let keys = store.as_dictionary().and_then(|s| s.get("keys")).and_then(plist::Value::as_dictionary)
        .filter(|keys| !keys.is_empty()).ok_or(WorkerError("missing_coupled_keystore"))?;
    validate_key_references(&aps, keys)?;
    validate_key_references(&users, keys)?;
    let users = users.as_array().ok_or(WorkerError("invalid_ids_users_format"))?;
    if users.is_empty() { return Err(WorkerError("missing_registered_users")); }
    let mut own_handles = BTreeSet::new();
    for user in users {
        let registrations = user.as_dictionary().and_then(|u| u.get("registration"))
            .and_then(plist::Value::as_dictionary).ok_or(WorkerError("missing_madrid_registration"))?;
        let handles = registrations.get("com.apple.madrid").and_then(plist::Value::as_dictionary)
            .and_then(|r| r.get("handles")).and_then(plist::Value::as_array)
            .ok_or(WorkerError("missing_madrid_registration"))?;
        for handle in handles {
            let handle = handle.as_string().ok_or(WorkerError("invalid_registered_handle"))?;
            if !valid_handle(handle) { return Err(WorkerError("invalid_registered_handle")); }
            own_handles.insert(handle.to_string());
        }
    }
    if !own_handles.contains(&bundle.preferred_handle) { return Err(WorkerError("preferred_handle_mismatch")); }
    hardware_json(bundle)?;
    Ok(Validation {
        version_supported: true, aps_format_valid: true, ids_users_format_valid: true,
        ids_identity_format_valid: true, hardware_format_valid: true,
        preferred_handle_matches: true, registered_user_count: users.len(),
        own_handle_count: own_handles.len(), keystore_format_valid: true,
        keystore_references_present: true,
        network_contacted: false,
    })
}

fn validate_key_references(value: &plist::Value, keys: &plist::Dictionary) -> Result<()> {
    match value {
        plist::Value::Dictionary(dictionary) => {
            for (name, child) in dictionary {
                if name == "private" {
                    let alias = child.as_string().ok_or(WorkerError("unsupported_private_key_shape"))?;
                    if !keys.contains_key(alias) { return Err(WorkerError("keystore_reference_missing")); }
                }
                validate_key_references(child, keys)?;
            }
        }
        plist::Value::Array(values) => { for child in values { validate_key_references(child, keys)?; } }
        _ => {}
    }
    Ok(())
}

pub fn hardware_json(bundle: &SessionExport) -> Result<Value> {
    if bundle.hardware_key.len() > 2 * 1024 * 1024 { return Err(WorkerError("hardware_key_too_large")); }
    let clean: String = bundle.hardware_key.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = STANDARD.decode(clean).map_err(|_| WorkerError("invalid_hardware_encoding"))?;
    let json: Value = serde_json::from_slice(&bytes).map_err(|_| WorkerError("invalid_hardware_format"))?;
    let inner = json.get("inner").and_then(Value::as_object).ok_or(WorkerError("unsupported_hardware_shape"))?;
    for key in ["product_name", "platform_serial_number", "platform_uuid", "root_disk_uuid", "board_id", "os_build_num", "mlb"] {
        if inner.get(key).and_then(Value::as_str).is_none_or(str::is_empty) {
            return Err(WorkerError("incomplete_hardware_format"));
        }
    }
    Ok(json)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Conversation {
    pub participants: Vec<String>,
    #[serde(default)] pub sender_guid: Option<String>,
    #[serde(default)] pub cv_name: Option<String>,
    #[serde(default)] pub after_guid: Option<String>,
}

impl Conversation {
    pub fn validate(&self, own_handle: &str) -> Result<()> {
        if self.participants.is_empty() || self.participants.len() > 32 { return Err(WorkerError("invalid_conversation")); }
        let mut seen = HashSet::new();
        for handle in &self.participants {
            if !valid_handle(handle) || !seen.insert(handle) { return Err(WorkerError("invalid_conversation")); }
        }
        if !self.participants.iter().any(|h| h == own_handle) { return Err(WorkerError("conversation_missing_own_handle")); }
        for guid in [&self.sender_guid, &self.after_guid].into_iter().flatten() {
            if uuid::Uuid::parse_str(guid).is_err() { return Err(WorkerError("invalid_conversation_guid")); }
        }
        Ok(())
    }

    pub fn protocol(&self) -> rustpush::ConversationData {
        rustpush::ConversationData { participants: self.participants.clone(),
            sender_guid: self.sender_guid.clone(), cv_name: self.cv_name.clone(), after_guid: self.after_guid.clone() }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Validate { id: String },
    Connect { id: String },
    Disconnect { id: String },
    Status { id: String, operation_id: String },
    SendText { id: String, conversation: Conversation, text: String },
    SendPoll { id: String, conversation: Conversation, question: String, options: Vec<String> },
    PrepareText { id: String, conversation: Conversation, text: String },
    PreparePoll { id: String, conversation: Conversation, question: String, options: Vec<String> },
    Dispatch { id: String, operation_id: String },
}

impl Command {
    pub fn id(&self) -> &str {
        match self {
            Self::Validate { id } | Self::Connect { id } | Self::Disconnect { id }
            | Self::Status { id, .. } | Self::SendText { id, .. } | Self::SendPoll { id, .. }
            | Self::PrepareText { id, .. } | Self::PreparePoll { id, .. } | Self::Dispatch { id, .. } => id,
        }
    }
}

pub fn parse_command(line: &[u8]) -> Result<Command> {
    if line.len() > MAX_COMMAND_BYTES { return Err(WorkerError("command_too_large")); }
    let command: Command = serde_json::from_slice(line).map_err(|_| WorkerError("invalid_command"))?;
    if !valid_operation_id(command.id()) { return Err(WorkerError("invalid_request_id")); }
    Ok(command)
}

pub fn valid_operation_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
        && id != "." && id != ".."
}

pub fn valid_handle(handle: &str) -> bool {
    if handle.is_empty() || handle.len() > 320 || handle.chars().any(|c| c.is_whitespace() || c.is_control()) { return false; }
    if let Some(number) = handle.strip_prefix("tel:+") { return !number.is_empty() && number.bytes().all(|c| c.is_ascii_digit()); }
    if let Some(email) = handle.strip_prefix("mailto:") {
        return email.split_once('@').is_some_and(|(name, domain)| !name.is_empty() && !domain.is_empty() && !domain.contains('@'));
    }
    false
}

pub fn fingerprint<T: Serialize>(value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| WorkerError("invalid_operation"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub fn require_private_directory(path: &Path) -> Result<()> {
    if !path.is_absolute() { return Err(WorkerError("private_directory_guard")); }
    let metadata = fs::symlink_metadata(path).map_err(|_| WorkerError("private_directory_guard"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(WorkerError("private_directory_guard"));
    }
    Ok(())
}

pub fn private_read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)
        .map_err(|_| WorkerError("private_file_guard"))?;
    let metadata = file.metadata().map_err(|_| WorkerError("private_file_guard"))?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600 || metadata.len() > limit as u64 {
        return Err(WorkerError("private_file_guard"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file).take((limit + 1) as u64).read_to_end(&mut bytes).map_err(|_| WorkerError("private_file_read_failed"))?;
    if bytes.len() > limit { return Err(WorkerError("private_file_too_large")); }
    Ok(bytes)
}

pub fn atomic_private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or(WorkerError("private_write_failed"))?;
    require_private_directory(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o777 != 0o600 { return Err(WorkerError("private_file_guard")); }
    }
    let temp = parent.join(format!(".worker-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW)
            .open(&temp).map_err(|_| WorkerError("private_write_failed"))?;
        file.write_all(bytes).and_then(|_| file.sync_all()).map_err(|_| WorkerError("private_write_failed"))?;
        fs::rename(&temp, path).map_err(|_| WorkerError("private_write_failed"))?;
        File::open(parent).and_then(|dir| dir.sync_all()).map_err(|_| WorkerError("private_write_failed"))
    })();
    if result.is_err() { let _ = fs::remove_file(&temp); }
    result
}

pub fn load_bundle(export_path: &Path, work_dir: &Path) -> Result<SessionExport> {
    require_private_directory(work_dir)?;
    let runtime = work_dir.join("runtime-session.json");
    let path = if runtime.exists() { &runtime } else { export_path };
    let bytes = private_read(path, MAX_EXPORT_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|_| WorkerError("invalid_export"))
}

pub fn save_bundle(bundle: &SessionExport, work_dir: &Path) -> Result<()> {
    let bytes = serde_json::to_vec(bundle).map_err(|_| WorkerError("state_persist_failed"))?;
    atomic_private_write(&work_dir.join("runtime-session.json"), &bytes)
}

pub fn operation_path(work_dir: &Path, id: &str) -> Result<PathBuf> {
    if !valid_operation_id(id) { return Err(WorkerError("invalid_operation_id")); }
    Ok(work_dir.join(format!("operation-{id}.json")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xml(value: &plist::Value) -> String {
        let mut bytes = Vec::new();
        plist::to_writer_xml(&mut bytes, value).unwrap();
        String::from_utf8(bytes).unwrap()
    }

    fn synthetic_export() -> (SessionExport, Vec<u8>) {
        use plist::{Dictionary, Value as P};
        let keypair = |alias: &str| P::Dictionary(Dictionary::from_iter([
            ("private".to_string(), P::String(alias.into())), ("cert".to_string(), P::Data(vec![0])),
        ]));
        let aps = P::Dictionary(Dictionary::from_iter([
            ("token".to_string(), P::Data(vec![0; 32])), ("keypair".to_string(), keypair("synthetic-aps")),
        ]));
        let registration = P::Dictionary(Dictionary::from_iter([
            ("handles".to_string(), P::Array(vec![P::String("mailto:buddy@example.test".into())])),
            ("id_keypair".to_string(), keypair("synthetic-reg")),
        ]));
        let users = P::Array(vec![P::Dictionary(Dictionary::from_iter([
            ("auth_keypair".to_string(), keypair("synthetic-auth")),
            ("registration".to_string(), P::Dictionary(Dictionary::from_iter([("com.apple.madrid".to_string(), registration)]))),
        ]))]);
        let hardware = serde_json::json!({"inner":{"product_name":"SYNTHETIC","platform_serial_number":"SYNTHETIC",
            "platform_uuid":"SYNTHETIC","root_disk_uuid":"SYNTHETIC","board_id":"SYNTHETIC",
            "os_build_num":"SYNTHETIC","mlb":"SYNTHETIC"}});
        let store = P::Dictionary(Dictionary::from_iter([
            ("keys".to_string(), P::Dictionary(Dictionary::from_iter([
                ("synthetic-aps".to_string(), P::Data(vec![1])), ("synthetic-auth".to_string(), P::Data(vec![2])),
                ("synthetic-reg".to_string(), P::Data(vec![3])),
            ]))),
            ("secrets".to_string(), P::Dictionary(Dictionary::new())),
        ]));
        (SessionExport { version: 1, aps_state: xml(&aps), ids_users: xml(&users),
            ids_identity: xml(&P::Dictionary(Dictionary::new())), preferred_handle: "mailto:buddy@example.test".into(),
            hardware_key: STANDARD.encode(serde_json::to_vec(&hardware).unwrap()), device_id: None, platform: None },
            xml(&store).into_bytes())
    }

    #[test]
    fn offline_validation_checks_coupled_aliases_and_own_handle_without_crypto_or_network() {
        let (mut export, store) = synthetic_export();
        let result = validate_export(&export, &store).unwrap();
        assert!(!result.network_contacted);
        assert!(result.keystore_references_present);
        assert_eq!(result.registered_user_count, 1);
        assert_eq!(result.own_handle_count, 1);
        let mut value: plist::Value = plist::from_bytes(&store).unwrap();
        value.as_dictionary_mut().unwrap().get_mut("keys").unwrap().as_dictionary_mut().unwrap().remove("synthetic-auth");
        assert!(matches!(validate_export(&export, xml(&value).as_bytes()), Err(WorkerError("keystore_reference_missing"))));
        export.preferred_handle = "mailto:other@example.test".into();
        assert!(matches!(validate_export(&export, &store), Err(WorkerError("preferred_handle_mismatch"))));
    }

    #[test]
    fn private_export_requires_supported_version_and_complete_registered_aps_state() {
        let (mut export, store) = synthetic_export();
        export.version = 2;
        assert!(matches!(validate_export(&export, &store), Err(WorkerError("unsupported_export_version"))));
        export.version = 1;
        export.aps_state = xml(&plist::Value::Dictionary(plist::Dictionary::new()));
        assert!(matches!(validate_export(&export, &store), Err(WorkerError("incomplete_registered_aps_state"))));
    }

    #[test]
    fn commands_reject_actor_overrides_unknown_fields_and_unsafe_ids() {
        let raw = br#"{"op":"send_text","id":"op1","sender":"other","conversation":{"participants":["mailto:buddy@example.test"]},"text":"hi"}"#;
        assert!(matches!(parse_command(raw), Err(WorkerError("invalid_command"))));
        assert!(parse_command(br#"{"op":"connect","id":"../escape"}"#).is_err());
        assert!(parse_command(br#"{"op":"connect","id":"ok"}"#).is_ok());
        assert!(parse_command(&vec![b'x'; MAX_COMMAND_BYTES + 1]).is_err());
    }

    #[test]
    fn conversation_must_include_own_actor_and_preserve_group_context() {
        let conversation = Conversation { participants: vec!["mailto:buddy@example.test".into(), "tel:+15555550123".into()],
            sender_guid: None, cv_name: None, after_guid: None };
        assert!(conversation.validate("mailto:buddy@example.test").is_ok());
        assert!(conversation.validate("mailto:other@example.test").is_err());
        assert!(!valid_handle("mailto:user@example.test\n"));
        assert!(!valid_handle("tel:123"));
    }

    #[test]
    fn fingerprint_changes_for_changed_content_not_repeated_requests() {
        let first = parse_command(br#"{"op":"send_text","id":"op1","conversation":{"participants":["mailto:buddy@example.test"]},"text":"hi"}"#).unwrap();
        let repeated = first.clone();
        let different = parse_command(br#"{"op":"send_text","id":"op1","conversation":{"participants":["mailto:buddy@example.test"]},"text":"changed"}"#).unwrap();
        assert_eq!(fingerprint(&first).unwrap(), fingerprint(&repeated).unwrap());
        assert_ne!(fingerprint(&first).unwrap(), fingerprint(&different).unwrap());
    }
}
