// Modified 2026-10-27 for OrdinaryPlace Buddy. SSPL v1; see repository LICENSE.
// Default startup is offline. Only an explicit JSONL connect command contacts Apple.
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use buddy_imessage::*;
use keystore::{init_keystore, software::{NoEncryptor, SoftwareKeystore, SoftwareKeystoreState}};
use rustpush::{APSConnection, APSConnectionResource, APSState, IDSNGMIdentity, IDSUser,
    IMClient, MADRID_SERVICE, Message, MessageInst, MessageType, NormalMessage, OSConfig};
use rustpush::polls::{NativePollPayload, PollPayload};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[derive(Clone, Serialize, Deserialize)]
struct PollMetadata { session_id: String, option_ids: Vec<String> }

#[derive(Clone, Serialize, Deserialize)]
struct Operation {
    version: u32,
    id: String,
    fingerprint: String,
    message: MessageInst,
    poll: Option<PollMetadata>,
    // ExtensionApp deliberately skips balloon during normal serde. Preserve the
    // typed JSON payload separately and rebuild the SAME session/options on load.
    poll_payload: Option<PollPayload>,
    status: String,
}

struct Connected {
    connection: APSConnection,
    client: Arc<IMClient>,
    actor: String,
    session: Arc<Mutex<SessionExport>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Connected {
    fn drop(&mut self) {
        for task in &self.tasks { task.abort(); }
        self.connection.close();
    }
}

struct Worker {
    export_path: PathBuf,
    work_dir: PathBuf,
    output: mpsc::Sender<Value>,
    connected: Option<Connected>,
    initialized: bool,
    persistence_failed: Arc<AtomicBool>,
    operations: Arc<Mutex<HashMap<String, Operation>>>,
}

fn plist_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    plist::to_writer_xml(&mut bytes, value).map_err(|_| WorkerError("private_state_encode_failed"))?;
    Ok(bytes)
}

fn configuration(bundle: &SessionExport) -> Result<Arc<dyn OSConfig>> {
    let value = hardware_json(bundle)?;
    let inner: rustpush::macos::HardwareConfig = serde_json::from_value(value["inner"].clone())
        .map_err(|_| WorkerError("unsupported_hardware_shape"))?;
    // Match the Corten Linux key helper: use the actual extracted platform UUID,
    // never a newly generated/synthetic hardware identity.
    let device_id = inner.platform_uuid.to_uppercase();
    if bundle.device_id.as_ref().is_some_and(|id| !id.is_empty() && id != &device_id) {
        return Err(WorkerError("device_identity_mismatch"));
    }
    let text = |name: &str, default: &str| value.get(name).and_then(Value::as_str)
        .filter(|text| !text.is_empty()).unwrap_or(default).to_string();
    let icloud_ua = text("icloud_ua", "com.apple.iCloudHelper/282 CFNetwork/1568.100.1 Darwin/22.5.0");
    if icloud_ua.split_once(char::is_whitespace).is_none() { return Err(WorkerError("unsupported_hardware_user_agent")); }
    Ok(Arc::new(rustpush::macos::MacOSConfig {
        inner, version: text("version", "13.6.4"),
        protocol_version: value.get("protocol_version").and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok()).filter(|v| *v != 0).unwrap_or(1660),
        device_id: device_id.clone(), udid: Some(device_id), icloud_ua,
        aoskit_version: text("aoskit_version", "com.apple.AOSKit/282 (com.apple.accountsd/113)"),
    }))
}

fn save_operation(directory: &Path, operation: &Operation) -> Result<()> {
    let bytes = serde_json::to_vec(operation).map_err(|_| WorkerError("operation_encode_failed"))?;
    atomic_private_write(&operation_path(directory, &operation.id)?, &bytes)
}

fn load_operation(directory: &Path, id: &str) -> Result<Operation> {
    let path = operation_path(directory, id)?;
    let bytes = private_read(&path, MAX_COMMAND_BYTES * 4).map_err(|_| WorkerError("operation_not_found_or_invalid"))?;
    let record: Operation = serde_json::from_slice(&bytes).map_err(|_| WorkerError("invalid_operation_record"))?;
    if record.version != 1 || record.id != id { return Err(WorkerError("invalid_operation_record")); }
    Ok(record)
}

fn report_operation(operation: &Operation, request_id: &str) -> Value {
    json!({"event":"operation","id":operation.id,"request_id":request_id,"message_guid":operation.message.id,
        "status":operation.status,"poll":operation.poll,"automatic_retry":false})
}

fn error_event(request_id: Option<&str>, error: WorkerError) -> Value {
    json!({"event":"error","id":request_id,"request_id":request_id,"code":error.0})
}

async fn emit(output: &mpsc::Sender<Value>, event: Value) {
    let _ = output.send(event).await;
}

impl Worker {
    fn validation(&self) -> Result<Validation> {
        let bundle = load_bundle(&self.export_path, &self.work_dir)?;
        let store = private_read(&self.work_dir.join("keystore.plist"), MAX_EXPORT_BYTES)?;
        validate_export(&bundle, &store)
    }

    async fn connect(&mut self) -> Result<()> {
        if self.connected.is_some() { return Err(WorkerError("already_connected")); }
        if self.initialized { return Err(WorkerError("restart_required_before_reconnect")); }
        let bundle = load_bundle(&self.export_path, &self.work_dir)?;
        let keystore_path = self.work_dir.join("keystore.plist");
        let store_bytes = private_read(&keystore_path, MAX_EXPORT_BYTES)?;
        validate_export(&bundle, &store_bytes)?;
        let config = configuration(&bundle)?;
        let store: SoftwareKeystoreState = plist::from_bytes(&store_bytes)
            .map_err(|_| WorkerError("invalid_keystore_format"))?;
        let failed = self.persistence_failed.clone();
        init_keystore(SoftwareKeystore {
            state: RwLock::new(store), encryptor: NoEncryptor,
            update_state: Box::new(move |state| {
                if plist_bytes(state).and_then(|bytes| atomic_private_write(&keystore_path, &bytes)).is_err() {
                    failed.store(true, Ordering::SeqCst);
                }
            }),
        });
        self.initialized = true;
        // Resolve the existing coupled crypto state, with no empty/default or
        // newly generated identity fallback. A parser panic is a static error.
        let typed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let aps: APSState = plist::from_bytes(bundle.aps_state.as_bytes()).map_err(|_| WorkerError("invalid_aps_state"))?;
            let users: Vec<IDSUser> = plist::from_bytes(bundle.ids_users.as_bytes()).map_err(|_| WorkerError("invalid_ids_users"))?;
            let identity: IDSNGMIdentity = plist::from_bytes(bundle.ids_identity.as_bytes()).map_err(|_| WorkerError("invalid_ids_identity"))?;
            Ok::<_, WorkerError>((aps, users, identity))
        })).map_err(|_| WorkerError("crypto_state_restore_failed"))??;
        let (aps, users, identity) = typed;
        if aps.token.is_none() || aps.keypair.is_none() || users.is_empty()
            || users.iter().any(|user| !user.registration.contains_key("com.apple.madrid")) {
            return Err(WorkerError("incomplete_registered_state"));
        }
        let handles: Vec<_> = users.iter().flat_map(|user| user.registration["com.apple.madrid"].handles.clone()).collect();
        if !handles.contains(&bundle.preferred_handle) { return Err(WorkerError("preferred_handle_mismatch")); }
        let session = Arc::new(Mutex::new(bundle.clone()));
        let (connection, error) = APSConnectionResource::new(config.clone(), Some(aps)).await;
        if error.is_some() { connection.close(); return Err(WorkerError("apple_connect_failed")); }
        let current_aps = connection.state.read().await.clone();
        let initial_save = (|| {
            let bytes = plist_bytes(&current_aps)?;
            let mut current = session.lock().map_err(|_| WorkerError("state_persist_failed"))?;
            current.aps_state = String::from_utf8(bytes).map_err(|_| WorkerError("state_persist_failed"))?;
            save_bundle(&current, &self.work_dir)
        })();
        if initial_save.is_err() { connection.close(); return Err(WorkerError("state_persist_failed")); }
        let mut receive = connection.messages_cont.subscribe();
        let session_for_users = session.clone();
        let directory_for_users = self.work_dir.clone();
        let failed = self.persistence_failed.clone();
        let client = Arc::new(IMClient::new(connection.clone(), users, identity, &[&MADRID_SERVICE],
            self.work_dir.join("id-cache.plist"), config,
            Box::new(move |users| {
                let result = (|| {
                    let bytes = plist_bytes(&users)?;
                    let mut session = session_for_users.lock().map_err(|_| WorkerError("state_persist_failed"))?;
                    session.ids_users = String::from_utf8(bytes).map_err(|_| WorkerError("state_persist_failed"))?;
                    save_bundle(&session, &directory_for_users)
                })();
                if result.is_err() { failed.store(true, Ordering::SeqCst); }
            })).await);
        let actor = bundle.preferred_handle.clone();
        let actual_handles = client.identity.get_handles().await;
        if !actual_handles.contains(&actor) { connection.close(); return Err(WorkerError("preferred_handle_mismatch")); }
        let output = self.output.clone();
        let recv_client = client.clone();
        let connected_at_ms = epoch_ms();
        let receive_task = tokio::spawn(async move {
            loop {
                match receive.recv().await {
                    Ok(message) => match recv_client.handle(message).await {
                        Ok(Some(message)) => emit_inbound(&output, &actual_handles, message, connected_at_ms).await,
                        Ok(None) => {},
                        Err(_) => emit(&output, json!({"event":"transport_error","code":"inbound_decode_failed"})).await,
                    },
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        emit(&output, json!({"event":"transport_error","code":"receive_overflow_restart_required"})).await;
                        recv_client.conn.close();
                        break;
                    }
                    Err(_) => break,
                }
            }
        });
        let state_connection = connection.clone();
        let session_for_state = session.clone();
        let state_directory = self.work_dir.clone();
        let failed = self.persistence_failed.clone();
        let output = self.output.clone();
        let state_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                let state = state_connection.state.read().await.clone();
                let result = (|| {
                    let bytes = plist_bytes(&state)?;
                    let mut session = session_for_state.lock().map_err(|_| WorkerError("state_persist_failed"))?;
                    session.aps_state = String::from_utf8(bytes).map_err(|_| WorkerError("state_persist_failed"))?;
                    save_bundle(&session, &state_directory)
                })();
                if result.is_err() || failed.load(Ordering::SeqCst) {
                    emit(&output, json!({"event":"transport_error","code":"state_persist_failed_restart_required"})).await;
                    state_connection.close();
                    break;
                }
            }
        });
        self.connected = Some(Connected { connection, client, actor, session, tasks: vec![receive_task, state_task] });
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        // Take ownership first so even a persistence failure closes transport.
        if let Some(connected) = self.connected.take() {
            let state = connected.connection.state.read().await.clone();
            let bytes = plist_bytes(&state)?;
            let mut session = connected.session.lock().map_err(|_| WorkerError("state_persist_failed"))?;
            session.aps_state = String::from_utf8(bytes).map_err(|_| WorkerError("state_persist_failed"))?;
            save_bundle(&session, &self.work_dir)?;
        }
        Ok(())
    }

    fn prepare(&mut self, command: &Command) -> Result<Operation> {
        let bundle = load_bundle(&self.export_path, &self.work_dir)?;
        let (id, conversation, text, poll) = match command {
            Command::SendText { id, conversation, text } | Command::PrepareText { id, conversation, text } =>
                (id, conversation, Some(text), None),
            Command::SendPoll { id, conversation, question, options } | Command::PreparePoll { id, conversation, question, options } =>
                (id, conversation, None, Some((question, options))),
            _ => return Err(WorkerError("invalid_operation")),
        };
        conversation.validate(&bundle.preferred_handle)?;
        let digest = fingerprint(command)?;
        if operation_path(&self.work_dir, id)?.exists() {
            let existing = load_operation(&self.work_dir, id)?;
            if existing.fingerprint != digest { return Err(WorkerError("operation_conflict")); }
            return Ok(existing);
        }
        let (normal, metadata, poll_payload) = if let Some((question, options)) = poll {
            let actor = bundle.preferred_handle.strip_prefix("mailto:").unwrap_or(&bundle.preferred_handle).to_string();
            let (normal, metadata) = NormalMessage::native_poll(actor, question.clone(), options.clone())
                .map_err(|_| WorkerError("invalid_new_poll"))?;
            let (_, data) = normal.app.as_ref().ok_or(WorkerError("invalid_new_poll"))?
                .native_poll_payload().map_err(|_| WorkerError("invalid_new_poll"))?
                .ok_or(WorkerError("invalid_new_poll"))?;
            let NativePollPayload::Poll(payload) = data.payload else { return Err(WorkerError("invalid_new_poll")); };
            (normal, Some(PollMetadata { session_id: metadata.session_id, option_ids: metadata.option_ids }), Some(payload))
        } else {
            let text = text.ok_or(WorkerError("invalid_operation"))?;
            if text.is_empty() || text.len() > 32 * 1024 { return Err(WorkerError("invalid_text")); }
            (NormalMessage::new(text.clone(), MessageType::IMessage), None, None)
        };
        let mut message = MessageInst::new(conversation.protocol(), &bundle.preferred_handle, Message::Message(normal));
        // Persist the exact group/DM GUID and timestamp the protocol will use,
        // before crossing the network boundary. Subsequent prepare_send calls
        // keep this generated conversation GUID and the MessageInst GUID.
        message.prepare_send(&[bundle.preferred_handle]);
        let operation = Operation { version: 1, id: id.clone(), fingerprint: digest,
            message, poll: metadata, poll_payload, status: "prepared".into() };
        save_operation(&self.work_dir, &operation)?;
        self.operations.lock().map_err(|_| WorkerError("operation_state_failed"))?.insert(id.clone(), operation.clone());
        Ok(operation)
    }

    async fn dispatch(&mut self, operation_id: &str) -> Result<Operation> {
        let connected = self.connected.as_ref().ok_or(WorkerError("not_connected"))?;
        if self.persistence_failed.load(Ordering::SeqCst) { return Err(WorkerError("state_persist_failed")); }
        if !connected.client.identity.get_handles().await.contains(&connected.actor) {
            return Err(WorkerError("own_identity_changed"));
        }
        let mut operation = load_operation(&self.work_dir, operation_id)?;
        if operation.status != "prepared" { return Ok(operation); }
        if operation.message.sender.as_deref() != Some(connected.actor.as_str()) || operation.message.target.is_some() {
            return Err(WorkerError("operation_actor_mismatch"));
        }
        restore_poll_balloon(&mut operation, &connected.actor)?;
        let conversation = operation.message.conversation.as_ref().ok_or(WorkerError("invalid_operation_record"))?;
        Conversation { participants: conversation.participants.clone(), sender_guid: conversation.sender_guid.clone(),
            cv_name: conversation.cv_name.clone(), after_guid: conversation.after_guid.clone() }.validate(&connected.actor)?;
        if !matches!(&operation.message.message, Message::Message(normal) if normal.service == MessageType::IMessage) {
            return Err(WorkerError("unsupported_operation_message"));
        }
        operation.status = "dispatching".into();
        save_operation(&self.work_dir, &operation)?;
        let result = tokio::time::timeout(Duration::from_secs(60), connected.client.send(&mut operation.message)).await;
        let outcome = match result {
            Ok(Ok(mut job)) => match job.handle.take() {
                Some(handle) => match tokio::time::timeout(Duration::from_secs(150), handle).await {
                    Ok(Ok(Ok(()))) => "submitted",
                    _ => "uncertain",
                },
                None => "submitted",
            },
            // Once dispatch starts, errors/timeouts are conservatively uncertain.
            // Do not replace the GUID, fall back to SMS, or automatically retry.
            _ => "uncertain",
        };
        operation.status = outcome.into();
        save_operation(&self.work_dir, &operation)?;
        self.operations.lock().map_err(|_| WorkerError("operation_state_failed"))?
            .insert(operation.id.clone(), operation.clone());
        Ok(operation)
    }

    async fn command(&mut self, command: Command) -> Result<bool> {
        let id = command.id().to_string();
        match &command {
            Command::Validate { .. } => emit(&self.output, json!({"event":"validation","id":id,"request_id":id,"result":self.validation()?})).await,
            Command::Connect { .. } => {
                self.connect().await?;
                emit(&self.output, json!({"event":"connected","id":id,"request_id":id,"own_identity_verified":true})).await;
            }
            Command::Disconnect { .. } => {
                self.disconnect().await?;
                emit(&self.output, json!({"event":"disconnected","id":id,"request_id":id})).await;
                return Ok(false);
            }
            Command::Status { operation_id, .. } => emit(&self.output, report_operation(&load_operation(&self.work_dir, operation_id)?, &id)).await,
            Command::PrepareText { .. } | Command::PreparePoll { .. } => {
                let operation = self.prepare(&command)?;
                emit(&self.output, report_operation(&operation, &id)).await;
            }
            Command::SendText { .. } | Command::SendPoll { .. } => {
                if self.connected.is_none() { return Err(WorkerError("not_connected")); }
                let operation = self.prepare(&command)?;
                let operation = self.dispatch(&operation.id).await?;
                emit(&self.output, report_operation(&operation, &id)).await;
            }
            Command::Dispatch { operation_id, .. } => {
                let operation = self.dispatch(operation_id).await?;
                emit(&self.output, report_operation(&operation, &id)).await;
            }
        }
        Ok(true)
    }
}

fn epoch_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

async fn emit_inbound(output: &mpsc::Sender<Value>, handles: &[String], message: MessageInst, connected_at_ms: u64) {
    let conversation = message.conversation.as_ref().map(|c| json!({"participants":c.participants,
        "sender_guid":c.sender_guid,"cv_name":c.cv_name,"after_guid":c.after_guid}));
    let mut event = json!({"event":"message","message_id":message.id,"sender":message.sender,
        "from_me":message.sender.as_ref().is_some_and(|sender| handles.contains(sender)),
        "timestamp_ms":message.sent_timestamp,"received_at_ms":epoch_ms(),
        "initial_connection_window":epoch_ms().saturating_sub(connected_at_ms) < 30_000,
        "verification_failed":message.verification_failed,
        "conversation":conversation});
    match message.native_poll_event() {
        Ok(Some(poll)) => {
            let (kind, payload) = match poll.data.payload {
                NativePollPayload::Poll(payload) => ("poll", serde_json::to_value(payload)),
                NativePollPayload::Vote(payload) => ("poll_vote", serde_json::to_value(payload)),
            };
            event["kind"] = json!(kind);
            event["poll_message_id"] = json!(poll.poll_message_id);
            event["session_id"] = json!(poll.session_id);
            event["poll_part"] = json!(poll.poll_part);
            if let Ok(payload) = payload { event["payload"] = payload; }
        }
        Err(error) => {
            event["kind"] = json!("unsupported_poll");
            event["poll_error"] = json!(error.to_string());
        }
        Ok(None) => match &message.message {
            Message::Message(normal) => {
                event["kind"] = json!("text");
                event["text"] = json!(normal.parts.raw_text());
                event["has_attachments"] = json!(normal.parts.has_attachments());
                event["extension_bundle_id"] = json!(normal.app.as_ref().map(|app| &app.bundle_id));
            }
            Message::Delivered => { event["kind"] = json!("delivery_receipt"); }
            Message::Read => { event["kind"] = json!("read_receipt"); }
            Message::React(_) => { event["kind"] = json!("reaction"); }
            _ => { event["kind"] = json!("unsupported"); }
        },
    }
    emit(output, event).await;
}

async fn bounded_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let buffer = reader.fill_buf().await.map_err(|_| WorkerError("input_failed"))?;
        if buffer.is_empty() { return Ok(if line.is_empty() { None } else { Some(line) }); }
        let end = buffer.iter().position(|byte| *byte == b'\n').map(|i| i + 1).unwrap_or(buffer.len());
        if end > MAX_COMMAND_BYTES.saturating_sub(line.len()) { return Err(WorkerError("command_too_large")); }
        line.extend_from_slice(&buffer[..end]);
        let complete = buffer[end - 1] == b'\n';
        reader.consume(end);
        if complete { return Ok(Some(line)); }
    }
}

fn arguments() -> Result<(PathBuf, PathBuf, bool)> {
    let mut bundle = None;
    let mut directory = None;
    let mut validate_only = false;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--bundle" => bundle = args.next().map(PathBuf::from),
            "--work-dir" => directory = args.next().map(PathBuf::from),
            "--validate" => validate_only = true,
            _ => return Err(WorkerError("invalid_arguments")),
        }
    }
    let bundle = bundle.filter(|p| p.is_absolute()).ok_or(WorkerError("invalid_arguments"))?;
    let directory = directory.filter(|p| p.is_absolute()).ok_or(WorkerError("invalid_arguments"))?;
    Ok((bundle, directory, validate_only))
}

#[tokio::main]
async fn main() {
    // Upstream cache writes inherit this mask, including id-cache.plist.
    unsafe { libc::umask(0o077); }
    // Upstream errors/panics can format keys or message contents. Never expose
    // their detailed diagnostics through this private protocol worker.
    std::panic::set_hook(Box::new(|_| eprintln!("Buddy transport stopped: internal failure")));
    log::set_max_level(log::LevelFilter::Off);
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (output, mut events) = mpsc::channel::<Value>(256);
    let writer = tokio::spawn(async move {
        let mut stdout = BufWriter::new(tokio::io::stdout());
        while let Some(event) = events.recv().await {
            let Ok(mut bytes) = serde_json::to_vec(&event) else { break };
            bytes.push(b'\n');
            if stdout.write_all(&bytes).await.is_err() || stdout.flush().await.is_err() { break; }
        }
    });
    let result = run(output.clone()).await;
    if let Err(error) = result { emit(&output, error_event(None, error)).await; }
    drop(output);
    let _ = writer.await;
}

async fn run(output: mpsc::Sender<Value>) -> Result<()> {
    let (export_path, work_dir, validate_only) = arguments()?;
    require_private_directory(&work_dir)?;
    let mut worker = Worker { export_path, work_dir: work_dir.clone(), output: output.clone(), connected: None,
        initialized: false, persistence_failed: Arc::new(AtomicBool::new(false)), operations: Arc::new(Mutex::new(HashMap::new())) };
    if validate_only {
        emit(&output, json!({"event":"validation","request_id":null,"result":worker.validation()?})).await;
        return Ok(());
    }
    let lock = OpenOptions::new().read(true).write(true).create(true).mode(0o600).custom_flags(libc::O_NOFOLLOW)
        .open(work_dir.join("worker.lock")).map_err(|_| WorkerError("worker_lock_failed"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 { return Err(WorkerError("worker_already_running")); }
    emit(&output, json!({"event":"ready","connected":false,"network_contacted":false})).await;
    let mut input = BufReader::new(tokio::io::stdin());
    while let Some(line) = bounded_line(&mut input).await? {
        let command = match parse_command(&line) {
            Ok(command) => command,
            Err(error) => { emit(&output, error_event(None, error)).await; continue; }
        };
        let id = command.id().to_string();
        match worker.command(command).await {
            Ok(true) => {},
            Ok(false) => break,
            Err(error) => emit(&output, error_event(Some(&id), error)).await,
        }
    }
    worker.disconnect().await?;
    drop(lock);
    Ok(())
}

fn restore_poll_balloon(operation: &mut Operation, actor: &str) -> Result<()> {
    match (&operation.poll, &operation.poll_payload) {
        (Some(metadata), Some(payload)) => {
            let expected_actor = actor.strip_prefix("mailto:").unwrap_or(actor);
            if payload.item.creator_handle != expected_actor
                || payload.item.ordered_poll_options.iter().map(|option| option.option_identifier.clone())
                    .collect::<Vec<_>>() != metadata.option_ids {
                return Err(WorkerError("invalid_persisted_poll"));
            }
            let normal = NormalMessage::native_poll_with_ids(payload.clone(), &metadata.session_id)
                .map_err(|_| WorkerError("invalid_persisted_poll"))?;
            operation.message.message = Message::Message(normal);
        }
        (None, None) => {
            if matches!(&operation.message.message, Message::Message(normal) if normal.app.is_some()) {
                return Err(WorkerError("unsupported_operation_message"));
            }
        }
        _ => return Err(WorkerError("invalid_persisted_poll")),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::DirBuilderExt;

    struct PrivateTestDirectory(PathBuf);
    impl PrivateTestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("buddy-worker-test-{}", uuid::Uuid::new_v4()));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for PrivateTestDirectory {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

    fn offline_worker(directory: &Path) -> Worker {
        let bundle = SessionExport { version: 1, aps_state: String::new(), ids_users: String::new(),
            ids_identity: String::new(), hardware_key: String::new(), preferred_handle: "mailto:buddy@example.test".into(),
            device_id: None, platform: None };
        let path = directory.join("export.json");
        atomic_private_write(&path, &serde_json::to_vec(&bundle).unwrap()).unwrap();
        let (output, _) = mpsc::channel(16);
        Worker { export_path: path, work_dir: directory.into(), output, connected: None,
            initialized: false, persistence_failed: Arc::new(AtomicBool::new(false)), operations: Arc::new(Mutex::new(HashMap::new())) }
    }

    fn poll_command() -> Command {
        Command::PreparePoll { id: "synthetic-poll".into(), conversation: Conversation {
            participants: vec!["mailto:buddy@example.test".into(), "mailto:family@example.test".into()],
            sender_guid: None, cv_name: None, after_guid: None }, question: "Dinner?".into(),
            options: vec!["Pizza".into(), "Sushi".into()] }
    }

    #[test]
    fn offline_poll_intent_is_durable_and_rebuilds_same_guid_session_and_options() {
        let directory = PrivateTestDirectory::new();
        let mut worker = offline_worker(&directory.0);
        let first = worker.prepare(&poll_command()).unwrap();
        let repeated = worker.prepare(&poll_command()).unwrap();
        assert_eq!(first.message.id, repeated.message.id);
        assert_eq!(first.poll.as_ref().unwrap().session_id, repeated.poll.as_ref().unwrap().session_id);
        let mut loaded = load_operation(&directory.0, "synthetic-poll").unwrap();
        assert!(matches!(&loaded.message.message, Message::Message(normal) if normal.app.as_ref().unwrap().balloon.is_none()));
        restore_poll_balloon(&mut loaded, "mailto:buddy@example.test").unwrap();
        let event = loaded.message.native_poll_event().unwrap().unwrap();
        assert_eq!(event.session_id, first.poll.unwrap().session_id);
        assert_eq!(event.poll_message_id, first.message.id);
        let NativePollPayload::Poll(payload) = event.data.payload else { panic!("Expected poll") };
        assert_eq!(payload.item.ordered_poll_options.len(), 2);
        assert_eq!(payload.item.creator_handle, "buddy@example.test");
        assert!(worker.connected.is_none());
    }

    #[test]
    fn duplicate_operation_with_changed_content_is_refused() {
        let directory = PrivateTestDirectory::new();
        let mut worker = offline_worker(&directory.0);
        worker.prepare(&poll_command()).unwrap();
        let mut changed = poll_command();
        let Command::PreparePoll { question, .. } = &mut changed else { panic!("Expected poll command") };
        *question = "Changed".into();
        assert!(matches!(worker.prepare(&changed), Err(WorkerError("operation_conflict"))));
    }

    #[tokio::test]
    async fn dispatch_without_explicit_connection_cannot_cross_network_boundary() {
        let directory = PrivateTestDirectory::new();
        let mut worker = offline_worker(&directory.0);
        let operation = worker.prepare(&poll_command()).unwrap();
        assert!(matches!(worker.dispatch(&operation.id).await, Err(WorkerError("not_connected"))));
        assert_eq!(load_operation(&directory.0, &operation.id).unwrap().status, "prepared");
    }

    #[test]
    fn persisted_vote_identity_or_option_metadata_cannot_replace_the_prepared_poll() {
        let directory = PrivateTestDirectory::new();
        let mut worker = offline_worker(&directory.0);
        let mut operation = worker.prepare(&poll_command()).unwrap();
        operation.poll_payload.as_mut().unwrap().item.creator_handle = "other@example.test".into();
        assert!(restore_poll_balloon(&mut operation, "mailto:buddy@example.test").is_err());
    }

    #[tokio::test]
    async fn status_reply_correlates_fresh_request_without_changing_durable_operation_id() {
        let directory = PrivateTestDirectory::new();
        let mut worker = offline_worker(&directory.0);
        let (output, mut replies) = mpsc::channel(8);
        worker.output = output;
        worker.command(poll_command()).await.unwrap();
        let prepared = replies.recv().await.unwrap();
        assert_eq!(prepared["id"], "synthetic-poll");
        assert_eq!(prepared["request_id"], "synthetic-poll");
        assert!(replies.try_recv().is_err());
        worker.command(Command::Status { id: "fresh-status-query".into(), operation_id: "synthetic-poll".into() }).await.unwrap();
        let status = replies.recv().await.unwrap();
        assert_eq!(status["id"], "synthetic-poll");
        assert_eq!(status["request_id"], "fresh-status-query");
        assert_eq!(status["status"], "prepared");
        assert_eq!(status["message_guid"], prepared["message_guid"]);
        assert!(replies.try_recv().is_err());
    }

    #[test]
    fn command_error_preserves_request_correlation_with_only_static_diagnostics() {
        let error = error_event(Some("fresh-dispatch-query"), WorkerError("not_connected"));
        assert_eq!(error["request_id"], "fresh-dispatch-query");
        assert_eq!(error["id"], "fresh-dispatch-query");
        assert_eq!(error["code"], "not_connected");
        assert_eq!(error_event(None, WorkerError("invalid_command"))["request_id"], Value::Null);
    }
}
