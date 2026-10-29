# Buddy Linux iMessage worker

Modified 2026-10-28. This crate is part of the SSPL-licensed protocol fork. It uses
the real rustpush messaging APIs and native Polls helpers without a Mac runtime.
It does not provide Apple sign-in; a dedicated Linux login helper remains a
separate provisioning step.

Linux validation uses the real Unicorn-based NAC source vendored in
[`third_party/open-absinthe-linux`](../../third_party/open-absinthe-linux/PROVENANCE.md),
pinned to `thescruggs/imessage-linux` revision
`79a0a753f0513d105f47c0bbd58c8efc7f506a91` with its original SSPL license and
source hashes. Rust 1.99.1 is pinned in `rust-toolchain.toml`. The resource helper
described in that provenance document fetches and checks the separately supplied
public `IMDAppleServices` binary; no Apple binary or account identity is vendored.
The Linux emulator and restored-session worker require no Mac framework or relay.
Offline compilation and emulator initialization do not verify account activation
or message delivery.

Use the public [Linux build instructions](../../third_party/open-absinthe-linux/BUILDING.md)
for required tools, pinned submodules, compile-only certificate preparation and
the locked worker build. No ignored research workbench is required.

## Private input and default offline behavior

Run with an owner-only export file and an existing owner-only working directory:

```sh
buddy-imessage --bundle /absolute/private/export.json \
  --work-dir /absolute/private/worker --validate
```

`--validate` only parses outer plist formats, hardware-key JSON, registered own
handles, and coupled keystore references. It never initializes transport,
registers, connects, logs in, sends, resolves recipients, or modifies private
state. It reports booleans/counts and static error categories. It is not a full
cryptographic or Apple-account verification.

The version 1 export is private JSON with these fields:

```text
version: 1
aps_state: XML plist string from the dedicated bot session
ids_users: XML plist string from that same session
ids_identity: XML plist string from that same session
preferred_handle: an own native handle present in the Madrid registration
hardware_key: the existing base64 JSON hardware key
device_id: optional saved device identifier
platform: optional saved platform marker
```

Do not include account passwords, PETs, cookies, tokens for unrelated services,
or other session fields. The APNs/IDS state and hardware key are themselves
secrets. The matching private keystore copy must exist at
`<work-dir>/keystore.plist`; missing keys or mismatched aliases stop operation.
The worker never initializes an empty keystore or generates a replacement IDS
identity as a recovery shortcut. The configured hardware identity is the
extracted key's real platform UUID; a contradictory saved device ID is refused.

Directories must be 0700 and files 0600, owned by the running Unix user. Files
are opened without following final-component symlinks. Use a worker-specific
directory. Original exports and Corten session state are read-only inputs;
updates go to `runtime-session.json`, `keystore.plist`, `id-cache.plist`, and
private operation records in the separate worker directory. The worker persists
APNs snapshots, IDS key updates and keystore changes there. A single-process
directory lock prevents simultaneous workers from sharing that state.

Without `--validate`, startup emits `ready` with `connected:false` and
`network_contacted:false`, then waits for JSON lines on stdin. Only an explicit
`connect` command crosses the Apple network boundary. Before using it, stop the
old bridge so it cannot compete for the same APNs identity. Connecting a
registered client can trigger the library's normal registration refresh; this
is not a new Apple-password login flow.

## JSONL commands

Every command has an ASCII `id` containing only letters, numbers, `_`, `-` and
`.` (1–128 characters, excluding `.` and `..`). Unknown fields, including sender
overrides, are refused. The parent service must authenticate family senders and
authorize the complete destination audience before invoking this worker.
Each parsed command receives exactly one final response with
`request_id` equal to that command's `id`. An operation response keeps `id` as
the durable operation ID, so a `status` query can use a fresh request ID without
changing the operation it inspects. Dispatch progress is persisted privately and
does not emit an interim operation response. Invalid/unparseable commands and
startup failures have a null `request_id`; detailed input is never echoed.

```json
{"op":"validate","id":"check-1"}
{"op":"connect","id":"connect-1"}
{"op":"typing","id":"typing-1","conversation":{"participants":["mailto:buddy@example.test","mailto:family@example.test"]},"active":true}
{"op":"send_feedback","id":"stable-feedback-1","conversation":{"participants":["mailto:buddy@example.test","mailto:family@example.test"]},"text":"I'm working on it."}
{"op":"send_text","id":"stable-action-1","conversation":{"participants":["mailto:buddy@example.test","mailto:family@example.test"]},"text":"Hello"}
{"op":"send_poll","id":"stable-poll-1","conversation":{"participants":["mailto:buddy@example.test","mailto:family@example.test"]},"question":"Dinner?","options":["Pizza","Sushi"]}
{"op":"status","id":"query-1","operation_id":"stable-poll-1"}
{"op":"disconnect","id":"stop-1"}
```

These addresses are synthetic examples, not recipients to contact. Real
conversations use the actual verified own handle and exact participants.
Optional conversation fields are `sender_guid`, `cv_name`, and `after_guid`;
UUID fields must be valid. No SMS fallback, recipient override, arbitrary actor,
vote-spoofing interface, or native vote-removal command is provided.

Ready events advertise `capabilities.typing:true`. Older workers without that
flag do not support the command. Typing requires an existing connection and an
exact direct conversation containing the connected own actor and one external
peer. Only the host chooses that approved audience. `active:false` stops typing;
app icons, sender overrides, text and message GUIDs are not accepted. The response
is `event:"typing"`, matching `id`/`request_id`, the requested `active` boolean,
and `status:"submitted"` or `"uncertain"`.

Typing has a two-second total send budget, uses a directly awaited send path
without a detached send job, and never creates a durable message operation or
replays after restart. Bytes already submitted to APNs cannot be recalled.
`submitted` indicates protocol submission only: typing has no IDS delivery
confirmation and no phone-rendering claim. Failures/timeouts remain uncertain
and are not retried. Host leases, refreshes and best-effort stops determine its
lifecycle; no recipient-device typing TTL is established here.

Transient operation records do not imply state-free transport. A plain direct
typing start has no encrypted payload, while stop has an encrypted payload and
advances the existing per-device NGM counters normally. Recipient lookup can also
update the existing key cache. Cancellation never rolls back those counters or
creates a replacement identity.

`capabilities.feedback:true` advertises a separate bounded, durable plain-text
feedback operation. It accepts at most 1000 UTF-8 bytes and the same verified
direct audience. It persists the ordinary iMessage GUID and intent before I/O,
keeps normal encrypted text/response flags, and uses a two-second enclosing
budget for send plus the existing external-result observation. A timeout cancels
the directly awaited job and stores `uncertain` with the same GUID; it does not
leave a detached job blocking later commands. Already submitted bytes cannot be
recalled. Positive normal external transport evidence is required for
`submitted`; neither status proves recipient delivery. Repeated IDs return their
stored state; changed content conflicts and uncertain sends are never retried.
`send_text` retains its original send/observation behavior. A host must not use it
as a fallback for optional feedback on an older worker without the capability.

`prepare_text` and `prepare_poll` accept the same data as their `send_` variants
but only create a private durable intent offline. Use
`{"op":"dispatch","id":"dispatch-1","operation_id":"stable-poll-1"}`
after explicit connection to dispatch a prepared operation. A `prepare_` and a
`send_` command with the same ID have different fingerprints; dispatch the
prepared record rather than changing its operation.

## Delivery and restart rules

Before any send, the worker persists the exact message GUID, conversation,
poll/session/option UUIDs, typed poll payload, and command fingerprint. Poll
payload is stored separately because the upstream generic `ExtensionApp` serde
representation intentionally omits balloon data. Dispatch reconstructs the same
balloon and validates its actor/options before sending.

States are `prepared`, `dispatching`, `submitted`, or `uncertain`. Repeating an
operation ID returns its existing record; changed content is a conflict. Once a
dispatch starts, errors/timeouts are conservatively uncertain. The worker never
automatically repeats an uncertain send, invents a new GUID, or changes service
to SMS. A stored `dispatching` record after a process crash also requires
reconciliation; it is not permission to send again. The underlying protocol may
retransmit within one send job using the same message identity.

Send timeouts bound observation, not all underlying network activity. The
upstream client can leave its same-GUID send job running after the worker stops
awaiting it; that job may continue its own retries until worker/connection
shutdown. A timeout's diagnostic snapshot can therefore be incomplete. The
worker never treats that timeout as permission for an outer resend, and it
does not claim that returning `uncertain` has aborted every in-flight send.

New dispatches collect the typed `SendJob.process` results while awaiting the
job, then drain at most 4096 remaining results. `send_diagnostics` is persisted
with the final operation and returned by `status`:

```text
version: 1
job_state: awaiting_client | client_failed | client_timed_out | completed | failed | timed_out
external: {accepted, rejected, timed_out, error_codes, error_codes_overflow}
own: {accepted, rejected, timed_out, error_codes, error_codes_overflow}
unexpected_results: count
lagged_results: count
stream_closed: boolean
```

These are per-target result counts; `accepted` means the transport/service
acknowledgement represented by the library's `SendResult::Sent`. They do not
prove delivery to Messages, native rendering, reading or a user's vote. No
device token, participant handle, key or free-form error text is included in
these diagnostic fields. Each scope retains counts for at most 64 distinct
numeric `SendResult::APSError` codes. Codes preserve the API's signed integer
type (JSON object keys encode those integers as decimal strings). Further
results with unretained codes increment `error_codes_overflow`; repeated
retained codes continue to increment their existing count. A dropped/lagged
stream cannot be reconstructed. A
failure or timeout before the library returns a job also leaves its per-target
results unknown. An empty-but-open stream or a drain that reaches its bound is
incomplete, not a successful result.

For new dispatches, `submitted` requires a completed job, at least one external
accepted result, a closed result stream, and no own/external rejection,
timeout, unexpected target or lost result. Any such error or incomplete result
is `uncertain`, even if the library job returned `Ok(())`. There is no automatic
retry. Older operation files load with `send_diagnostics:null`; their original
status and identity are retained, and no new evidence is inferred from them.
Operation replies include `delivery_verified:false`. Native delivery/read
receipts are emitted as separate inbound evidence; phone observation remains
a separate check. Operation records and `status` responses include GUIDs and
poll metadata, not private keys or credentials.

## Inbound events

`message` events retain native message ID, sender, source time, conversation,
`from_me` and `verification_failed`. Kinds include `text`, `poll`, `poll_vote`,
receipts, reactions and explicit unsupported content. Native polls expose their
typed JSON plus original poll GUID/part/session before flattening can discard it.
Every message also has a static `message_type` variant category. Unsupported
events can therefore distinguish typing, profile updates, cache invalidation
and other protocol events without serializing their bodies. A typed
`Message::Error` emits `event:"message", kind:"error", message_type:"error"`,
numeric `status`, and `error_for_message_id` as a canonical UUID or null. This
target comes only from `ErrorMessage.for_uuid`; the error event's own wrapper
GUID is never substituted as the failed message. Remote `status_str` and other
free-form protocol error text are omitted. `error_category` is the static
`message_protection_802` only for an exact remote
`ec-com.apple.messageprotection-802` match (the source client already handles
that code by invalidating its key cache); all other strings become `unknown`.
For reasons of the exact shape `ec-com.apple.messageprotection-<integer>`,
`error_domain` is the static `com.apple.messageprotection` and `error_code` is
the signed 64-bit integer. This reason code is distinct from the envelope's
numeric `status` (`fR`), which is not an HTTP status. Other domains are not
copied from remote text. Unknown, malformed, overflowing or oversized reasons
produce null domain/code. `error_reason_shape` is only `empty`, `oversized`,
`message_protection_numeric`, `blastdoor_type` or `unrecognized`. The
`blastdoor_type` label recognizes only the bounded `type-` prefix; it does not
interpret the remaining fields. `error_reason_length` reports the byte length
up to 128, with 129 meaning longer than the limit. For bounded reasons only,
`error_message_protection_component_present` indicates whether the known EC
prefix occurs anywhere. A composite reason does not yield an inferred domain
or code. Longer reasons are neither parsed nor scanned for that component. No
raw reason or source substring is emitted.

These shape-only checks follow the reverse-engineered
[IMBlastdoor reason formatter](https://github.com/EthanArbuckle/iPhone17-1_18.2_22C152_Restore/blob/e26ed4563f78871c59d2d96856756a65d62517e5/System/Library/PrivateFrameworks/IMDaemonCore.framework/IMBlastdoor.m#L403)
and the newer IDS formatter's
[secondary/EC/legacy inputs](https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/90aa0cfe59d9682b4265e1354c8b19ec3c7823ab/System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app/IDS/IDS_21.mm#L394).
They do not establish the semantics or grammar of a live composite reason.
These events remain diagnostic evidence; they cannot authorize an action or a
resend.
The JSON payload's creator/participant handle is an untrusted claim: authenticate
against the transport sender and verified aliases, correlate the original poll
and session, and validate option IDs before counting a vote. Do not act on
failed-verification, missing-sender, historical/replayed, or self-echo events.

Stdout is private application JSONL and can contain actual chat text, handles,
locations, or poll content. Keep it on the protected service pipe/per-chat
archive; it is not an operational console log. No Rust logger is initialized,
error codes are static, and the panic hook omits detailed upstream diagnostics.
An inbound queue overflow or state-persistence failure closes the connection
and emits a restart-required error instead of claiming healthy processing.

## Offline checks

```sh
cargo test --manifest-path tools/buddy-imessage/Cargo.toml
cargo check --manifest-path tools/buddy-imessage/Cargo.toml
```

Tests use synthetic commands and private temporary directories. They exercise
actor-override rejection, fingerprints, durable native poll reconstruction,
unchanged IDs across repeated preparations, and no dispatch without explicit
connection. No test restores real account state or contacts Apple. Respect
`AGENTS.md`: do not run `rustfmt`.
