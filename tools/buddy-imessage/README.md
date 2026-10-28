# Buddy Linux iMessage worker

Modified 2026-10-27. This crate is part of the SSPL-licensed protocol fork. It uses
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

`submitted` means the protocol send job completed, not that someone saw the
message. Native delivery/read receipts are emitted as inbound evidence; phone
observation remains a separate check. Operation records and `status` responses
include GUIDs and poll metadata, not private keys or credentials.

## Inbound events

`message` events retain native message ID, sender, source time, conversation,
`from_me` and `verification_failed`. Kinds include `text`, `poll`, `poll_vote`,
receipts, reactions and explicit unsupported content. Native polls expose their
typed JSON plus original poll GUID/part/session before flattening can discard it.
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
