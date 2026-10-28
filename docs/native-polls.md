# Native poll codec

Modified 2026-10-27 for OrdinaryPlace Buddy. This work remains under the repository's
Server Side Public License v1; see [LICENSE](../LICENSE) and the existing
[LICENSE.exceptions](../LICENSE.exceptions). The exception names OpenBubbles;
it does not grant OrdinaryPlace a separate exception.

`src/imessage/polls.rs` is an offline typed codec for the native Apple Polls
extension's base64 JSON data URL. It encodes and decodes poll definitions and
vote selections, preserves unknown JSON fields and URL query metadata, and
applies local encoded/decoded size limits. Version 1 is the supported schema.
No string-length limit beyond these byte limits is claimed as a native rule.
Duplicate JSON object keys are rejected at every nesting level before any map
can silently overwrite them, including unknown objects nested inside arrays.
Identical key names in separate objects remain valid. Errors expose no input.

The new-poll constructor accepts 2–12 nonempty choices with unique, caller-supplied
stable option IDs. It does not generate IDs during a retry. The inbound decoder
preserves empty titles, empty option/vote lists, case, option order, and payload
claims without promoting them to valid actions. The explicit-selection vote
constructor rejects an empty list; empty inbound lists can be re-encoded but do
not imply a proven unvote operation. Native clients can select multiple choices;
this codec does not impose single-choice behavior.
The codec validates option IDs as nonempty unique strings; it does not establish
that arbitrary strings are valid native identifiers. The future adapter must
generate and persist native option/session UUIDs and correlate them with the
original poll message before a send or vote operation.

Creator and participant handles in JSON are **untrusted claims**. A future
adapter must bind them to the authenticated `MessageInst.sender`, verified
aliases, the chat, original poll message GUID, balloon session, and known option
IDs. The codec neither authenticates votes nor tallies a result. It deliberately
does not normalize handle or identifier case. Decide any identity normalization
only in the verified account registry.

## Provenance

The independently implemented JSON shape is based on the primary research
artifact [sbaresearch/transcript-consistency](https://github.com/sbaresearch/transcript-consistency)
at commit `cc89bf6d418aa3c78b0366e5c80b19dc364aa020`:

- [`code/imessage/src/imessage/messages.rs`](https://github.com/sbaresearch/transcript-consistency/blob/cc89bf6d418aa3c78b0366e5c80b19dc364aa020/code/imessage/src/imessage/messages.rs):
  native bundle identifier, version 1 poll/vote JSON fields, poll URL suffix, and
  normal native poll construction.
- [`code/imessage/imessage-group/src/common.rs`](https://github.com/sbaresearch/transcript-consistency/blob/cc89bf6d418aa3c78b0366e5c80b19dc364aa020/code/imessage/imessage-group/src/common.rs):
  inbound URL decoding and vote extension-reaction representation.

The artifact accompanies *Send and Pretend: Exploiting Transcript Consistency
Issues in End-to-End Encrypted Group Chats* by Gegenhuber, Grefner, Günther,
Wininger, Schmidt, and Judmayer. Its native schema is useful interoperability
evidence; this change does not copy its attack client, recipient overrides,
account data, or embedded Apple icon. Fixtures here use synthetic text and IDs.

## Verification and remaining work

Run the isolated harness from the repository root:

```sh
cargo test --manifest-path tools/poll-codec/Cargo.toml
```

Or run in a Linux Rust image, with the repository mounted at `/workspace`:

```sh
docker run --rm -v "$PWD:/workspace" -w /workspace rust:1.90-bookworm \
  cargo test --manifest-path tools/poll-codec/Cargo.toml
```

The harness imports the actual production module and depends only on base64,
serde, and serde_json. It does not compile or initialize rustpush registration,
contact Apple, access an account, read runtime state, target a device, or send.
Tests establish synthetic codec behavior only. Follow `AGENTS.md`: do not run
`rustfmt` on this repository.

Still required: native balloon serialization fields and constructors, Corten
FFI records/functions and regenerated bindings, structured bridge/Buddy events,
sender/alias and poll correlation checks, restart/deduplication handling, and
controlled native rendering/vote verification. Added-choice, vote removal,
result finalization, and newer native schema semantics remain unproven. No
working native poll delivery is claimed by this module or its passing tests.
