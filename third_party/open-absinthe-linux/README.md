# open-absinthe

An open, drop-in replacement for OpenBubbles' closed-source **NAC** component.

iMessage registration needs a short Apple-signed blob called **validation
data**. Only Apple's obfuscated `IMDAppleServices` binary (an x86-64 Mach-O)
can produce it, so this crate runs the real binary under the
[Unicorn](https://www.unicorn-engine.org/) CPU emulator and answers the ~37
CoreFoundation / IOKit / libc calls it makes from a configured Mac hardware
identity. It is a Rust port of pypush's `emulated/nac.py` + `jelly.py`.

The public API is the one [`rustpush`](https://github.com/OpenBubbles/rustpush)
expects, so the crate replaces the closed `open-absinthe` without caller
changes.

## The binary: placed by bootstrap, never redistributed, never downloaded here

`IMDAppleServices` is Apple's property and is not in this repository. The
library does **no network I/O**. `tools/bootstrap.sh` downloads it once and
verifies it (sha1 `e1181ccad82e6629d52c6a006645ad87ee59bd13`, a 6,222,784-byte
fat Mach-O).

- `nac::binary_path()`: `$OPEN_ABSINTHE_BINARY` if set and non-empty, else
  `${XDG_DATA_HOME:-~/.local/share}/imessage-linux/IMDAppleServices`.
- On the first `ValidationCtx::new` the file is read, its sha1 is checked
  against `nac::BINARY_SHA1`, and the x86-64 slice is cached for the life of
  the process. A missing file fails with `nac::E_NO_BINARY` (-10) and a wrong
  hash with `nac::E_BAD_HASH` (-12). Both errors are logged with the path and
  tell you to run `tools/bootstrap.sh`. Failures are not cached.

`imsg doctor` reports the same path and hash check.

## API

```rust
use open_absinthe::nac::{HardwareConfig, ValidationCtx};

let mut request = Vec::new();
let mut ctx = ValidationCtx::new(&cert_chain, &mut request, &hw)?; // nac_init: 338-byte request
// POST `request` to Apple's id-initialize-validation; read `session-info` (698 bytes)
ctx.key_establishment(&session_info)?;                             // nac_key_establishment
let validation_data = ctx.sign()?;                                 // nac_sign: 517 bytes
```

- `HardwareConfig` is serde-serializable (byte fields become plist `<data>`).
  Its `Debug` output is redacted because the struct is a device credential.
- `ValidationCtx` is `Send` (rustpush holds it across `.await`). The emulator
  sits behind a `Mutex`, which is how `sign(&self)` gets mutable access soundly.
- `AbsintheError(i32)` holds either the binary's own status code or one of
  the crate's codes (`-1`, `-10`, `-12`, `-20`, `-100`…`-104`); the table is
  in `lib.rs`.
- `HardwareConfig::from_validation_data` is unsupported and returns
  `Err(AbsintheError(-1))`.

## Size signals

For a given identity the sizes do not change between runs: a **338**-byte
request, **698**-byte session-info and, for the Intel reference identity,
**517**-byte validation data. If the ROM/MLB lookup misses, that blob
shrinks to **389** bytes and Apple rejects registration. The validation
data size also depends on the identity itself (the binary sizes its
buffers from the board id / model / serial lengths): a real Apple Silicon
Apple Silicon identity gives 389 bytes with every lookup hitting, and Apple
accepted it (2026-10-16). So 389 is only a red flag for the reference
identity. That lookup goes through the uppercase
`4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:{ROM,MLB}` registry keys, so a
wrong-case key is enough to cause it. The bytes themselves differ on every
run because the binary calls `arc4random`. With `arc4random` pinned to 0,
this crate's request and validation data are byte-identical to pypush's.

## Emulation design

The x86-64 slice is mapped **flat at address 0**, so every file offset is
also its runtime address. Page 0 is unmapped so that a NULL dereference
faults.

| region | address | purpose |
|---|---|---|
| image | `0x0` | the binary (must end below the stack) |
| stack | `0x0030_0000` | 1 MiB |
| heap | `0x0040_0000` | 1 MiB bump allocator, 16-byte aligned; when it is exhausted `malloc` returns NULL |
| stop page | `0x0090_0000` | a page of `ret`, pushed as the return address; emulation halts when the call returns there |
| hook page | `0x00D0_0000` | a page of `ret`; each hooked import gets `0xD00000 + index` (pypush's order), and one code hook dispatches on the address |

Imports are resolved the way dyld resolves them: first the indirect symbol
table for the lazy and non-lazy pointer sections, then the bind-opcode
stream. CF objects are 1-based handles into a side table.

Hardening:

- Hooks never panic, because they run inside an `extern "C"` callback.
- Guest reads and writes are bounds-checked and capped at 1 MiB.
- C-string reads stop at unmapped memory.
- The Mach-O parser and the bind interpreter reject malformed input without
  panicking or looping without bound.
- Each NAC call is limited to **30 s** of wall-clock time (no instruction
  count limit, which would slow every call). A runaway call returns
  `E_EMU_LIMIT` (-101).
- Unexpected hook events are logged at `error!`/`warn!` and counted. A healthy
  run logs none.

### Hooks

`_malloc`, `___memset_chk` (returns dest), `_memcpy` (returns dest),
`___bzero`, `_free`, `_sysctlbyname`, `_statfs$INODE64`, `_arc4random`,
`_IORegistryEntryFromPath`, `_IORegistryEntryCreateCFProperty` (identity
lookup), `_IORegistryEntryGetParentEntry`, `_IOServiceMatching`,
`_IOServiceGetMatchingService`, `_IOServiceGetMatchingServices` /
`_IOIteratorNext` (exactly one fake ethernet interface), `_IOObjectRelease`,
`_CFGetTypeID`, `_CFStringGetTypeID`, `_CFDataGetTypeID`, `_CFDataGetLength`,
`_CFDataGetBytes` (CFRange semantics), `_CFStringGetLength`,
`_CFStringGetMaximumSizeForEncoding`, `_CFStringGetCString`
(NUL-terminated, returns true), `_CFDictionaryCreateMutable`,
`_CFDictionaryGetValue`, `_CFDictionarySetValue`, `_CFUUIDCreateString`,
`_CFRelease`, `_DASessionCreate`, `_DADiskCreateFromBSDName`,
`_DADiskCopyDescription` (root-disk UUID).

The data globals are `___stack_chk_guard`, `_kIOMasterPortDefault`,
`_kCFAllocatorDefault`, `_kDADiskDescriptionVolumeUUIDKey` and
`_kCFBooleanTrue`. They are bound into the hook page, so each one reads as
`0xC3C3…C3`. The only one the binary uses as a dictionary key is the Disk
Arbitration volume-UUID key, so that word maps to it. A key that is a
constant `__builtin_CFString` in the image (`IOPropertyMatch`,
`IOPrimaryInterface`) is resolved to its text, and any other raw pointer is
stored opaquely.

## Tests

```sh
cargo test -p open-absinthe                                   # unit + offline reference
cargo test -p open-absinthe --release -- --ignored --nocapture  # live test against Apple
```

- **Unit tests** cover:
  - fat-slice selection and `parse` on a synthetic Mach-O;
  - every bind opcode, plus the caps on hostile input;
  - ULEB/SLEB decoding;
  - hooks given garbage arguments;
  - bounded C-string and CFString reads;
  - the heap allocator;
  - the `HardwareConfig` plist round trip and `Debug` redaction;
  - `ValidationCtx: Send`.
- **`missing_binary`** points `$OPEN_ABSINTHE_BINARY` at a temporary path. A
  missing file must fail with `E_NO_BINARY` and a junk file with `E_BAD_HASH`.
  This test does not need the real binary.
- **`reference_offline`** runs by default and needs no network. It uses
  pypush's reference identity and the bootstrap-placed `cert-1.0.plist`. It
  runs `nac_init` twice and requires a 338-byte request each time with zero
  hook anomalies. If the binary or the cert is absent, it prints `SKIP:` and
  passes.
- **`reference_live`** (`#[ignore]`) runs the full flow against Apple's
  `id-initialize-validation` endpoint, which it finds through the IDS bag. It
  asserts sizes of 338, 698 and 517. It uses JJTech's published identity and
  registers nothing. With `OPEN_ABSINTHE_HWCONFIG=<hwconfig.plist>`,
  `own_identity_validation_data_is_accepted` runs the same round with your
  own identity and only requires a successful round and a plausible
  (300–800 byte) blob, since the size is identity dependent;
  `own_identity_bisect` is a print-only diagnostic. Apple's IDS hosts use Apple's private PKI, so this test
  shells out to `curl -k`. That is test glue only: the library itself never
  does network I/O.

## Build notes

`unicorn-engine` builds a bundled QEMU with cmake. Building only `arch_x86`
takes about 12 s, against about 80 s for `arch_all`. QEMU references 128-bit
atomics, so `build.rs` links `libatomic` on Linux.

`unicorn-engine-sys` also needs a C compiler and `cmake`, and runs `bindgen`,
which needs `libclang` (e.g. `clang` / `libclang-dev` packages).

Identity strings are assumed to be ASCII (Apple's identifiers, such as
serials, UUIDs and model names, are). The `CFStringGetMaximumSizeForEncoding`
hook returns `length` like pypush, not the `3 * length` real CF returns for
UTF-8. The binary sizes its output from this value: `3 * length` makes the
validation data 645 bytes instead of the correct 517. A non-ASCII string
makes `CFStringGetCString` refuse, which is logged as a hook anomaly.
