//! `open-absinthe`: produces Apple IDS "validation data" for a Mac hardware
//! identity by emulating Apple's `IMDAppleServices` NAC routines.
//!
//! API-compatible with OpenBubbles' (now closed) `open-absinthe` as used by
//! rustpush (`open_absinthe::AbsintheError`, `open_absinthe::nac::{
//! HardwareConfig, ValidationCtx}`).
//!
//! The real Apple binary (an x86-64 Mach-O, placed on disk by
//! `tools/bootstrap.sh`, never redistributed) runs under the
//! [Unicorn](https://www.unicorn-engine.org/) CPU emulator; the ~37
//! CoreFoundation / IOKit / libc functions it imports are answered from a
//! [`nac::HardwareConfig`]. The library never touches the network. See the
//! crate README for the emulation design.

use std::error::Error;
use std::fmt;

mod emulator;
mod macho;
pub mod nac;

/// Error from the NAC routines.
///
/// The value is either the status code `IMDAppleServices` itself returned
/// (non-zero results of `nac_init` / `nac_key_establishment` / `nac_sign`,
/// typically large negative numbers such as `-44023`), or one of this crate's
/// own small negative codes:
///
/// | code | meaning |
/// |---|---|
/// | `-1` | [`nac::HardwareConfig::from_validation_data`] (unsupported) |
/// | [`nac::E_NO_BINARY`] (`-10`) | `IMDAppleServices` missing or unreadable at [`nac::binary_path`] |
/// | [`nac::E_BAD_HASH`] (`-12`) | `IMDAppleServices` sha1 is not [`nac::BINARY_SHA1`] |
/// | [`nac::E_BAD_MACHO`] (`-20`) | binary is not a usable fat x86-64 Mach-O |
/// | [`nac::E_UNICORN`] (`-100`) | the emulator faulted (bad memory access, invalid instruction, ...) |
/// | [`nac::E_EMU_LIMIT`] (`-101`) | a NAC call did not return within the time limit |
/// | [`nac::E_HEAP`] (`-102`) | host-side allocation in the emulated heap failed (guest `malloc` exhaustion returns NULL and surfaces as `E_UNICORN`) |
/// | [`nac::E_BAD_OUTPUT`] (`-103`) | the binary returned an implausible output buffer |
/// | [`nac::E_POISONED`] (`-104`) | the context was poisoned by an earlier panic |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbsintheError(pub i32);

impl fmt::Display for AbsintheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for AbsintheError {}
