//! NAC ("validation data") API: [`HardwareConfig`] and [`ValidationCtx`].
//!
//! Flow used by rustpush (`src/macos.rs`):
//! 1. [`ValidationCtx::new`] with Apple's cert chain -> request bytes
//!    (healthy run: **338 bytes**), sent to `id-initialize-validation`;
//! 2. [`ValidationCtx::key_establishment`] with Apple's session-info
//!    (**698 bytes**);
//! 3. [`ValidationCtx::sign`] -> validation data. Its size depends on the
//!    identity: **517 bytes** for the Intel reference identity (where 389
//!    means the ROM/MLB lookups missed and Apple will reject it); a real
//!    Apple Silicon identity gives 389 bytes, which Apple accepts.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha1::{Digest, Sha1};

use crate::AbsintheError;
use crate::emulator::{self, CfObj, Emulator, IoKitData};

/// `IMDAppleServices` is missing or unreadable at [`binary_path`].
pub const E_NO_BINARY: i32 = -10;
/// `IMDAppleServices` does not hash to [`BINARY_SHA1`].
pub const E_BAD_HASH: i32 = -12;
/// The binary is not a usable fat x86-64 Mach-O.
pub const E_BAD_MACHO: i32 = -20;
/// Unicorn reported an error (memory fault, invalid instruction, ...).
pub const E_UNICORN: i32 = -100;
/// A NAC call did not return within the emulator's time limit (30 s).
pub const E_EMU_LIMIT: i32 = -101;
/// The host could not allocate in the emulated heap (`Emulator::alloc`,
/// for input/output buffers). Guest-side exhaustion is different: the
/// binary's `malloc` returns NULL and the call then fails with [`E_UNICORN`].
pub const E_HEAP: i32 = -102;
/// The binary returned an implausible output buffer.
pub const E_BAD_OUTPUT: i32 = -103;
/// The context's lock was poisoned by an earlier panic.
pub const E_POISONED: i32 = -104;

/// sha1 of the only `IMDAppleServices` build the emulator supports.
pub const BINARY_SHA1: &str = "e1181ccad82e6629d52c6a006645ad87ee59bd13";

/// What to run to download it: the checkout's script, or the copy an
/// installed package ships (which only downloads). Windows: `imsg setup`.
#[cfg(not(windows))]
pub const BOOTSTRAP_HINT: &str = "tools/bootstrap.sh (installed package: /usr/share/imessage-linux/tools/bootstrap.sh)";
#[cfg(windows)]
pub const BOOTSTRAP_HINT: &str = "`imsg setup` (or `imsg setup --from <folder>` with a copy of ~/.local/share/imessage-linux from a Linux install)";

/// Location of Apple's `IMDAppleServices` (downloaded and sha1-verified by
/// `tools/bootstrap.sh`, never redistributed; this library never downloads
/// it): `$OPEN_ABSINTHE_BINARY` if set, else
/// `${XDG_DATA_HOME:-~/.local/share}/imessage-linux/IMDAppleServices`
/// (Windows: `%LOCALAPPDATA%\imessage-linux\IMDAppleServices`).
pub fn binary_path() -> PathBuf {
    if let Some(p) = std::env::var_os("OPEN_ABSINTHE_BINARY").filter(|v| !v.is_empty()) {
        return PathBuf::from(p);
    }
    data_dir().join("IMDAppleServices")
}

#[cfg(not(windows))]
fn data_dir() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".local/share")
        });
    base.join("imessage-linux")
}

/// Windows: `%LOCALAPPDATA%\imessage-linux`, fallback
/// `%USERPROFILE%\AppData\Local`. Same rule as
/// `imessage_common::paths::data_dir` (this crate cannot depend on it).
#[cfg(windows)]
fn data_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| {
            std::env::var_os("USERPROFILE")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join("AppData")
                .join("Local")
        });
    base.join("imessage-linux")
}

fn sha1_hex(data: &[u8]) -> String {
    Sha1::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// The verified x86-64 slice, loaded once per process.
static X64_SLICE: OnceLock<Arc<[u8]>> = OnceLock::new();

/// Read `IMDAppleServices` from [`binary_path`], verify its sha1 and return
/// its x86-64 slice. The first success is cached for the life of the process
/// (later calls neither re-read the 6 MB file nor see `$OPEN_ABSINTHE_BINARY`
/// changes); failures are not cached, so running `tools/bootstrap.sh` later
/// fixes a running daemon.
fn load_x64_slice() -> Result<Arc<[u8]>, AbsintheError> {
    if let Some(s) = X64_SLICE.get() {
        return Ok(s.clone());
    }
    let path = binary_path();
    let data = std::fs::read(&path).map_err(|e| {
        log::error!(
            "open-absinthe: cannot read IMDAppleServices at {}: {e}; run {BOOTSTRAP_HINT} \
             (or point $OPEN_ABSINTHE_BINARY at the file)",
            path.display()
        );
        AbsintheError(E_NO_BINARY)
    })?;
    let sum = sha1_hex(&data);
    if sum != BINARY_SHA1 {
        log::error!(
            "open-absinthe: {} has sha1 {sum}, expected {BINARY_SHA1}; run {BOOTSTRAP_HINT} to re-download it",
            path.display()
        );
        return Err(AbsintheError(E_BAD_HASH));
    }
    let slice: Arc<[u8]> = Arc::from(crate::macho::x64_slice(&data)?);
    Ok(X64_SLICE.get_or_init(|| slice).clone())
}

// ---------------------------------------------------------------------------
// serde helpers (same names and behaviour as upstream open-absinthe)
// ---------------------------------------------------------------------------

pub fn bin_serialize<S>(x: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bytes(x)
}

pub fn bin_deserialize_mac<'de, D>(d: D) -> Result<[u8; 6], D::Error>
where
    D: Deserializer<'de>,
{
    let v = bin_deserialize(d)?;
    <[u8; 6]>::try_from(v.as_slice())
        .map_err(|_| de::Error::invalid_length(v.len(), &"exactly 6 bytes (MAC address)"))
}

pub fn bin_deserialize<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct DataVisitor;

    impl<'de> de::Visitor<'de> for DataVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a byte array")
        }

        fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            Ok(v.to_vec())
        }

        fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
            Ok(v)
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(b) = seq.next_element::<u8>()? {
                out.push(b);
            }
            Ok(out)
        }
    }

    d.deserialize_byte_buf(DataVisitor)
}

// ---------------------------------------------------------------------------
// HardwareConfig
// ---------------------------------------------------------------------------

/// The 14 Mac hardware identifiers presented to `IMDAppleServices`.
///
/// Field names, order, and serde attributes match upstream open-absinthe, so
/// rustpush's persisted `MacOSConfig` and our `hwconfig.plist` are compatible.
#[derive(Clone, Serialize, Deserialize)]
pub struct HardwareConfig {
    pub product_name: String,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize_mac")]
    pub io_mac_address: [u8; 6],
    pub platform_serial_number: String,
    pub platform_uuid: String,
    pub root_disk_uuid: String,
    pub board_id: String,
    pub os_build_num: String,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub platform_serial_number_enc: Vec<u8>, // Gq3489ugfi
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub platform_uuid_enc: Vec<u8>, // Fyp98tpgj
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub root_disk_uuid_enc: Vec<u8>, // kbjfrfpoJU
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub rom: Vec<u8>,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub rom_enc: Vec<u8>, // oycqAZloTNDm
    pub mlb: String,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub mlb_enc: Vec<u8>, // abKPld1EcMni
}

/// Show only the last `keep` characters of an identifier.
fn mask(s: &str, keep: usize) -> String {
    let n = s.chars().count();
    if n <= keep {
        return "*".repeat(n);
    }
    let tail: String = s.chars().skip(n - keep).collect();
    format!("{}{}", "*".repeat(n - keep), tail)
}

struct Redacted(String);

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn blob(b: &[u8]) -> Redacted {
    Redacted(format!("<{} bytes>", b.len()))
}

/// Redacting `Debug`: this struct is a device credential. Serial, MLB, UUIDs
/// and ROM are masked; FairPlay blobs are shown as lengths only.
impl fmt::Debug for HardwareConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = self.io_mac_address;
        f.debug_struct("HardwareConfig")
            .field("product_name", &self.product_name)
            .field("io_mac_address", &Redacted(format!("{:02x}:{:02x}:{:02x}:**:**:**", m[0], m[1], m[2])))
            .field("platform_serial_number", &Redacted(mask(&self.platform_serial_number, 3)))
            .field("platform_uuid", &Redacted(mask(&self.platform_uuid, 4)))
            .field("root_disk_uuid", &Redacted(mask(&self.root_disk_uuid, 4)))
            .field("board_id", &self.board_id)
            .field("os_build_num", &self.os_build_num)
            .field("platform_serial_number_enc", &blob(&self.platform_serial_number_enc))
            .field("platform_uuid_enc", &blob(&self.platform_uuid_enc))
            .field("root_disk_uuid_enc", &blob(&self.root_disk_uuid_enc))
            .field("rom", &blob(&self.rom))
            .field("rom_enc", &blob(&self.rom_enc))
            .field("mlb", &Redacted(mask(&self.mlb, 3)))
            .field("mlb_enc", &blob(&self.mlb_enc))
            .finish()
    }
}

/// The `IOPower`-plane registry prefix `IMDAppleServices` reads ROM and MLB
/// under. Case matters: the binary queries uppercase `4A6A`; a lowercase key
/// silently misses, dropping ROM+MLB and producing (for the reference
/// identity) a 389-byte blob Apple rejects instead of the healthy 517.
const ROM_MLB_PREFIX: &str = "4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14";

impl HardwareConfig {
    /// The faked IOKit registry, keyed and typed exactly as pypush's
    /// `emulated/data.plist`.
    fn iokit(&self) -> IoKitData {
        let data = |b: &[u8]| CfObj::Data(b.to_vec());
        // product-name / board-id are NUL-terminated CFData, as on a real Mac.
        let nul = |s: &str| CfObj::Data(s.bytes().chain(std::iter::once(0)).collect());
        let registry = HashMap::from([
            ("product-name".to_owned(), nul(&self.product_name)),
            ("board-id".to_owned(), nul(&self.board_id)),
            ("IOPlatformSerialNumber".to_owned(), CfObj::Str(self.platform_serial_number.clone())),
            ("IOPlatformUUID".to_owned(), CfObj::Str(self.platform_uuid.clone())),
            ("IOMACAddress".to_owned(), data(&self.io_mac_address)),
            // MLB is raw bytes, NOT NUL-terminated (unlike board-id).
            (format!("{ROM_MLB_PREFIX}:MLB"), data(self.mlb.as_bytes())),
            (format!("{ROM_MLB_PREFIX}:ROM"), data(&self.rom)),
            ("Gq3489ugfi".to_owned(), data(&self.platform_serial_number_enc)),
            ("Fyp98tpgj".to_owned(), data(&self.platform_uuid_enc)),
            ("kbjfrfpoJU".to_owned(), data(&self.root_disk_uuid_enc)),
            ("oycqAZloTNDm".to_owned(), data(&self.rom_enc)),
            ("abKPld1EcMni".to_owned(), data(&self.mlb_enc)),
        ]);
        IoKitData { registry, root_disk_uuid: self.root_disk_uuid.clone() }
    }

    /// Upstream extracts a config from a relay's validation data; that is not
    /// possible with the emulator, so this always fails (it never panics).
    pub fn from_validation_data(_data: &[u8]) -> Result<HardwareConfig, AbsintheError> {
        log::error!("open-absinthe: HardwareConfig::from_validation_data is not supported by the emulator");
        Err(AbsintheError(-1))
    }
}

// ---------------------------------------------------------------------------
// ValidationCtx
// ---------------------------------------------------------------------------

/// A non-zero NAC return value as the signed status it means (pypush:
/// `(ret & 0xffffffff ^ 0x80000000) - 0x80000000`).
fn nac_err(what: &str, ret: u64) -> AbsintheError {
    let code = ret as u32 as i32;
    log::error!("open-absinthe: {what} returned {code}");
    AbsintheError(code)
}

struct Inner {
    emu: Emulator,
    /// The binary's opaque validation-context pointer from `nac_init`.
    ctx: u64,
}

/// A NAC validation session (one per registration attempt).
pub struct ValidationCtx {
    /// `sign` takes `&self` (rustpush's signature) but must run the emulator
    /// mutably; the Mutex provides that soundly.
    inner: Mutex<Inner>,
}

// SAFETY: `ValidationCtx` is `!Send` only because `Unicorn` holds an
// `Rc<UnsafeCell<..>>` (plus raw engine pointers). That `Rc` and its `Weak`
// clones (held by our one code hook) are created inside `Emulator::new` and
// never leave this context: the emulator instance is exclusively owned by the
// ctx, no handle to it is ever returned or stored elsewhere, and every access
// (including the temporary `Rc` the hook trampoline upgrades during
// `emu_start`) happens through the Mutex, i.e. on one thread at a time. The
// hook (`emulator::dispatch`) is a plain fn that captures nothing, in
// particular no thread-local state; Unicorn's own per-thread CPU pointer is
// re-established at the start of every `uc_emu_start`, so the engine is not
// tied to the thread that created it. Moving the whole context to another
// thread is therefore sound. (`Sync` is deliberately not claimed.)
unsafe impl Send for ValidationCtx {}

impl ValidationCtx {
    /// `nac_init`: consumes Apple's validation cert chain and writes the
    /// session request into `out_request_bytes`.
    pub fn new(
        cert_chain: &[u8],
        out_request_bytes: &mut Vec<u8>,
        hw_config: &HardwareConfig,
    ) -> Result<ValidationCtx, AbsintheError> {
        let slice = load_x64_slice()?;
        let mut emu = Emulator::new(&slice, hw_config.iokit())?;
        drop(slice);

        let cert = emu.alloc_bytes(cert_chain)?;
        let out_ctx = emu.alloc(8)?;
        let out_req = emu.alloc(8)?;
        let out_len = emu.alloc(8)?;
        let ret = emu.call(
            "nac_init",
            emulator::NAC_INIT,
            &[cert, cert_chain.len() as u64, out_ctx, out_req, out_len],
        )?;
        if ret != 0 {
            return Err(nac_err("nac_init", ret));
        }
        let ctx = emu.read_u64(out_ctx)?;
        let req = emu.read_u64(out_req)?;
        let len = emu.read_u64(out_len)?;
        *out_request_bytes = emu.read_output(req, len)?;
        log::debug!("open-absinthe: nac_init ok, request is {} bytes", out_request_bytes.len());
        Ok(ValidationCtx { inner: Mutex::new(Inner { emu, ctx }) })
    }

    /// `nac_key_establishment`: feeds Apple's session-info response.
    pub fn key_establishment(&mut self, response: &[u8]) -> Result<(), AbsintheError> {
        let inner = self.inner.get_mut().map_err(|_| poisoned())?;
        let addr = inner.emu.alloc_bytes(response)?;
        let ret = inner.emu.call(
            "nac_key_establishment",
            emulator::NAC_KEY_ESTABLISHMENT,
            &[inner.ctx, addr, response.len() as u64],
        )?;
        if ret != 0 {
            return Err(nac_err("nac_key_establishment", ret));
        }
        Ok(())
    }

    /// `nac_sign`: produces the validation data.
    pub fn sign(&self) -> Result<Vec<u8>, AbsintheError> {
        let mut inner = self.inner.lock().map_err(|_| poisoned())?;
        let Inner { emu, ctx } = &mut *inner;
        let out_data = emu.alloc(8)?;
        let out_len = emu.alloc(8)?;
        let ret = emu.call("nac_sign", emulator::NAC_SIGN, &[*ctx, 0, 0, out_data, out_len])?;
        if ret != 0 {
            return Err(nac_err("nac_sign", ret));
        }
        let addr = emu.read_u64(out_data)?;
        let len = emu.read_u64(out_len)?;
        let data = emu.read_output(addr, len)?;
        log::debug!("open-absinthe: nac_sign ok, validation data is {} bytes", data.len());
        Ok(data)
    }

    /// Number of unexpected hook / loader events so far (each was logged at
    /// `warn!`/`error!`). Zero on a healthy run; used by the reference tests.
    #[doc(hidden)]
    pub fn hook_anomalies(&self) -> usize {
        self.inner.lock().map(|i| i.emu.anomalies()).unwrap_or(usize::MAX)
    }
}

fn poisoned() -> AbsintheError {
    log::error!("open-absinthe: validation context poisoned by an earlier panic");
    AbsintheError(E_POISONED)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// rustpush holds the context across `.await` in a `Send` future.
    #[test]
    fn validation_ctx_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ValidationCtx>();
    }

    fn fake() -> HardwareConfig {
        HardwareConfig {
            product_name: "Macmini7,1".into(),
            io_mac_address: [0x02, 0x11, 0x22, 0x33, 0x44, 0x55],
            platform_serial_number: "C02FAKE00001".into(),
            platform_uuid: "00000000-1111-2222-3333-444444444444".into(),
            root_disk_uuid: "55555555-6666-7777-8888-999999999999".into(),
            board_id: "Mac-35C5E08120C7EEAF".into(),
            os_build_num: "22F66".into(),
            platform_serial_number_enc: vec![1; 17],
            platform_uuid_enc: vec![2; 17],
            root_disk_uuid_enc: vec![3; 17],
            rom: vec![0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
            rom_enc: vec![4; 17],
            mlb: "C02FAKEMLB0000001".into(),
            mlb_enc: vec![5; 17],
        }
    }

    #[test]
    fn plist_round_trip() {
        let hw = fake();
        let mut xml = Vec::new();
        plist::to_writer_xml(&mut xml, &hw).unwrap();
        let text = String::from_utf8(xml.clone()).unwrap();
        assert!(text.contains("<key>io_mac_address</key>"));
        assert!(text.contains("<data>"), "byte fields must serialize as <data>");
        let back: HardwareConfig = plist::from_bytes(&xml).unwrap();
        assert_eq!(back.io_mac_address, hw.io_mac_address);
        assert_eq!(back.platform_serial_number, hw.platform_serial_number);
        assert_eq!(back.rom, hw.rom);
        assert_eq!(back.mlb_enc, hw.mlb_enc);
        assert_eq!(back.root_disk_uuid, hw.root_disk_uuid);
    }

    #[test]
    fn bad_mac_length_is_an_error_not_a_panic() {
        let mut hw = fake();
        hw.mlb_enc = vec![];
        let mut xml = Vec::new();
        plist::to_writer_xml(&mut xml, &hw).unwrap();
        // Replace the 6-byte MAC with 3 bytes ("AhEi" = 02 11 22).
        let text = String::from_utf8(xml).unwrap().replace("AhEiM0RV", "AhEi");
        assert!(plist::from_bytes::<HardwareConfig>(text.as_bytes()).is_err());
    }

    #[test]
    fn debug_is_redacted() {
        let s = format!("{:?}", fake());
        for secret in ["C02FAKE00001", "C02FAKEMLB0000001", "00000000-1111", "55555555-6666", "33:44:55"] {
            assert!(!s.contains(secret), "Debug leaked {secret}: {s}");
        }
        assert!(s.contains("Macmini7,1"));
    }

    #[test]
    fn from_validation_data_errors_instead_of_panicking() {
        assert_eq!(HardwareConfig::from_validation_data(&[0; 517]).err(), Some(AbsintheError(-1)));
    }

    #[test]
    fn iokit_registry_matches_pypush_layout() {
        let io = fake().iokit();
        assert_eq!(io.registry.len(), 12);
        assert!(matches!(io.registry.get("board-id"), Some(CfObj::Data(d)) if d == b"Mac-35C5E08120C7EEAF\0"));
        assert!(matches!(io.registry.get("product-name"), Some(CfObj::Data(d)) if d == b"Macmini7,1\0"));
        assert!(matches!(io.registry.get("IOPlatformUUID"), Some(CfObj::Str(_))));
        let mlb = io.registry.get("4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:MLB");
        assert!(matches!(mlb, Some(CfObj::Data(d)) if d == b"C02FAKEMLB0000001"));
        assert!(io.registry.contains_key("4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:ROM"));
        assert_eq!(io.root_disk_uuid, "55555555-6666-7777-8888-999999999999");
    }

    #[test]
    fn binary_path_default_name() {
        // Read-only: mutating the process env would race other tests.
        let path = binary_path();
        assert!(path.ends_with("IMDAppleServices") || std::env::var_os("OPEN_ABSINTHE_BINARY").is_some());
        assert_eq!(BINARY_SHA1.len(), 40);
    }
}
