//! The Unicorn-based emulation of `IMDAppleServices` (a Rust port of pypush's
//! `emulated/jelly.py` + the hooks in `emulated/nac.py`).
//!
//! # Memory layout
//!
//! The x86-64 slice is mapped **flat at address 0**, so every file offset is
//! also its runtime address; no slide is applied. Page 0 is unmapped again so
//! a NULL dereference faults instead of reading the Mach-O header.
//!
//! | region | address | size | purpose |
//! |---|---|---|---|
//! | image | `0x0` | slice size | the binary itself (must end below the stack) |
//! | stack | [`STACK_BASE`] | 1 MiB | `rsp`/`rbp` start at the top |
//! | heap | [`HEAP_BASE`] | 1 MiB | bump allocator, 16-byte aligned, never freed |
//! | stop page | [`STOP_ADDRESS`] | 1 page of `ret` | pushed as the return address of every call into the binary; emulation halts there |
//! | hook page | [`HOOK_BASE`] | 1 page of `ret` | each serviced import gets the address `HOOK_BASE + index`; one code hook over the page dispatches on the hit address |
//!
//! Imports are resolved like dyld, two ways (in this order, as pypush does):
//! the indirect-symbol table for the lazy / non-lazy pointer sections, then the
//! dyld bind-opcode stream. Symbols in [`HOOKS`] are pointed at their hook
//! address; the rest are left untouched (never called on the NAC path).
//!
//! CoreFoundation objects are faked as **1-based indices** into
//! [`EmuState::objects`] (0 would be NULL).
//!
//! # Robustness
//!
//! Hooks run inside a Unicorn callback (an `extern "C"` boundary), so they
//! must never panic: every guest read/write is bounds-checked and size-capped
//! ([`HOOK_IO_MAX`]), allocation failures return NULL to the guest, and
//! anything unexpected is logged and counted in [`EmuState::anomalies`]
//! instead. Each call into the binary is limited to [`CALL_TIMEOUT_US`].

use std::collections::HashMap;
use std::fmt;

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

use unicorn_engine::unicorn_const::{Arch, Mode, Prot, uc_error};
use unicorn_engine::{RegisterX86, Unicorn};

use crate::AbsintheError;
use crate::macho::{self, u64le};
use crate::nac::{E_BAD_MACHO, E_BAD_OUTPUT, E_EMU_LIMIT, E_HEAP, E_UNICORN};

const PAGE_SIZE: u64 = 0x1000;
pub const HOOK_BASE: u64 = 0x00D0_0000;
const HOOK_SIZE: u64 = PAGE_SIZE;
pub const STACK_BASE: u64 = 0x0030_0000;
const STACK_SIZE: u64 = 0x0010_0000;
pub const HEAP_BASE: u64 = 0x0040_0000;
pub const HEAP_SIZE: u64 = 0x0010_0000;
/// Return address for emulated calls; a page of `ret` where emulation halts.
pub const STOP_ADDRESS: u64 = 0x0090_0000;

/// Largest single guest read/write a hook (or an output buffer) may perform.
/// Every guest buffer lives in the 1 MiB heap or stack, so anything larger is
/// garbage and must not turn into a multi-gigabyte host allocation.
pub const HOOK_IO_MAX: u64 = HEAP_SIZE;

/// Wall-clock limit for one call into the binary. A healthy `nac_init` takes
/// well under a second under Unicorn (sign is faster); 30 s only trips on a
/// runaway loop, which then fails with [`E_EMU_LIMIT`] instead of hanging the
/// daemon. There is deliberately no instruction-count limit: Unicorn enforces
/// that with a per-instruction hook, which would slow every call down.
pub const CALL_TIMEOUT_US: u64 = 30_000_000;

/// Entry points inside this specific `IMDAppleServices` (file offsets == addrs).
pub const NAC_INIT: u64 = 0xB1DB0;
pub const NAC_KEY_ESTABLISHMENT: u64 = 0xB1DD0;
pub const NAC_SIGN: u64 = 0xB1DF0;

/// The value the binary reads out of any imported *data* symbol (CF constant
/// globals such as `kDADiskDescriptionVolumeUUIDKey` / `kCFBooleanTrue`,
/// `__stack_chk_guard`, `kIOMasterPortDefault`): those imports are bound into
/// the hook page like functions, so loading the variable yields eight `ret`
/// opcodes. pypush relies on the same artefact.
pub const HOOK_PAGE_WORD: u64 = 0xC3C3_C3C3_C3C3_C3C3;

const ARG_REGS: [RegisterX86; 6] = [
    RegisterX86::RDI,
    RegisterX86::RSI,
    RegisterX86::RDX,
    RegisterX86::RCX,
    RegisterX86::R8,
    RegisterX86::R9,
];

/// Hooked symbols. A symbol's index here **is** its hook-table address
/// (`HOOK_BASE + index`), and the order is pypush's, so addresses match the
/// reference implementation byte for byte. Do not reorder.
///
/// The `_k…` / `___stack_chk_guard` entries are data globals, never called;
/// they only need an address to bind to (see [`HOOK_PAGE_WORD`]).
pub const HOOKS: &[&str] = &[
    "_malloc",
    "___stack_chk_guard",
    "___memset_chk",
    "_sysctlbyname",
    "_memcpy",
    "_kIOMasterPortDefault",
    "_IORegistryEntryFromPath",
    "_kCFAllocatorDefault",
    "_IORegistryEntryCreateCFProperty",
    "_CFGetTypeID",
    "_CFStringGetTypeID",
    "_CFDataGetTypeID",
    "_CFDataGetLength",
    "_CFDataGetBytes",
    "_CFRelease",
    "_IOObjectRelease",
    "_statfs$INODE64",
    "_DASessionCreate",
    "_DADiskCreateFromBSDName",
    "_kDADiskDescriptionVolumeUUIDKey",
    "_DADiskCopyDescription",
    "_CFDictionaryGetValue",
    "_CFUUIDCreateString",
    "_CFStringGetLength",
    "_CFStringGetMaximumSizeForEncoding",
    "_CFStringGetCString",
    "_free",
    "_IOServiceMatching",
    "_IOServiceGetMatchingService",
    "_CFDictionaryCreateMutable",
    "_kCFBooleanTrue",
    "_CFDictionarySetValue",
    "_IOServiceGetMatchingServices",
    "_IOIteratorNext",
    "___bzero",
    "_IORegistryEntryGetParentEntry",
    "_arc4random",
];

/// Type IDs handed out by `CFDataGetTypeID` / `CFStringGetTypeID`.
const CF_DATA_TYPE_ID: u64 = 1;
const CF_STRING_TYPE_ID: u64 = 2;

/// Key under which `DADiskCopyDescription` stores the root-disk UUID.
const DA_VOLUME_UUID_KEY: &str = "DADiskDescriptionVolumeUUIDKey";

/// A CoreFoundation value, as far as the emulated binary can tell.
#[derive(Clone)]
pub enum CfObj {
    Data(Vec<u8>),
    Str(String),
    Dict(HashMap<String, CfObj>),
    /// A guest pointer that is neither one of our objects nor a readable
    /// constant CFString (e.g. `kCFBooleanTrue`); stored opaquely.
    Raw(#[allow(dead_code)] u64),
}

/// Prints only the variant and its size: these values are hardware
/// identifiers (serials, UUIDs, MAC, ROM, encrypted blobs) and appear in
/// anomaly logs, so their contents must never be formatted.
impl fmt::Debug for CfObj {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CfObj::Data(d) => write!(f, "Data(<{} bytes>)", d.len()),
            CfObj::Str(s) => write!(f, "Str(<{} chars>)", s.chars().count()),
            CfObj::Dict(d) => write!(f, "Dict(<{} keys>)", d.len()),
            CfObj::Raw(p) => write!(f, "Raw({p:#x})"),
        }
    }
}

/// The IOKit registry this machine should appear to have (keys exactly as
/// `IMDAppleServices` queries them), plus the root-disk UUID returned through
/// Disk Arbitration.
pub struct IoKitData {
    pub registry: HashMap<String, CfObj>,
    pub root_disk_uuid: String,
}

/// Mutable state carried alongside the Unicorn instance.
pub struct EmuState {
    objects: Vec<CfObj>,
    heap_used: u64,
    /// `IOServiceGetMatchingServices` / `IOIteratorNext` fake exactly one
    /// ethernet interface; this is the one-shot latch.
    eth_iterator: bool,
    iokit: IoKitData,
    /// End of the mapped image; constant CFStrings must lie below it.
    image_end: u64,
    /// Count of unexpected hook / loader events (each also logged at
    /// `warn!` or `error!`). Zero on a healthy run.
    pub anomalies: usize,
    /// `arc4random` source, seeded in [`Emulator::new`] so the hook never
    /// initialises an RNG (a panic inside the Unicorn callback aborts).
    rng: StdRng,
}

impl EmuState {
    /// Bump-allocate `size` bytes, 16-byte aligned (real malloc alignment;
    /// pypush does not align, which makes no difference to the output).
    /// `None` when the heap is exhausted.
    fn malloc(&mut self, size: u64) -> Option<u64> {
        let rounded = size.checked_add(15)? & !15;
        let end = self.heap_used.checked_add(rounded)?;
        if end > HEAP_SIZE {
            return None;
        }
        let addr = HEAP_BASE + self.heap_used;
        self.heap_used = end;
        Some(addr)
    }

    fn push(&mut self, obj: CfObj) -> u64 {
        self.objects.push(obj);
        self.objects.len() as u64
    }

    /// Our object for a 1-based handle.
    fn get(&self, handle: u64) -> Option<&CfObj> {
        let i = usize::try_from(handle.checked_sub(1)?).ok()?;
        self.objects.get(i)
    }

    fn get_mut(&mut self, handle: u64) -> Option<&mut CfObj> {
        let i = usize::try_from(handle.checked_sub(1)?).ok()?;
        self.objects.get_mut(i)
    }
}

/// Log at `error!` and count an anomaly.
macro_rules! anomaly {
    ($uc:expr, $($arg:tt)*) => {{
        log::error!("open-absinthe: hook: {}", format_args!($($arg)*));
        $uc.get_data_mut().anomalies += 1;
    }};
}

fn uce(what: &str, e: uc_error) -> AbsintheError {
    log::error!("open-absinthe: unicorn error during {what}: {e:?}");
    AbsintheError(E_UNICORN)
}

/// Read `len` guest bytes; `None` if unmapped or larger than [`HOOK_IO_MAX`].
fn read_guest(uc: &Unicorn<EmuState>, addr: u64, len: u64) -> Option<Vec<u8>> {
    if len > HOOK_IO_MAX {
        return None;
    }
    uc.mem_read_as_vec(addr, len as usize).ok()
}

/// Read a NUL-terminated C string (at most 256 bytes, as pypush) without
/// reading past mapped memory: page-sized chunks are read until a NUL, the
/// limit, or an unmapped page.
fn read_cstr(uc: &Unicorn<EmuState>, ptr: u64) -> Option<String> {
    const MAX: u64 = 256;
    let mut out = Vec::new();
    let mut addr = ptr;
    while (out.len() as u64) < MAX {
        let page_left = PAGE_SIZE - (addr % PAGE_SIZE);
        let n = page_left.min(MAX - out.len() as u64);
        let Ok(chunk) = uc.mem_read_as_vec(addr, n as usize) else { break };
        if let Some(end) = chunk.iter().position(|&b| b == 0) {
            out.extend_from_slice(&chunk[..end]);
            return String::from_utf8(out).ok();
        }
        out.extend_from_slice(&chunk);
        addr = addr.checked_add(n)?;
    }
    // No NUL within the limit (or the string runs into unmapped memory):
    // fall back to what was readable, like pypush's fixed 256-byte read.
    if out.is_empty() { None } else { String::from_utf8(out).ok() }
}

/// Read a compile-time `__builtin_CFString` constant (`{isa, flags, char *str,
/// long length}`) from the image. Only pointers into the mapped image are
/// considered; anything else (our object handles, `HOOK_PAGE_WORD`, heap
/// pointers) is not a constant string.
fn read_cfstr(uc: &Unicorn<EmuState>, ptr: u64) -> Option<String> {
    let image_end = uc.get_data().image_end;
    if ptr < PAGE_SIZE || ptr.checked_add(32)? > image_end {
        return None;
    }
    let hdr = uc.mem_read_as_vec(ptr, 32).ok()?;
    let str_ptr = u64le(&hdr, 16)?;
    let length = u64le(&hdr, 24)?;
    if length > 4096 || str_ptr < PAGE_SIZE || str_ptr.checked_add(length)? > image_end {
        return None;
    }
    String::from_utf8(uc.mem_read_as_vec(str_ptr, length as usize).ok()?).ok()
}

/// Resolve a `CFDictionary{Get,Set}Value` key.
///
/// * one of our handles holding a string -> that string (pypush);
/// * [`HOOK_PAGE_WORD`] -> `kDADiskDescriptionVolumeUUIDKey`: every imported
///   CF constant global reads as that same word, and the only one the binary
///   uses as a dictionary key is the Disk Arbitration volume-UUID key it
///   looks up in `DADiskCopyDescription`'s result (pypush's "hack");
/// * a constant `__builtin_CFString` in the image (e.g. the matching-dict keys
///   `IOPropertyMatch` / `IOPrimaryInterface`) -> its text. pypush stores
///   these as opaque ints; recovering the text keeps keys comparable;
/// * anything else -> an opaque `raw:0x…` key (pypush stores the int).
fn dict_key(uc: &mut Unicorn<EmuState>, ptr: u64) -> Option<String> {
    match uc.get_data().get(ptr) {
        Some(CfObj::Str(s)) => return Some(s.clone()),
        Some(other) => {
            let what = format!("{other:?}");
            anomaly!(uc, "dictionary key is a non-string object {what}");
            return None;
        }
        None => {}
    }
    if ptr == HOOK_PAGE_WORD {
        return Some(DA_VOLUME_UUID_KEY.to_owned());
    }
    if let Some(s) = read_cfstr(uc, ptr) {
        log::debug!("open-absinthe: dictionary key {ptr:#x} is constant CFString {s:?}");
        return Some(s);
    }
    log::debug!("open-absinthe: dictionary key {ptr:#x} stored opaquely");
    Some(format!("raw:{ptr:#x}"))
}

/// Resolve a `CFDictionarySetValue` value: our object, a constant CFString,
/// or an opaque pointer (`kCFBooleanTrue` reads as [`HOOK_PAGE_WORD`]).
fn dict_value(uc: &Unicorn<EmuState>, ptr: u64) -> CfObj {
    if let Some(obj) = uc.get_data().get(ptr) {
        return obj.clone();
    }
    match read_cfstr(uc, ptr) {
        Some(s) => CfObj::Str(s),
        None => CfObj::Raw(ptr),
    }
}

fn write_guest(uc: &mut Unicorn<EmuState>, addr: u64, data: &[u8], what: &str) {
    if let Err(e) = uc.mem_write(addr, data) {
        anomaly!(uc, "{what}: write of {} bytes at {addr:#x} failed: {e:?}", data.len());
    }
}

/// Dispatch for every hooked symbol; the hit address selects the symbol.
fn dispatch(uc: &mut Unicorn<EmuState>, address: u64, _size: u32) {
    let Some(&name) = address.checked_sub(HOOK_BASE).and_then(|i| HOOKS.get(i as usize)) else {
        anomaly!(uc, "call to unassigned hook address {address:#x}");
        return;
    };

    let mut a = [0u64; 6];
    for (slot, reg) in a.iter_mut().zip(ARG_REGS) {
        *slot = uc.reg_read(reg).unwrap_or(0);
    }
    log::trace!("open-absinthe: hook {name} args={a:x?}");

    if let Some(v) = hook(uc, name, &a)
        && let Err(e) = uc.reg_write(RegisterX86::RAX, v)
    {
        anomaly!(uc, "{name}: cannot set rax: {e:?}");
    }
}

/// Run one hook; `Some(v)` sets `rax` (pypush writes `rax` whenever its hook
/// returns non-`None`; only `CFDictionarySetValue` leaves it untouched).
fn hook(uc: &mut Unicorn<EmuState>, name: &str, a: &[u64; 6]) -> Option<u64> {
    let v = match name {
        "_malloc" => match uc.get_data_mut().malloc(a[0]) {
            Some(p) => p,
            None => {
                anomaly!(uc, "malloc({:#x}): emulated heap exhausted; returning NULL", a[0]);
                0
            }
        },
        // void *__memset_chk(void *dest, int c, size_t len, size_t destlen)
        "___memset_chk" => {
            if a[2] > HOOK_IO_MAX {
                anomaly!(uc, "__memset_chk: length {:#x} too large", a[2]);
            } else {
                let fill = vec![a[1] as u8; a[2] as usize];
                write_guest(uc, a[0], &fill, "__memset_chk");
            }
            a[0] // returns dest (pypush returns 0; the binary ignores it)
        }
        // void *memcpy(void *dest, const void *src, size_t n)
        "_memcpy" => {
            match read_guest(uc, a[1], a[2]) {
                Some(src) => write_guest(uc, a[0], &src, "memcpy"),
                None => anomaly!(uc, "memcpy: cannot read {:#x} bytes at {:#x}", a[2], a[1]),
            }
            a[0] // returns dest (pypush returns 0; the binary ignores it)
        }
        // void bzero(void *s, size_t n)
        "___bzero" => {
            if a[1] > HOOK_IO_MAX {
                anomaly!(uc, "bzero: length {:#x} too large", a[1]);
            } else {
                write_guest(uc, a[0], &vec![0u8; a[1] as usize], "bzero");
            }
            0
        }
        // Outputs are not checked by the binary (pypush: same).
        "_sysctlbyname" | "_statfs$INODE64" | "_CFRelease" | "_IOObjectRelease" | "_free" => 0,
        "_IORegistryEntryFromPath" => 1,
        "_CFStringGetTypeID" => CF_STRING_TYPE_ID,
        "_CFDataGetTypeID" => CF_DATA_TYPE_ID,
        "_DASessionCreate" => 201,
        "_DADiskCreateFromBSDName" => 202,
        "_IOServiceGetMatchingService" => 92,
        // CFStringRef CFUUIDCreateString(CFAllocatorRef, CFUUIDRef uuid):
        // the "UUID" is already the string object from DADiskCopyDescription.
        "_CFUUIDCreateString" => a[1],
        // CFIndex CFStringGetMaximumSizeForEncoding(CFIndex length, enc):
        // returns `length`, as pypush does. Real CF returns up to 3 * length
        // for UTF-8, but that is NOT output-neutral: with `3 * length` the
        // validation data grows from 517 to 645 bytes (the binary sizes data
        // from this value, not just a scratch buffer). So identity strings
        // must be ASCII (Apple's are; see README); a non-ASCII one makes
        // CFStringGetCString below refuse (an anomaly) rather than overflow.
        "_CFStringGetMaximumSizeForEncoding" => a[0],
        "_arc4random" => uc.get_data_mut().rng.next_u32() as u64,

        // CFTypeRef IORegistryEntryCreateCFProperty(entry, CFStringRef key, alloc, options)
        "_IORegistryEntryCreateCFProperty" => {
            let Some(key) = read_cfstr(uc, a[1]) else {
                anomaly!(uc, "IORegistryEntryCreateCFProperty: key {:#x} is not a constant CFString", a[1]);
                return Some(0);
            };
            match uc.get_data().iokit.registry.get(&key).cloned() {
                Some(v) => {
                    log::debug!("open-absinthe: IOKit {key} -> present");
                    uc.get_data_mut().push(v)
                }
                None => {
                    log::debug!("open-absinthe: IOKit {key} -> none");
                    0
                }
            }
        }
        "_CFGetTypeID" => match uc.get_data().get(a[0]) {
            Some(CfObj::Data(_)) => CF_DATA_TYPE_ID,
            Some(CfObj::Str(_)) => CF_STRING_TYPE_ID,
            other => {
                let what = format!("{other:?}");
                anomaly!(uc, "CFGetTypeID on {what}");
                0
            }
        },
        "_CFDataGetLength" => match uc.get_data().get(a[0]) {
            Some(CfObj::Data(d)) => d.len() as u64,
            other => {
                let what = format!("{other:?}");
                anomaly!(uc, "CFDataGetLength on {what}");
                0
            }
        },
        // void CFDataGetBytes(CFDataRef, CFRange{location, length}, UInt8 *buf)
        // The range arrives in two registers. pypush slices [rsi:rdx]
        // (start:end); CF semantics are [loc, loc+len). Identical for the
        // location 0 the binary always passes; we implement CF's.
        "_CFDataGetBytes" => {
            let (loc, len) = (a[1], a[2]);
            let bytes = match uc.get_data().get(a[0]) {
                Some(CfObj::Data(d)) => {
                    let end = loc.checked_add(len).filter(|&e| e <= d.len() as u64);
                    end.map(|e| d[loc as usize..e as usize].to_vec())
                }
                _ => None,
            };
            match bytes {
                Some(b) => {
                    write_guest(uc, a[3], &b, "CFDataGetBytes");
                    b.len() as u64
                }
                None => {
                    anomaly!(uc, "CFDataGetBytes: bad object {:#x} or range {loc:#x}+{len:#x}", a[0]);
                    0
                }
            }
        }
        // CFIndex CFStringGetLength: UTF-16 code units (== chars for ASCII).
        "_CFStringGetLength" => match uc.get_data().get(a[0]) {
            Some(CfObj::Str(s)) => s.encode_utf16().count() as u64,
            other => {
                let what = format!("{other:?}");
                anomaly!(uc, "CFStringGetLength on {what}");
                0
            }
        },
        // Boolean CFStringGetCString(CFStringRef, char *buf, CFIndex bufsize, enc)
        // Writes the UTF-8 bytes plus a NUL and returns true (1), refusing
        // (false) if that does not fit in bufsize. pypush writes the bytes
        // without a NUL and returns their length; the binary only tests the
        // result for non-zero and mallocs bufsize = length + 1 fresh (zeroed)
        // bytes, so the guest-visible memory is identical.
        "_CFStringGetCString" => {
            let s = match uc.get_data().get(a[0]) {
                Some(CfObj::Str(s)) => s.clone(),
                other => {
                    let what = format!("{other:?}");
                    anomaly!(uc, "CFStringGetCString on {what}");
                    return Some(0);
                }
            };
            let mut bytes = s.into_bytes();
            bytes.push(0);
            if bytes.len() as u64 > a[2] {
                anomaly!(uc, "CFStringGetCString: {} bytes do not fit in {:#x}", bytes.len(), a[2]);
                0
            } else {
                write_guest(uc, a[1], &bytes, "CFStringGetCString");
                1
            }
        }
        "_CFDictionaryCreateMutable" => uc.get_data_mut().push(CfObj::Dict(HashMap::new())),
        // const void *CFDictionaryGetValue(CFDictionaryRef, const void *key)
        "_CFDictionaryGetValue" => {
            let Some(key) = dict_key(uc, a[1]) else { return Some(0) };
            let found = match uc.get_data().get(a[0]) {
                Some(CfObj::Dict(d)) => Ok(d.get(&key).cloned()),
                other => Err(format!("{other:?}")),
            };
            match found {
                Ok(Some(v)) => uc.get_data_mut().push(v),
                Ok(None) => {
                    // pypush raises here: a healthy run never misses.
                    anomaly!(uc, "CFDictionaryGetValue: key {key:?} not found");
                    0
                }
                Err(what) => {
                    anomaly!(uc, "CFDictionaryGetValue on {what}");
                    0
                }
            }
        }
        // void CFDictionarySetValue(CFMutableDictionaryRef, key, value)
        "_CFDictionarySetValue" => {
            let key = dict_key(uc, a[1])?;
            let val = dict_value(uc, a[2]);
            match uc.get_data_mut().get_mut(a[0]) {
                Some(CfObj::Dict(d)) => {
                    d.insert(key, val);
                }
                _ => anomaly!(uc, "CFDictionarySetValue on non-dictionary {:#x}", a[0]),
            }
            return None; // void: leave rax alone, as pypush does
        }
        // CFMutableDictionaryRef IOServiceMatching(const char *name)
        // Like pypush, first creates the CFString object for the name, then
        // the dictionary, so object handles are numbered identically.
        "_IOServiceMatching" => {
            let name = read_cstr(uc, a[0]).unwrap_or_else(|| {
                anomaly!(uc, "IOServiceMatching: unreadable name at {:#x}", a[0]);
                String::new()
            });
            log::debug!("open-absinthe: IOServiceMatching {name:?}");
            let st = uc.get_data_mut();
            st.push(CfObj::Str(name.clone()));
            st.push(CfObj::Dict(HashMap::from([("IOProviderClass".to_owned(), CfObj::Str(name))])))
        }
        "_DADiskCopyDescription" => {
            let st = uc.get_data_mut();
            let uuid = st.iokit.root_disk_uuid.clone();
            st.push(CfObj::Dict(HashMap::from([(DA_VOLUME_UUID_KEY.to_owned(), CfObj::Str(uuid))])))
        }
        // kern_return_t IOServiceGetMatchingServices(port, matching, io_iterator_t *existing)
        // io_iterator_t is a 32-bit port name: write all four bytes (pypush
        // writes one, leaving stale stack bytes in the handle; the handle is
        // only passed back to IOIteratorNext/IOObjectRelease, which ignore it).
        "_IOServiceGetMatchingServices" => {
            uc.get_data_mut().eth_iterator = true;
            write_guest(uc, a[2], &93u32.to_le_bytes(), "IOServiceGetMatchingServices");
            0
        }
        "_IOIteratorNext" => {
            let st = uc.get_data_mut();
            if std::mem::take(&mut st.eth_iterator) { 94 } else { 0 }
        }
        // kern_return_t IORegistryEntryGetParentEntry(entry, plane, io_registry_entry_t *parent)
        // 32-bit out-parameter, see IOServiceGetMatchingServices.
        "_IORegistryEntryGetParentEntry" => {
            let parent = (a[0] as u32).wrapping_add(100);
            write_guest(uc, a[2], &parent.to_le_bytes(), "IORegistryEntryGetParentEntry");
            0
        }
        // Data symbols: bound for an address to read, never called.
        other => {
            anomaly!(uc, "data symbol {other} was called");
            return None;
        }
    };
    Some(v)
}

/// A mapped, bound emulator ready to run the NAC entry points.
pub struct Emulator {
    uc: Unicorn<'static, EmuState>,
}

impl Emulator {
    /// Map the x86-64 `slice` and bind its imports to our hooks.
    pub fn new(slice: &[u8], iokit: IoKitData) -> Result<Emulator, AbsintheError> {
        let info = macho::parse(slice)?;
        let image_size = (slice.len() as u64).div_ceil(PAGE_SIZE) * PAGE_SIZE;
        if image_size > STACK_BASE {
            log::error!("open-absinthe: x86-64 slice ({image_size:#x} bytes) overlaps the emulated stack");
            return Err(AbsintheError(E_BAD_MACHO));
        }

        let state = EmuState {
            objects: Vec::new(),
            heap_used: 0,
            eth_iterator: false,
            iokit,
            image_end: image_size,
            anomalies: 0,
            rng: StdRng::from_entropy(),
        };
        let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_64, state).map_err(|e| uce("init", e))?;
        let ret_page = vec![0xC3u8; PAGE_SIZE as usize];
        let setup = |e| uce("memory setup", e);

        uc.mem_map(HOOK_BASE, HOOK_SIZE, Prot::ALL).map_err(setup)?;
        uc.mem_write(HOOK_BASE, &ret_page).map_err(setup)?;
        uc.add_code_hook(HOOK_BASE, HOOK_BASE + HOOK_SIZE - 1, dispatch).map_err(setup)?;

        uc.mem_map(0, image_size, Prot::ALL).map_err(setup)?;
        uc.mem_write(0, slice).map_err(setup)?;
        uc.mem_unmap(0, PAGE_SIZE).map_err(setup)?;

        let mut emu = Emulator { uc };
        let lazy = macho::indirect_binds(slice, &info);
        emu.apply_binds(&lazy);
        let stream = info
            .bind_off
            .checked_add(info.bind_size)
            .and_then(|end| slice.get(info.bind_off..end))
            .unwrap_or_else(|| {
                log::warn!("open-absinthe: bind opcodes lie outside the image");
                emu.uc.get_data_mut().anomalies += 1;
                &[]
            });
        let opcodes = macho::bind_opcodes(stream, &info.segment_offsets);
        emu.uc.get_data_mut().anomalies += opcodes.unsupported;
        emu.apply_binds(&opcodes.binds);

        let uc = &mut emu.uc;
        uc.mem_map(STACK_BASE, STACK_SIZE, Prot::ALL).map_err(setup)?;
        uc.reg_write(RegisterX86::RSP, STACK_BASE + STACK_SIZE).map_err(setup)?;
        uc.reg_write(RegisterX86::RBP, STACK_BASE + STACK_SIZE).map_err(setup)?;
        uc.mem_map(HEAP_BASE, HEAP_SIZE, Prot::ALL).map_err(setup)?;
        uc.mem_map(STOP_ADDRESS, PAGE_SIZE, Prot::ALL).map_err(setup)?;
        uc.mem_write(STOP_ADDRESS, &ret_page).map_err(setup)?;
        Ok(emu)
    }

    fn apply_binds(&mut self, binds: &[macho::Bind]) {
        for b in binds {
            let Some(idx) = HOOKS.iter().position(|h| *h == b.symbol) else { continue };
            let target = (HOOK_BASE + idx as u64).wrapping_add_signed(b.addend);
            if let Err(e) = self.uc.mem_write(b.location, &target.to_le_bytes()) {
                log::warn!("open-absinthe: cannot bind {} at {:#x}: {e:?}", b.symbol, b.location);
                self.uc.get_data_mut().anomalies += 1;
            }
        }
    }

    /// Number of anomalies (unexpected hook / loader events) so far.
    pub fn anomalies(&self) -> usize {
        self.uc.get_data().anomalies
    }

    /// Allocate `size` bytes on the emulated heap.
    pub fn alloc(&mut self, size: u64) -> Result<u64, AbsintheError> {
        self.uc.get_data_mut().malloc(size).ok_or_else(|| {
            log::error!("open-absinthe: emulated heap exhausted allocating {size} bytes");
            AbsintheError(E_HEAP)
        })
    }

    /// Allocate guest memory holding `data`.
    pub fn alloc_bytes(&mut self, data: &[u8]) -> Result<u64, AbsintheError> {
        let addr = self.alloc(data.len() as u64)?;
        self.uc.mem_write(addr, data).map_err(|e| uce("input write", e))?;
        Ok(addr)
    }

    pub fn read_u64(&self, addr: u64) -> Result<u64, AbsintheError> {
        let b = self.uc.mem_read_as_vec(addr, 8).map_err(|e| uce("output read", e))?;
        u64le(&b, 0).ok_or(AbsintheError(E_UNICORN))
    }

    /// Read an output buffer the binary returned (`len` capped).
    pub fn read_output(&self, addr: u64, len: u64) -> Result<Vec<u8>, AbsintheError> {
        if len > HOOK_IO_MAX {
            log::error!("open-absinthe: implausible output length {len:#x}");
            return Err(AbsintheError(E_BAD_OUTPUT));
        }
        self.uc.mem_read_as_vec(addr, len as usize).map_err(|e| {
            log::error!("open-absinthe: output buffer {addr:#x}+{len:#x} unreadable: {e:?}");
            AbsintheError(E_BAD_OUTPUT)
        })
    }

    /// Call into the binary with System V argument registers (at most six),
    /// returning `rax`.
    pub fn call(&mut self, what: &str, address: u64, args: &[u64]) -> Result<u64, AbsintheError> {
        debug_assert!(args.len() <= ARG_REGS.len());
        let uc = &mut self.uc;
        let err = |e| uce(what, e);
        let rsp = uc.reg_read(RegisterX86::RSP).map_err(err)? - 8;
        uc.reg_write(RegisterX86::RSP, rsp).map_err(err)?;
        uc.mem_write(rsp, &STOP_ADDRESS.to_le_bytes()).map_err(err)?;
        for (reg, v) in ARG_REGS.iter().zip(args) {
            uc.reg_write(*reg, *v).map_err(err)?;
        }
        if let Err(e) = uc.emu_start(address, STOP_ADDRESS, CALL_TIMEOUT_US, 0) {
            let rip = uc.reg_read(RegisterX86::RIP).unwrap_or(0);
            log::error!("open-absinthe: {what} faulted at rip={rip:#x}: {e:?}");
            return Err(AbsintheError(E_UNICORN));
        }
        // emu_start returns Ok on timeout too; only reaching the stop page
        // means the function actually returned.
        let rip = uc.reg_read(RegisterX86::RIP).map_err(err)?;
        if rip != STOP_ADDRESS {
            log::error!(
                "open-absinthe: {what} did not return within {} s (rip={rip:#x})",
                CALL_TIMEOUT_US / 1_000_000
            );
            return Err(AbsintheError(E_EMU_LIMIT));
        }
        uc.reg_read(RegisterX86::RAX).map_err(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> EmuState {
        EmuState {
            objects: Vec::new(),
            heap_used: 0,
            eth_iterator: false,
            iokit: IoKitData { registry: HashMap::new(), root_disk_uuid: String::new() },
            image_end: 0,
            anomalies: 0,
            rng: StdRng::seed_from_u64(0),
        }
    }

    #[test]
    fn malloc_is_aligned_and_exhaustion_returns_none() {
        let mut st = state();
        assert_eq!(st.malloc(1), Some(HEAP_BASE));
        assert_eq!(st.malloc(0x25), Some(HEAP_BASE + 0x10));
        assert_eq!(st.malloc(0), Some(HEAP_BASE + 0x40));
        assert_eq!(st.malloc(HEAP_SIZE), None);
        assert_eq!(st.malloc(u64::MAX), None);
        assert_eq!(st.malloc(u64::MAX - 3), None);
        assert!(st.malloc(16).is_some());
    }

    #[test]
    fn object_handles_are_one_based() {
        let mut st = state();
        assert!(st.get(0).is_none());
        assert_eq!(st.push(CfObj::Str("a".into())), 1);
        assert!(matches!(st.get(1), Some(CfObj::Str(s)) if s == "a"));
        assert!(st.get(2).is_none());
        assert!(st.get(u64::MAX).is_none());
    }

    /// Hooks against a bare emulator (no binary): out-of-range sizes and
    /// unmapped pointers are anomalies, not panics or huge allocations.
    #[test]
    fn hooks_survive_garbage_arguments() {
        let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_64, state()).unwrap();
        uc.mem_map(HEAP_BASE, HEAP_SIZE, Prot::ALL).unwrap();
        let mut run = |name: &str, args: [u64; 6]| hook(&mut uc, name, &args);
        assert_eq!(run("_memcpy", [HEAP_BASE, HEAP_BASE + 8, u64::MAX, 0, 0, 0]), Some(HEAP_BASE));
        assert_eq!(run("___memset_chk", [HEAP_BASE, 0, 1 << 40, 1 << 40, 0, 0]), Some(HEAP_BASE));
        assert_eq!(run("___bzero", [0xdead_0000, 16, 0, 0, 0, 0]), Some(0));
        assert_eq!(run("_malloc", [u64::MAX, 0, 0, 0, 0, 0]), Some(0));
        assert_eq!(run("_CFDataGetBytes", [7, 0, 4, HEAP_BASE, 0, 0]), Some(0));
        assert_eq!(run("_CFGetTypeID", [0, 0, 0, 0, 0, 0]), Some(0));
        assert_eq!(run("_CFDictionarySetValue", [99, 1, 2, 0, 0, 0]), None);
        assert_eq!(run("_kCFBooleanTrue", [0; 6]), None);
        assert_eq!(uc.get_data().anomalies, 8);

        // Well-formed calls are not anomalies.
        let mut run = |name: &str, args: [u64; 6]| hook(&mut uc, name, &args);
        let d = run("_CFDictionaryCreateMutable", [0; 6]).unwrap();
        uc.mem_write(HEAP_BASE, b"IOEthernetInterface\0").unwrap();
        let mut run = |name: &str, args: [u64; 6]| hook(&mut uc, name, &args);
        assert_eq!(run("_CFDictionarySetValue", [d, HOOK_PAGE_WORD, HOOK_PAGE_WORD, 0, 0, 0]), None);
        let v = run("_CFDictionaryGetValue", [d, HOOK_PAGE_WORD, 0, 0, 0, 0]).unwrap();
        assert!(v > d);
        let m = run("_IOServiceMatching", [HEAP_BASE, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(m, v + 2, "IOServiceMatching creates the name string, then the dict");
        // CFStringGetCString on the name: NUL-terminated, returns true.
        assert_eq!(run("_CFStringGetCString", [m - 1, HEAP_BASE + 0x100, 0x20, 0x0800_0100, 0, 0]), Some(1));
        assert_eq!(uc.get_data().anomalies, 8);
        assert_eq!(uc.mem_read_as_vec(HEAP_BASE + 0x100, 20).unwrap(), b"IOEthernetInterface\0");
        // ... and refuses a buffer without room for the NUL.
        assert_eq!(hook(&mut uc, "_CFStringGetCString", &[m - 1, HEAP_BASE + 0x200, 19, 0, 0, 0]), Some(0));
        assert_eq!(uc.get_data().anomalies, 9);
    }

    /// Anomaly logs format `CfObj` with `{:?}`; it must not leak payloads.
    #[test]
    fn cfobj_debug_hides_payload() {
        let s = format!("{:?}", CfObj::Str("C07SW06DG1J1".into()));
        assert_eq!(s, "Str(<12 chars>)");
        assert!(!s.contains("C07SW06DG1J1"));
        let d = format!("{:?}", CfObj::Data(b"\xde\xad\xbe\xefSECRETROM".to_vec()));
        assert_eq!(d, "Data(<13 bytes>)");
        assert!(!d.contains("SECRET") && !d.contains("222") && !d.contains("0xde"));
        let m = format!("{:?}", CfObj::Dict(HashMap::from([("IOPlatformUUID".to_owned(), CfObj::Str("x".into()))])));
        assert_eq!(m, "Dict(<1 keys>)");
        assert_eq!(format!("{:?}", CfObj::Raw(0xd00008)), "Raw(0xd00008)");
    }

    #[test]
    fn cstring_and_cfstring_reads_stay_in_mapped_memory() {
        let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_64, state()).unwrap();
        uc.mem_map(0x1000, 0x1000, Prot::ALL).unwrap();
        uc.get_data_mut().image_end = 0x2000;
        // A string with no NUL running to the end of the mapping.
        uc.mem_write(0x1ffc, b"abcd").unwrap();
        assert_eq!(read_cstr(&uc, 0x1ffc).as_deref(), Some("abcd"));
        uc.mem_write(0x1100, b"hi\0").unwrap();
        assert_eq!(read_cstr(&uc, 0x1100).as_deref(), Some("hi"));
        assert_eq!(read_cstr(&uc, 0x5000), None);
        // __builtin_CFString {isa, flags, str, length} -> "hi".
        let mut cf = vec![0u8; 32];
        cf[16..24].copy_from_slice(&0x1100u64.to_le_bytes());
        cf[24..32].copy_from_slice(&2u64.to_le_bytes());
        uc.mem_write(0x1200, &cf).unwrap();
        assert_eq!(read_cfstr(&uc, 0x1200).as_deref(), Some("hi"));
        assert_eq!(read_cfstr(&uc, HOOK_PAGE_WORD), None);
        assert_eq!(read_cfstr(&uc, 0x1ff0), None);
        assert_eq!(read_cfstr(&uc, 3), None);
    }
}
