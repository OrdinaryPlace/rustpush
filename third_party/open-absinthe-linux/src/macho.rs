//! A minimal Mach-O reader: just enough to load `IMDAppleServices` flat into
//! the emulator and resolve its imported symbols.
//!
//! We parse by hand rather than through an off-the-shelf crate because the
//! import-binding step needs two fields the common readers do not surface: a
//! symbol-pointer section's `reserved1` (its index into the indirect symbol
//! table) and the dysymtab's `indirectsymoff`.
//!
//! Everything here is bounds-checked: malformed input yields an error or is
//! skipped, never a panic or an unbounded loop.

use crate::AbsintheError;
use crate::nac::E_BAD_MACHO;

fn bad(what: &str) -> AbsintheError {
    log::error!("open-absinthe: malformed IMDAppleServices: {what}");
    AbsintheError(E_BAD_MACHO)
}

pub fn u32le(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes(s.try_into().ok()?))
}

pub fn u64le(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off.checked_add(8)?)?;
    Some(u64::from_le_bytes(s.try_into().ok()?))
}

fn u32be(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_be_bytes(s.try_into().ok()?))
}

pub const FAT_MAGIC: u32 = 0xCAFE_BABE;
pub const MH_MAGIC_64: u32 = 0xFEED_FACF;
pub const CPU_TYPE_X86_64: u32 = 0x0100_0007;

/// Return the x86-64 slice of a universal (fat) binary. The fat header is
/// big-endian regardless of the slices' endianness.
pub fn x64_slice(bin: &[u8]) -> Result<&[u8], AbsintheError> {
    if u32be(bin, 0) != Some(FAT_MAGIC) {
        return Err(bad("not a fat Mach-O"));
    }
    let n = u32be(bin, 4).ok_or_else(|| bad("truncated fat header"))? as usize;
    for i in 0..n {
        let Some(a) = i.checked_mul(20).and_then(|x| x.checked_add(8)) else { break };
        let (Some(cpu), Some(off), Some(size)) = (u32be(bin, a), u32be(bin, a + 8), u32be(bin, a + 12)) else {
            break; // arch table runs past the file
        };
        if cpu == CPU_TYPE_X86_64 {
            let (off, size) = (off as usize, size as usize);
            return off
                .checked_add(size)
                .and_then(|end| bin.get(off..end))
                .ok_or_else(|| bad("x86-64 slice lies outside the file"));
        }
    }
    Err(bad("no x86-64 slice"))
}

/// A lazy / non-lazy symbol-pointer section: (file offset, byte size, `reserved1`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SymbolPointerSection {
    pub offset: u64,
    pub size: u64,
    pub reserved1: u32,
}

/// The pieces of a parsed Mach-O the loader needs.
#[derive(Default, Debug)]
pub struct MachInfo {
    /// Lazy + non-lazy symbol-pointer sections, in file order.
    pub sym_ptr_sections: Vec<SymbolPointerSection>,
    /// Segment file offsets in load order; dyld bind opcodes index into this.
    pub segment_offsets: Vec<u64>,
    pub symoff: usize,
    pub stroff: usize,
    pub indirectsymoff: usize,
    pub bind_off: usize,
    pub bind_size: usize,
}

pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_DYSYMTAB: u32 = 0xb;
pub const LC_DYLD_INFO: u32 = 0x22;
pub const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
pub const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
pub const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;

/// Parse the load commands of an (already sliced) x86-64 Mach-O.
pub fn parse(b: &[u8]) -> Result<MachInfo, AbsintheError> {
    let short = || bad("truncated load command");
    if u32le(b, 0) != Some(MH_MAGIC_64) {
        return Err(bad("x86-64 slice is not a 64-bit Mach-O"));
    }
    let ncmds = u32le(b, 16).ok_or_else(short)? as usize;
    let mut info = MachInfo::default();
    let mut off = 32usize;
    for _ in 0..ncmds {
        let cmd = u32le(b, off).ok_or_else(short)?;
        let cmdsize = u32le(b, off + 4).ok_or_else(short)? as usize;
        if cmdsize < 8 || off.checked_add(cmdsize).is_none_or(|end| end > b.len()) {
            return Err(bad("load command size out of range"));
        }
        let field32 = |rel: usize| u32le(b, off + rel).ok_or_else(short);
        match cmd {
            LC_SEGMENT_64 => {
                info.segment_offsets.push(u64le(b, off + 40).ok_or_else(short)?); // fileoff
                let nsects = field32(64)? as usize;
                for i in 0..nsects {
                    let s = off + 72 + i.saturating_mul(80);
                    if s.saturating_add(80) > off + cmdsize {
                        return Err(bad("section header outside its segment command"));
                    }
                    let size = u64le(b, s + 40).ok_or_else(short)?;
                    let offset = u32le(b, s + 48).ok_or_else(short)? as u64;
                    let flags = u32le(b, s + 64).ok_or_else(short)?;
                    let reserved1 = u32le(b, s + 68).ok_or_else(short)?;
                    let kind = flags & 0xff;
                    if kind == S_LAZY_SYMBOL_POINTERS || kind == S_NON_LAZY_SYMBOL_POINTERS {
                        info.sym_ptr_sections.push(SymbolPointerSection { offset, size, reserved1 });
                    }
                }
            }
            LC_SYMTAB => {
                info.symoff = field32(8)? as usize;
                info.stroff = field32(16)? as usize;
            }
            LC_DYSYMTAB => {
                info.indirectsymoff = field32(56)? as usize;
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                info.bind_off = field32(16)? as usize;
                info.bind_size = field32(20)? as usize;
            }
            _ => {}
        }
        off += cmdsize;
    }
    Ok(info)
}

/// Read a NUL-terminated string (bytes taken as Latin-1) starting at `start`;
/// stops at the end of `b`.
pub fn c_string(b: &[u8], start: usize) -> String {
    b.get(start..)
        .unwrap_or_default()
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as char)
        .collect()
}

/// Decode an unsigned LEB128 at `*i`, advancing it. `None` if the stream ends
/// mid-number. Bits beyond 64 are discarded (never a shift overflow).
pub fn uleb128(b: &[u8], i: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *b.get(*i)?;
        *i += 1;
        if shift < 64 {
            result |= ((byte & 0x7f) as u64) << shift;
        }
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift = shift.saturating_add(7);
    }
}

/// Decode a signed LEB128 at `*i`, advancing it.
pub fn sleb128(b: &[u8], i: &mut usize) -> Option<i64> {
    let mut result = 0i64;
    let mut shift = 0u32;
    loop {
        let byte = *b.get(*i)?;
        *i += 1;
        if shift < 64 {
            result |= ((byte & 0x7f) as i64) << shift;
        }
        shift = shift.saturating_add(7);
        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                result |= -1i64 << shift;
            }
            return Some(result);
        }
    }
}

/// One import binding: write `symbol`'s address (+ `addend`) at `location`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bind {
    pub location: u64,
    pub symbol: String,
    pub addend: i64,
}

/// Binds from the indirect symbol table for every lazy / non-lazy pointer
/// section (one 8-byte pointer per entry).
pub fn indirect_binds(b: &[u8], info: &MachInfo) -> Vec<Bind> {
    let mut out = Vec::new();
    for sec in &info.sym_ptr_sections {
        // A section can hold at most one pointer per 8 bytes of the file.
        let count = (sec.size / 8).min(b.len() as u64 / 8);
        for i in 0..count {
            let Some(ind) = (sec.reserved1 as u64)
                .checked_add(i)
                .and_then(|x| x.checked_mul(4))
                .and_then(|x| x.checked_add(info.indirectsymoff as u64))
            else {
                break;
            };
            let Some(entry) = u32le(b, ind as usize) else { break };
            // Strip INDIRECT_SYMBOL_LOCAL / _ABS flags, as pypush does.
            let sym_index = (entry & 0x3fff_ffff) as usize;
            let Some(strx) = sym_index.checked_mul(16).and_then(|o| u32le(b, info.symoff.checked_add(o)?)) else {
                continue;
            };
            let symbol = c_string(b, info.stroff.saturating_add(strx as usize));
            out.push(Bind { location: sec.offset + i * 8, symbol, addend: 0 });
        }
    }
    out
}

// dyld bind opcodes (<mach-o/loader.h>).
pub const BIND_OPCODE_DONE: u8 = 0x00;
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
pub const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
pub const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
pub const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
pub const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
pub const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
pub const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
pub const BIND_OPCODE_DO_BIND: u8 = 0x90;
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u8 = 0xA0;
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xB0;
pub const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xC0;
pub const BIND_TYPE_POINTER: u8 = 1;

/// Upper bound on binds produced from one opcode stream, so a garbage
/// `DO_BIND_ULEB_TIMES_SKIPPING_ULEB` count cannot spin for 2^64 iterations.
const MAX_BINDS: usize = 1 << 20;

/// Result of interpreting a bind-opcode stream.
#[derive(Debug, Default)]
pub struct BindStream {
    pub binds: Vec<Bind>,
    /// Opcodes / bind types we do not support (logged at `warn!`). Zero for
    /// the supported `IMDAppleServices`.
    pub unsupported: usize,
}

/// Interpret a dyld bind-opcode stream. `segments` are segment file offsets
/// (the binary is mapped flat, so file offset == address).
pub fn bind_opcodes(stream: &[u8], segments: &[u64]) -> BindStream {
    let mut out = BindStream::default();
    let mut i = 0usize;
    let mut symbol = String::new();
    let mut bind_type = BIND_TYPE_POINTER;
    let mut addend = 0i64;
    let mut seg_index = 0usize;
    let mut seg_offset = 0u64;

    let emit = |out: &mut BindStream, seg_index: usize, seg_offset: u64, symbol: &str, bind_type: u8, addend: i64| {
        if out.binds.len() >= MAX_BINDS {
            return false;
        }
        if bind_type != BIND_TYPE_POINTER {
            log::warn!("open-absinthe: unsupported bind type {bind_type} for {symbol}");
            out.unsupported += 1;
            return true;
        }
        let Some(&base) = segments.get(seg_index) else {
            log::warn!("open-absinthe: bind for {symbol} names missing segment {seg_index}");
            out.unsupported += 1;
            return true;
        };
        out.binds.push(Bind { location: base.wrapping_add(seg_offset), symbol: symbol.to_owned(), addend });
        true
    };

    while let Some(&current) = stream.get(i) {
        i += 1;
        let opcode = current & 0xF0;
        let immediate = current & 0x0F;
        // A truncated ULEB ends the stream like DONE.
        let ok = match opcode {
            BIND_OPCODE_DONE => break,
            BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => true,
            BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => uleb128(stream, &mut i).is_some(),
            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                let raw = stream.get(i..).unwrap_or_default();
                let n = raw.iter().take_while(|&&c| c != 0).count();
                symbol = raw[..n].iter().map(|&c| c as char).collect();
                i += n + 1; // name + NUL
                true
            }
            BIND_OPCODE_SET_TYPE_IMM => {
                bind_type = immediate;
                true
            }
            BIND_OPCODE_SET_ADDEND_SLEB => sleb128(stream, &mut i).map(|v| addend = v).is_some(),
            BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                seg_index = immediate as usize;
                uleb128(stream, &mut i).map(|v| seg_offset = v).is_some()
            }
            BIND_OPCODE_ADD_ADDR_ULEB => {
                uleb128(stream, &mut i).map(|v| seg_offset = seg_offset.wrapping_add(v)).is_some()
            }
            BIND_OPCODE_DO_BIND => {
                let more = emit(&mut out, seg_index, seg_offset, &symbol, bind_type, addend);
                seg_offset = seg_offset.wrapping_add(8);
                more
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                let more = emit(&mut out, seg_index, seg_offset, &symbol, bind_type, addend);
                match uleb128(stream, &mut i) {
                    Some(v) => {
                        seg_offset = seg_offset.wrapping_add(v).wrapping_add(8);
                        more
                    }
                    None => false,
                }
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                let more = emit(&mut out, seg_index, seg_offset, &symbol, bind_type, addend);
                seg_offset = seg_offset.wrapping_add(immediate as u64 * 8 + 8);
                more
            }
            BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => match (uleb128(stream, &mut i), uleb128(stream, &mut i)) {
                (Some(count), Some(skip)) => {
                    // Bounded even when `emit` does not push (unsupported bind
                    // type / missing segment), which would otherwise let a
                    // garbage count spin for up to 2^64 iterations.
                    let capped = count.min(MAX_BINDS as u64);
                    let mut more = true;
                    for _ in 0..capped {
                        more = emit(&mut out, seg_index, seg_offset, &symbol, bind_type, addend);
                        if !more {
                            break;
                        }
                        seg_offset = seg_offset.wrapping_add(skip).wrapping_add(8);
                    }
                    if more && count > capped {
                        log::warn!("open-absinthe: bind repeat count {count} exceeds {MAX_BINDS}; truncated");
                        out.unsupported += 1;
                    }
                    more
                }
                _ => false,
            },
            other => {
                // BIND_OPCODE_THREADED (0xD0) and unknown opcodes: the operand
                // layout is unknown, so the rest of the stream is unreadable.
                log::warn!("open-absinthe: unsupported bind opcode {other:#04x}");
                out.unsupported += 1;
                false
            }
        };
        if !ok {
            if out.binds.len() >= MAX_BINDS {
                log::warn!("open-absinthe: bind stream exceeds {MAX_BINDS} binds; truncated");
                out.unsupported += 1;
            }
            break;
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn uleb128_cases() {
        let cases: &[(&[u8], u64, usize)] = &[
            (&[0x00], 0, 1),
            (&[0x7f], 127, 1),
            (&[0x80, 0x01], 128, 2),
            (&[0xe5, 0x8e, 0x26], 624_485, 3),
            (&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01], u64::MAX, 10),
        ];
        for &(bytes, want, len) in cases {
            let mut i = 0;
            assert_eq!(uleb128(bytes, &mut i), Some(want), "{bytes:x?}");
            assert_eq!(i, len);
        }
        // Over-long encodings must not panic on shift overflow.
        let mut long = vec![0x80u8; 20];
        long.push(0x01);
        let mut i = 0;
        assert_eq!(uleb128(&long, &mut i), Some(0));
        assert_eq!(i, 21);
        // Truncated.
        let mut i = 0;
        assert_eq!(uleb128(&[0x80, 0x80], &mut i), None);
    }

    #[test]
    fn sleb128_cases() {
        for (bytes, want) in [(&[0x02u8][..], 2i64), (&[0x7e], -2), (&[0xff, 0x00], 127), (&[0x81, 0x7f], -127), (&[0x80, 0x7f], -128)] {
            let mut i = 0;
            assert_eq!(sleb128(bytes, &mut i), Some(want), "{bytes:x?}");
            assert_eq!(i, bytes.len());
        }
    }

    fn be(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }

    #[test]
    fn fat_slice_selection() {
        // Two archs: arm64 at 0x40 (4 bytes), x86_64 at 0x50 (4 bytes).
        let mut bin = vec![0u8; 0x60];
        bin[0..4].copy_from_slice(&be(FAT_MAGIC));
        bin[4..8].copy_from_slice(&be(2));
        let arch = |bin: &mut Vec<u8>, i: usize, cpu: u32, off: u32, size: u32| {
            let a = 8 + i * 20;
            bin[a..a + 4].copy_from_slice(&be(cpu));
            bin[a + 8..a + 12].copy_from_slice(&be(off));
            bin[a + 12..a + 16].copy_from_slice(&be(size));
        };
        arch(&mut bin, 0, 0x0100_000c, 0x40, 4);
        arch(&mut bin, 1, CPU_TYPE_X86_64, 0x50, 4);
        bin[0x50..0x54].copy_from_slice(b"X64!");
        assert_eq!(x64_slice(&bin).unwrap(), b"X64!");

        // Slice pointing past EOF.
        let mut oob = bin.clone();
        arch(&mut oob, 1, CPU_TYPE_X86_64, 0x5e, 0x10);
        assert_eq!(x64_slice(&oob), Err(AbsintheError(E_BAD_MACHO)));
        // No x86-64.
        let mut none = bin.clone();
        arch(&mut none, 1, 0x0100_000c, 0x50, 4);
        assert_eq!(x64_slice(&none), Err(AbsintheError(E_BAD_MACHO)));
        // Not fat / truncated / absurd arch count.
        assert_eq!(x64_slice(b"\xcf\xfa\xed\xfe"), Err(AbsintheError(E_BAD_MACHO)));
        assert_eq!(x64_slice(&[]), Err(AbsintheError(E_BAD_MACHO)));
        let mut many = bin.clone();
        many[4..8].copy_from_slice(&be(u32::MAX));
        assert_eq!(x64_slice(&many).unwrap(), b"X64!");
    }

    fn le32(v: &mut Vec<u8>, x: u32) {
        v.extend_from_slice(&x.to_le_bytes());
    }
    fn le64(v: &mut Vec<u8>, x: u64) {
        v.extend_from_slice(&x.to_le_bytes());
    }

    fn section(v: &mut Vec<u8>, name: &str, size: u64, offset: u32, flags: u32, reserved1: u32) {
        let mut n = [0u8; 16];
        n[..name.len()].copy_from_slice(name.as_bytes());
        v.extend_from_slice(&n); // sectname
        v.extend_from_slice(&[0u8; 16]); // segname
        le64(v, offset as u64); // addr
        le64(v, size); // size
        le32(v, offset); // offset
        le32(v, 3); // align
        le32(v, 0); // reloff
        le32(v, 0); // nreloc
        le32(v, flags);
        le32(v, reserved1);
        le32(v, 0); // reserved2
        le32(v, 0); // reserved3
    }

    /// A minimal 64-bit Mach-O: one segment with a __text section and a
    /// __la_symbol_ptr (2 pointers, reserved1 = 1) plus a __got (1 pointer,
    /// reserved1 = 0); symtab with three symbols; dysymtab; dyld_info.
    pub(crate) fn synthetic_macho() -> Vec<u8> {
        const LA_OFF: u32 = 0x400;
        const GOT_OFF: u32 = 0x410;
        const SYM_OFF: u32 = 0x500;
        const STR_OFF: u32 = 0x540;
        const IND_OFF: u32 = 0x580;
        const BIND_OFF: u32 = 0x5a0;

        let mut cmds = Vec::new();
        // LC_SEGMENT_64 with 3 sections.
        let seg_size = 72 + 3 * 80;
        le32(&mut cmds, LC_SEGMENT_64);
        le32(&mut cmds, seg_size);
        cmds.extend_from_slice(&[0u8; 16]); // segname
        le64(&mut cmds, 0); // vmaddr
        le64(&mut cmds, 0x1000); // vmsize
        le64(&mut cmds, 0); // fileoff
        le64(&mut cmds, 0x1000); // filesize
        le32(&mut cmds, 7);
        le32(&mut cmds, 7);
        le32(&mut cmds, 3); // nsects
        le32(&mut cmds, 0);
        section(&mut cmds, "__text", 0x10, 0x300, 0x8000_0400, 0);
        section(&mut cmds, "__la_symbol_ptr", 16, LA_OFF, S_LAZY_SYMBOL_POINTERS, 1);
        section(&mut cmds, "__got", 8, GOT_OFF, S_NON_LAZY_SYMBOL_POINTERS, 0);
        // LC_SYMTAB
        le32(&mut cmds, LC_SYMTAB);
        le32(&mut cmds, 24);
        le32(&mut cmds, SYM_OFF);
        le32(&mut cmds, 3);
        le32(&mut cmds, STR_OFF);
        le32(&mut cmds, 0x40);
        // LC_DYSYMTAB (80 bytes; indirectsymoff at +56)
        le32(&mut cmds, LC_DYSYMTAB);
        le32(&mut cmds, 80);
        let mut dy = vec![0u8; 72];
        dy[48..52].copy_from_slice(&IND_OFF.to_le_bytes());
        dy[52..56].copy_from_slice(&3u32.to_le_bytes());
        cmds.extend_from_slice(&dy);
        // LC_DYLD_INFO_ONLY (48 bytes; bind_off at +16, bind_size at +20)
        le32(&mut cmds, LC_DYLD_INFO_ONLY);
        le32(&mut cmds, 48);
        let mut di = vec![0u8; 40];
        di[8..12].copy_from_slice(&BIND_OFF.to_le_bytes());
        di[12..16].copy_from_slice(&4u32.to_le_bytes());
        cmds.extend_from_slice(&di);

        let mut b = Vec::new();
        le32(&mut b, MH_MAGIC_64);
        le32(&mut b, CPU_TYPE_X86_64);
        le32(&mut b, 3);
        le32(&mut b, 6); // MH_DYLIB
        le32(&mut b, 4); // ncmds
        le32(&mut b, cmds.len() as u32);
        le32(&mut b, 0);
        le32(&mut b, 0);
        b.extend_from_slice(&cmds);
        b.resize(0x1000, 0);

        // Strings: "\0_malloc\0_memcpy\0_free\0" at STR_OFF.
        let strtab = b"\0_malloc\0_memcpy\0_free\0";
        b[STR_OFF as usize..STR_OFF as usize + strtab.len()].copy_from_slice(strtab);
        // nlist_64 entries (16 bytes): n_strx = 1, 9, 17.
        for (i, strx) in [1u32, 9, 17].into_iter().enumerate() {
            let o = SYM_OFF as usize + i * 16;
            b[o..o + 4].copy_from_slice(&strx.to_le_bytes());
        }
        // Indirect table: [2 (_free), 0 (_malloc), 1|0x40000000 (_memcpy, LOCAL flag)].
        for (i, v) in [2u32, 0, 1 | 0x4000_0000].into_iter().enumerate() {
            let o = IND_OFF as usize + i * 4;
            b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        }
        b[BIND_OFF as usize..BIND_OFF as usize + 4].copy_from_slice(&[0x40, b'_', b'x', 0]);
        b
    }

    #[test]
    fn parse_synthetic_macho() {
        let b = synthetic_macho();
        let info = parse(&b).unwrap();
        assert_eq!(info.segment_offsets, vec![0]);
        assert_eq!(
            info.sym_ptr_sections,
            vec![
                SymbolPointerSection { offset: 0x400, size: 16, reserved1: 1 },
                SymbolPointerSection { offset: 0x410, size: 8, reserved1: 0 },
            ]
        );
        assert_eq!((info.symoff, info.stroff, info.indirectsymoff), (0x500, 0x540, 0x580));
        assert_eq!((info.bind_off, info.bind_size), (0x5a0, 4));

        let binds = indirect_binds(&b, &info);
        let got: Vec<(u64, &str)> = binds.iter().map(|b| (b.location, b.symbol.as_str())).collect();
        assert_eq!(got, vec![(0x400, "_malloc"), (0x408, "_memcpy"), (0x410, "_free")]);
    }

    #[test]
    fn parse_rejects_garbage_without_panicking() {
        let b = synthetic_macho();
        assert!(parse(&b[..20]).is_err());
        assert!(parse(&[0u8; 64]).is_err());
        // cmdsize running past EOF.
        let mut t = b.clone();
        t[36..40].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        assert!(parse(&t).is_err());
        // nsects larger than the command.
        let mut t = b.clone();
        t[32 + 64..32 + 68].copy_from_slice(&1000u32.to_le_bytes());
        assert!(parse(&t).is_err());
        // Absurd indirect indices are skipped, not followed.
        let mut info = parse(&b).unwrap();
        info.sym_ptr_sections[0].reserved1 = u32::MAX;
        info.sym_ptr_sections[1].size = u64::MAX;
        let _ = indirect_binds(&b, &info);
    }

    #[test]
    fn bind_opcode_interpreter() {
        let segs = [0x0u64, 0x1000, 0x2000];
        let mut s = Vec::new();
        s.push(BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1);
        s.extend_from_slice(&[BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB, 0x81, 0x01]);
        s.push(BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | 0xe);
        s.push(BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER);
        s.push(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM);
        s.extend_from_slice(b"_a\0");
        s.extend_from_slice(&[BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 1, 0x10]);
        s.push(BIND_OPCODE_DO_BIND); // 0x1010, then +8
        s.extend_from_slice(&[BIND_OPCODE_ADD_ADDR_ULEB, 0x08]); // 0x1020
        s.extend_from_slice(&[BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB, 0x10]); // 0x1020, then +0x18
        s.push(BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED | 2); // 0x1038, then +24
        s.push(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 1); // flags in immediate
        s.extend_from_slice(b"_b\0");
        s.extend_from_slice(&[BIND_OPCODE_SET_ADDEND_SLEB, 0x7e]); // -2
        s.extend_from_slice(&[BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 2, 0x00]);
        s.extend_from_slice(&[BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB, 3, 8]); // 0x2000,0x2010,0x2020
        s.push(BIND_OPCODE_DONE);
        s.push(BIND_OPCODE_DO_BIND); // after DONE: ignored

        let r = bind_opcodes(&s, &segs);
        assert_eq!(r.unsupported, 0);
        let got: Vec<(u64, &str, i64)> = r.binds.iter().map(|b| (b.location, b.symbol.as_str(), b.addend)).collect();
        assert_eq!(
            got,
            vec![
                (0x1010, "_a", 0),
                (0x1020, "_a", 0),
                (0x1038, "_a", 0),
                (0x2000, "_b", -2),
                (0x2010, "_b", -2),
                (0x2020, "_b", -2),
            ]
        );
    }

    #[test]
    fn bind_opcode_interpreter_is_bounded() {
        // Non-pointer bind type and a missing segment are reported, not bound.
        let s = [
            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM, b'_', b'x', 0,
            BIND_OPCODE_SET_TYPE_IMM | 2, BIND_OPCODE_DO_BIND,
            BIND_OPCODE_SET_TYPE_IMM | 1, BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 9, 0, BIND_OPCODE_DO_BIND,
            0xD0, // THREADED: unsupported, stops the stream
            BIND_OPCODE_DO_BIND,
        ];
        let r = bind_opcodes(&s, &[0]);
        assert!(r.binds.is_empty());
        assert_eq!(r.unsupported, 3);

        // A 2^63 repeat count is capped.
        let mut s = vec![BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM, b'_', b'x', 0, BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB];
        s.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0]);
        let r = bind_opcodes(&s, &[0]);
        assert_eq!(r.binds.len(), MAX_BINDS);
        assert_eq!(r.unsupported, 1);

        // ... also when the bind type is unsupported, so nothing is pushed:
        // the loop runs at most MAX_BINDS times and the truncation counts.
        let mut s = vec![
            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM, b'_', b'x', 0,
            BIND_OPCODE_SET_TYPE_IMM | 2, BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB,
        ];
        s.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0]);
        let r = bind_opcodes(&s, &[0]);
        assert!(r.binds.is_empty());
        assert_eq!(r.unsupported, MAX_BINDS + 1);

        // Truncated operands / unterminated symbol names end the stream quietly.
        assert!(bind_opcodes(&[BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, 0x80], &[0]).binds.is_empty());
        assert!(bind_opcodes(&[BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM, b'_'], &[0]).binds.is_empty());
    }
}
