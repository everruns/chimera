//! PE32+ image parsing for the Windows guest loader.
//!
//! The Windows analogue of [`crate::sys::linux::elf`]: it reads a Portable
//! Executable off disk, validates that it is a 64-bit x86-64 image, and reports
//! the pieces the loader needs to map it — the preferred image base, the entry
//! RVA, the section table, and the base-relocation and import data directories.
//! Applying the base relocations ([`apply_relocations`]) is separated out and
//! operates on the already-mapped image so it can run whether the image was
//! placed at its preferred base or slid elsewhere.
//!
//! Only the fields the loader consumes are decoded; the rest of the header is
//! skipped. Parsing is host-neutral byte work with no Windows API, so it builds
//! and unit-tests on any host — the module is compiled for a Windows target and
//! for test builds everywhere.

use crate::{Error, sys::vm::Prot};

/// `MZ` — the DOS header magic every PE image still begins with.
const DOS_MAGIC: u16 = 0x5A4D;
/// `PE\0\0` — the signature `e_lfanew` points at, little-endian.
const PE_SIGNATURE: u32 = 0x0000_4550;
/// `IMAGE_FILE_MACHINE_AMD64`.
const MACHINE_AMD64: u16 = 0x8664;
/// `IMAGE_NT_OPTIONAL_HDR64_MAGIC` — the PE32+ (64-bit) optional header.
const OPT_MAGIC_PE32PLUS: u16 = 0x20B;

/// Section `Characteristics` bits the loader honors.
const SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Data-directory indices (`IMAGE_DIRECTORY_ENTRY_*`).
const DIR_IMPORT: usize = 1;
const DIR_BASERELOC: usize = 5;

/// Base-relocation entry types (`IMAGE_REL_BASED_*`). `ABSOLUTE` is block
/// padding and is skipped; `DIR64` adjusts a full 64-bit address by the load
/// delta — the only kind an x86-64 image emits.
const REL_ABSOLUTE: u16 = 0;
const REL_DIR64: u16 = 10;

/// One section of the image: its RVA and virtual size (the span it occupies in
/// the mapped image), the file region that backs it, and the protection its
/// `Characteristics` call for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub name: [u8; 8],
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub pointer_to_raw_data: u32,
    pub size_of_raw_data: u32,
    pub characteristics: u32,
}

impl Section {
    /// The host protection a guest section is mapped with. Guest code runs
    /// through the translator, never natively, so a section is never mapped
    /// host-executable: it needs only to be readable for translation, and
    /// writable when the guest may store to it. A writable section (`.data`,
    /// and the writable-and-executable pages a packer or JIT guest uses) maps
    /// read-write; everything else maps read-only. The self-modifying-code
    /// machinery arms translated pages read-only regardless, so a store to
    /// translated code still traps.
    pub fn prot(&self) -> Prot {
        if self.characteristics & SCN_MEM_WRITE != 0 {
            Prot::ReadWrite
        } else {
            Prot::Read
        }
    }
}

/// The parsed pieces of a PE32+ image the loader consumes.
#[derive(Clone, Debug)]
pub struct ParsedPe {
    /// The image's preferred load address.
    pub image_base: u64,
    /// The entry point, as an RVA from the load base.
    pub entry_rva: u32,
    /// The virtual size of the whole mapped image, headers included.
    pub size_of_image: u32,
    /// The size of the headers region at the start of the image.
    pub size_of_headers: u32,
    /// The section table.
    pub sections: Vec<Section>,
    /// The base-relocation directory `(rva, size)`, `(0, 0)` if absent.
    pub reloc_dir: (u32, u32),
    /// The import directory `(rva, size)`, `(0, 0)` if absent.
    pub import_dir: (u32, u32),
}

fn bad(msg: &str) -> Error {
    Error::BadBinary(msg.into())
}

fn read_u16(buf: &[u8], off: usize) -> Result<u16, Error> {
    buf.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| bad("truncated PE header"))
}

fn read_u32(buf: &[u8], off: usize) -> Result<u32, Error> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| bad("truncated PE header"))
}

fn read_u64(buf: &[u8], off: usize) -> Result<u64, Error> {
    buf.get(off..off + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        .ok_or_else(|| bad("truncated PE header"))
}

/// Parse a PE32+ image from its raw file bytes. Rejects anything that is not a
/// 64-bit x86-64 PE with [`Error::BadBinary`].
pub fn parse_pe(buf: &[u8]) -> Result<ParsedPe, Error> {
    if read_u16(buf, 0)? != DOS_MAGIC {
        return Err(bad("not a PE image (no MZ header)"));
    }
    // e_lfanew at offset 0x3C names the PE signature.
    let pe_off = read_u32(buf, 0x3C)? as usize;
    if read_u32(buf, pe_off)? != PE_SIGNATURE {
        return Err(bad("bad PE signature"));
    }

    // COFF file header follows the 4-byte signature.
    let coff = pe_off + 4;
    if read_u16(buf, coff)? != MACHINE_AMD64 {
        return Err(bad("not an x86-64 PE image"));
    }
    let num_sections = read_u16(buf, coff + 2)? as usize;
    let size_of_optional = read_u16(buf, coff + 16)? as usize;

    // Optional header (PE32+) follows the 20-byte COFF header.
    let opt = coff + 20;
    if read_u16(buf, opt)? != OPT_MAGIC_PE32PLUS {
        return Err(bad("not a 64-bit (PE32+) image"));
    }
    let entry_rva = read_u32(buf, opt + 16)?;
    let image_base = read_u64(buf, opt + 24)?;
    let size_of_image = read_u32(buf, opt + 56)?;
    let size_of_headers = read_u32(buf, opt + 60)?;
    let num_dirs = read_u32(buf, opt + 108)? as usize;

    let dirs = opt + 112;
    let read_dir = |index: usize| -> Result<(u32, u32), Error> {
        if index >= num_dirs {
            return Ok((0, 0));
        }
        let d = dirs + index * 8;
        Ok((read_u32(buf, d)?, read_u32(buf, d + 4)?))
    };
    let import_dir = read_dir(DIR_IMPORT)?;
    let reloc_dir = read_dir(DIR_BASERELOC)?;

    // Section headers (40 bytes each) follow the optional header.
    let sec_base = opt + size_of_optional;
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let s = sec_base + i * 40;
        let name_bytes = buf
            .get(s..s + 8)
            .ok_or_else(|| bad("truncated section table"))?;
        let mut name = [0u8; 8];
        name.copy_from_slice(name_bytes);
        sections.push(Section {
            name,
            virtual_size: read_u32(buf, s + 8)?,
            virtual_address: read_u32(buf, s + 12)?,
            size_of_raw_data: read_u32(buf, s + 16)?,
            pointer_to_raw_data: read_u32(buf, s + 20)?,
            characteristics: read_u32(buf, s + 36)?,
        });
    }

    Ok(ParsedPe {
        image_base,
        entry_rva,
        size_of_image,
        size_of_headers,
        sections,
        reloc_dir,
        import_dir,
    })
}

/// Apply the base relocations in the mapped image, adjusting every fixed-up
/// address by `delta = actual_base - image_base`. `image` is the mapped image,
/// indexed by RVA (`image[0]` is the load base); `reloc_dir` is the base-
/// relocation directory `(rva, size)` from [`ParsedPe`]. A zero delta (the
/// image landed at its preferred base) is a no-op, as is an absent directory.
///
/// The relocation stream is a sequence of blocks, each an 8-byte header
/// (`PageRVA`, `BlockSize`) followed by `(BlockSize - 8) / 2` 16-bit entries
/// whose top four bits are the type and low twelve the offset within the page.
pub fn apply_relocations(image: &mut [u8], reloc_dir: (u32, u32), delta: i64) -> Result<(), Error> {
    let (rva, size) = reloc_dir;
    if delta == 0 || size == 0 {
        return Ok(());
    }
    let mut off = rva as usize;
    let end = off
        .checked_add(size as usize)
        .ok_or_else(|| bad("relocation directory overflows"))?;
    while off + 8 <= end {
        let page_rva = read_u32(image, off)? as usize;
        let block_size = read_u32(image, off + 4)? as usize;
        if block_size < 8 || off + block_size > end {
            return Err(bad("malformed base-relocation block"));
        }
        let entries = (block_size - 8) / 2;
        for i in 0..entries {
            let entry = read_u16(image, off + 8 + i * 2)?;
            let kind = entry >> 12;
            let page_off = (entry & 0x0FFF) as usize;
            match kind {
                REL_ABSOLUTE => {}
                REL_DIR64 => {
                    let target = page_rva + page_off;
                    let old = read_u64(image, target)?;
                    let new = old.wrapping_add(delta as u64);
                    image
                        .get_mut(target..target + 8)
                        .ok_or_else(|| bad("relocation target out of range"))?
                        .copy_from_slice(&new.to_le_bytes());
                }
                _ => return Err(bad("unsupported base-relocation type")),
            }
        }
        off += block_size;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but structurally valid PE32+ image: a DOS stub, the PE
    /// signature, a COFF header, a PE32+ optional header with a base-relocation
    /// directory, and one `.reloc` section carrying a single DIR64 fixup that
    /// targets a 64-bit pointer parked at RVA 0x2000.
    fn build_pe(image_base: u64, pointer_value: u64) -> (Vec<u8>, usize) {
        let pe_off = 0x40usize;
        let opt = pe_off + 4 + 20;
        let size_of_optional = 0xF0usize; // 112 + 16*8
        let sec_base = opt + size_of_optional;
        let headers_end = sec_base + 40;

        // File image: headers, then the .reloc raw data, then the pointer slot.
        // Keep RVAs and file offsets identical for simplicity (section alignment
        // is not exercised by the parser or the relocator).
        let reloc_rva = 0x1000usize;
        let ptr_rva = 0x2000usize;
        let mut buf = vec![0u8; 0x3000];

        let put16 = |b: &mut [u8], o: usize, v: u16| b[o..o + 2].copy_from_slice(&v.to_le_bytes());
        let put32 = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        let put64 = |b: &mut [u8], o: usize, v: u64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());

        put16(&mut buf, 0, DOS_MAGIC);
        put32(&mut buf, 0x3C, pe_off as u32);
        put32(&mut buf, pe_off, PE_SIGNATURE);

        // COFF header.
        let coff = pe_off + 4;
        put16(&mut buf, coff, MACHINE_AMD64);
        put16(&mut buf, coff + 2, 1); // one section
        put16(&mut buf, coff + 16, size_of_optional as u16);

        // Optional header (PE32+).
        put16(&mut buf, opt, OPT_MAGIC_PE32PLUS);
        put32(&mut buf, opt + 16, 0x1000); // entry rva
        put64(&mut buf, opt + 24, image_base);
        put32(&mut buf, opt + 56, 0x3000); // size of image
        put32(&mut buf, opt + 60, headers_end as u32); // size of headers
        put32(&mut buf, opt + 108, 16); // number of data directories
        // Directory 5 (base relocations): rva, size.
        let dir5 = opt + 112 + DIR_BASERELOC * 8;
        put32(&mut buf, dir5, reloc_rva as u32);
        put32(&mut buf, dir5 + 4, 12); // one 8-byte header + one 4-byte body pad

        // Section header for `.reloc`.
        buf[sec_base..sec_base + 6].copy_from_slice(b".reloc");
        put32(&mut buf, sec_base + 8, 0x1000); // virtual size
        put32(&mut buf, sec_base + 12, reloc_rva as u32); // virtual address
        put32(&mut buf, sec_base + 16, 0x1000); // size of raw data
        put32(&mut buf, sec_base + 20, reloc_rva as u32); // pointer to raw data

        // Base-relocation block: page rva 0x2000, block size 12, one DIR64 entry
        // at page offset 0.
        put32(&mut buf, reloc_rva, ptr_rva as u32);
        put32(&mut buf, reloc_rva + 4, 12);
        put16(&mut buf, reloc_rva + 8, REL_DIR64 << 12);

        // The pointer the relocation fixes up.
        put64(&mut buf, ptr_rva, pointer_value);

        (buf, ptr_rva)
    }

    #[test]
    fn parses_headers_and_sections() {
        let (buf, _) = build_pe(0x1_4000_0000, 0x1_4000_2000);
        let pe = parse_pe(&buf).unwrap();
        assert_eq!(pe.image_base, 0x1_4000_0000);
        assert_eq!(pe.entry_rva, 0x1000);
        assert_eq!(pe.size_of_image, 0x3000);
        assert_eq!(pe.reloc_dir, (0x1000, 12));
        assert!(pe.size_of_headers > 0);
        assert_eq!(pe.import_dir, (0, 0));
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(&pe.sections[0].name[..6], b".reloc");
        assert_eq!(pe.sections[0].virtual_address, 0x1000);
        // A non-writable section maps read-only (guest code is translated, not
        // run natively, so it is never host-executable).
        assert_eq!(pe.sections[0].prot(), Prot::Read);
    }

    #[test]
    fn section_prot_tracks_write_bit() {
        let writable = Section {
            name: *b".data\0\0\0",
            virtual_address: 0x1000,
            virtual_size: 0x10,
            pointer_to_raw_data: 0x1000,
            size_of_raw_data: 0x10,
            characteristics: SCN_MEM_WRITE,
        };
        let readonly = Section {
            characteristics: 0,
            ..writable.clone()
        };
        assert_eq!(writable.prot(), Prot::ReadWrite);
        assert_eq!(readonly.prot(), Prot::Read);
    }

    #[test]
    fn rejects_non_pe() {
        assert!(parse_pe(&[0, 1, 2, 3]).is_err());
        let mut buf = vec![0u8; 0x200];
        buf[0..2].copy_from_slice(&DOS_MAGIC.to_le_bytes());
        // e_lfanew points past the buffer.
        buf[0x3C..0x40].copy_from_slice(&0xFFFF_u32.to_le_bytes());
        assert!(parse_pe(&buf).is_err());
    }

    #[test]
    fn applies_dir64_relocation() {
        let image_base = 0x1_4000_0000u64;
        let preferred_ptr = image_base + 0x2000;
        let (mut image, ptr_rva) = build_pe(image_base, preferred_ptr);
        let pe = parse_pe(&image).unwrap();

        // Slide the image up by 0x10_0000 and relocate.
        let actual_base = image_base + 0x10_0000;
        let delta = actual_base as i64 - image_base as i64;
        apply_relocations(&mut image, pe.reloc_dir, delta).unwrap();

        let fixed = u64::from_le_bytes(image[ptr_rva..ptr_rva + 8].try_into().unwrap());
        assert_eq!(fixed, preferred_ptr + delta as u64);
    }

    #[test]
    fn zero_delta_is_a_noop() {
        let image_base = 0x1_4000_0000u64;
        let (mut image, ptr_rva) = build_pe(image_base, image_base + 0x2000);
        let pe = parse_pe(&image).unwrap();
        let before = image[ptr_rva..ptr_rva + 8].to_vec();
        apply_relocations(&mut image, pe.reloc_dir, 0).unwrap();
        assert_eq!(&image[ptr_rva..ptr_rva + 8], &before[..]);
    }
}
