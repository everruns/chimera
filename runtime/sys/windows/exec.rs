//! Guest run entry on a Windows host: load a PE image and run it.
//!
//! The Windows counterpart of the Linux `execv`. It maps the guest PE
//! ([`crate::sys::pe::map_pe`]), builds the initial thread state — a stack whose
//! top holds a null return address (so a top-level `ret` is the clean-exit
//! sentinel the run loop recognizes) and a zeroed TEB the guest's `gs` is
//! virtualized onto — and drives the [`Guest`] run loop with `syscall`
//! interception routed to the embedder.
//!
//! Still missing versus the Linux path: a full Windows process-entry frame
//! (`argc`/`argv`, the PEB, environment), import resolution against the host's
//! system DLLs, and thread/exception support. A freestanding PE that reaches its
//! work through direct `syscall`s runs today; a PE that calls into `kernel32`
//! needs the import/link work of the next stage.

use std::{ffi::OsString, path::Path};

use crate::{
    Error, SystemCalls,
    sys::{
        mmap::AddressSpace,
        pe::map_pe,
        vm::{self, Prot},
    },
};

use super::run::Guest;

/// Guest stack size, matching the Linux port's 8 MiB default.
const STACK_SIZE: usize = 8 * 1024 * 1024;
/// Size of the synthetic TEB the guest's `gs` is virtualized onto.
const TEB_SIZE: usize = 4096;

pub fn execv(
    program: &Path,
    _args: &[OsString],
    _envs: Option<&[(OsString, OsString)]>,
    handler: Box<dyn SystemCalls>,
    code_cache_size: usize,
) -> Result<i32, Error> {
    let file = std::fs::read(program)
        .map_err(|e| Error::io(format!("reading {}", program.display()), e))?;
    run_image(&file, handler, code_cache_size)
}

/// Map a PE image, build the entry state, and run it to termination.
fn run_image(
    file: &[u8],
    handler: Box<dyn SystemCalls>,
    code_cache_size: usize,
) -> Result<i32, Error> {
    let image = map_pe(file)?;

    let stack = vm::map_anon(STACK_SIZE, Prot::ReadWrite)?;
    // rsp holds the exit sentinel as the top-level return address, 16-byte
    // aligned, so a `ret` with an empty call stack exits cleanly.
    let rsp = (stack as u64 + STACK_SIZE as u64 - 16) & !15;
    unsafe { std::ptr::write(rsp as *mut u64, super::run::EXIT_SENTINEL) };

    let teb = vm::map_anon(TEB_SIZE, Prot::ReadWrite)?;

    let mut addr = AddressSpace::new(code_cache_size)?;
    addr.add_region(image.base as usize, image.size);
    addr.add_region(stack as usize, STACK_SIZE);
    addr.add_region(teb as usize, TEB_SIZE);

    let mut guest = Guest::new(handler, addr, image.entry, rsp, teb as u64);
    guest.run()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal position-independent PE32+ whose `.text` is `code` and
    /// whose entry is the start of `.text`. No relocations (the code must be
    /// position-independent), no imports.
    fn pe_with_code(code: &[u8]) -> Vec<u8> {
        let pe_off = 0x40usize;
        let opt = pe_off + 4 + 20;
        let size_of_optional = 0xF0usize;
        let sec_base = opt + size_of_optional;
        let text_rva = 0x1000usize;
        let mut buf = vec![0u8; 0x2000];

        let p16 = |b: &mut [u8], o: usize, v: u16| b[o..o + 2].copy_from_slice(&v.to_le_bytes());
        let p32 = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        let p64 = |b: &mut [u8], o: usize, v: u64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());

        p16(&mut buf, 0, 0x5A4D); // MZ
        p32(&mut buf, 0x3C, pe_off as u32);
        p32(&mut buf, pe_off, 0x0000_4550); // PE\0\0
        let coff = pe_off + 4;
        p16(&mut buf, coff, 0x8664); // AMD64
        p16(&mut buf, coff + 2, 1); // one section
        p16(&mut buf, coff + 16, size_of_optional as u16);
        p16(&mut buf, opt, 0x20B); // PE32+
        p32(&mut buf, opt + 16, text_rva as u32); // entry rva
        p64(&mut buf, opt + 24, 0x1_4000_0000); // image base
        p32(&mut buf, opt + 56, 0x2000); // size of image
        p32(&mut buf, opt + 60, (sec_base + 40) as u32); // size of headers
        p32(&mut buf, opt + 108, 16); // number of data directories

        buf[sec_base..sec_base + 5].copy_from_slice(b".text");
        p32(&mut buf, sec_base + 8, 0x1000); // virtual size
        p32(&mut buf, sec_base + 12, text_rva as u32); // virtual address
        p32(&mut buf, sec_base + 16, 0x1000); // size of raw data
        p32(&mut buf, sec_base + 20, text_rva as u32); // pointer to raw data
        p32(&mut buf, sec_base + 36, 0x4000_0000); // characteristics: MEM_READ

        buf[text_rva..text_rva + code.len()].copy_from_slice(code);
        buf
    }

    struct Deny;
    impl SystemCalls for Deny {}

    #[test]
    fn loads_and_runs_a_pe() {
        // mov eax, 77 ; ret   (ret -> null return address -> clean exit)
        let pe = pe_with_code(&[0xB8, 0x4D, 0x00, 0x00, 0x00, 0xC3]);
        let code = run_image(&pe, Box::new(Deny), crate::DEFAULT_CODE_CACHE_SIZE).unwrap();
        assert_eq!(code, 77);
    }
}
