//! Windows backend for [`super`]: `VirtualAlloc`/`VirtualProtect`/`VirtualFree`.
//!
//! Windows separates reserving address space from committing pages to it more
//! sharply than Linux does. [`reserve`] takes a `MEM_RESERVE` range with
//! `PAGE_NOACCESS`; [`commit`] backs a sub-range with `MEM_COMMIT` at the
//! requested protection, which is exactly how the code cache opens the middle
//! of its guarded reservation to read-write-execute. A reservation is freed as
//! a unit with `MEM_RELEASE`, so [`release`] and [`unmap`] pass the base with a
//! zero length.

use std::sync::OnceLock;

use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_NOACCESS,
    PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, VirtualAlloc, VirtualFree, VirtualProtect,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

use crate::Error;

use super::Prot;

fn prot_flags(prot: Prot) -> PAGE_PROTECTION_FLAGS {
    match prot {
        Prot::Read => PAGE_READONLY,
        Prot::ReadWrite => PAGE_READWRITE,
        Prot::ReadWriteExec => PAGE_EXECUTE_READWRITE,
    }
}

pub fn page_size() -> usize {
    static PAGE_SIZE: OnceLock<usize> = OnceLock::new();

    *PAGE_SIZE.get_or_init(|| {
        // SAFETY: GetSystemInfo writes a fully-initialized SYSTEM_INFO.
        let mut info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
        unsafe { GetSystemInfo(&mut info) };
        assert!(info.dwPageSize > 0, "host page size unavailable");
        info.dwPageSize as usize
    })
}

pub fn reserve(len: usize) -> Result<*mut u8, Error> {
    let region = unsafe { VirtualAlloc(std::ptr::null(), len, MEM_RESERVE, PAGE_NOACCESS) };
    if region.is_null() {
        return Err(Error::last_os_error("VirtualAlloc reserve"));
    }
    Ok(region as *mut u8)
}

pub fn commit(addr: *mut u8, len: usize, prot: Prot) -> Result<(), Error> {
    // Committing a sub-range of an existing reservation: VirtualAlloc with the
    // range's address and MEM_COMMIT leaves the surrounding reservation intact.
    let p = unsafe { VirtualAlloc(addr as *const _, len, MEM_COMMIT, prot_flags(prot)) };
    if p.is_null() {
        return Err(Error::last_os_error("VirtualAlloc commit"));
    }
    Ok(())
}

pub fn map_anon(len: usize, prot: Prot) -> Result<*mut u8, Error> {
    let region =
        unsafe { VirtualAlloc(std::ptr::null(), len, MEM_RESERVE | MEM_COMMIT, prot_flags(prot)) };
    if region.is_null() {
        return Err(Error::last_os_error("VirtualAlloc"));
    }
    Ok(region as *mut u8)
}

pub fn protect(addr: *mut u8, len: usize, prot: Prot) -> Result<(), Error> {
    let mut old: PAGE_PROTECTION_FLAGS = 0;
    let ok = unsafe { VirtualProtect(addr as *const _, len, prot_flags(prot), &mut old) };
    if ok == 0 {
        return Err(Error::last_os_error("VirtualProtect"));
    }
    Ok(())
}

pub fn release(addr: *mut u8, _len: usize) {
    // MEM_RELEASE frees the whole reservation and must pass a zero length.
    let ok = unsafe { VirtualFree(addr as *mut _, 0, MEM_RELEASE) };
    debug_assert_ne!(ok, 0, "VirtualFree release failed");
}

pub fn unmap(addr: *mut u8, _len: usize) {
    let ok = unsafe { VirtualFree(addr as *mut _, 0, MEM_RELEASE) };
    debug_assert_ne!(ok, 0, "VirtualFree failed");
}

pub fn copy_to_guest(addr: u64, buf: &[u8]) -> bool {
    // Chimera and the guest share one address space, so a store is a guarded
    // `rep movsb` — the same primitive `copy_from_guest` reads through, run in
    // the store direction. The vectored exception handler recovers a fault on
    // an unmapped or read-only destination, mirroring the Linux
    // `process_vm_writev` failure.
    unsafe {
        crate::arch::x86::trampoline::guarded_copy(addr as *mut u8, buf.as_ptr(), buf.len()) != 0
    }
}

pub fn init() -> Result<(), Error> {
    Ok(())
}

pub fn reset_after_fork() {}
