//! Host virtual-memory primitives, abstracted over the host OS.
//!
//! The DBT core reserves and protects three kinds of host memory it does not
//! reach through the guest's own syscalls: the translated-code cache (a large
//! reservation whose middle is opened read-write-execute), the inline
//! indirect-branch table, and the per-page write-protection Chimera arms to
//! trap self-modifying code. Each of those is one `mmap`/`mprotect` shape on
//! Linux and one `VirtualAlloc`/`VirtualProtect` shape on Windows; this module
//! is the single seam between the two, so the arch backend and the guest
//! address space stay host-neutral.
//!
//! The API is deliberately small and reservation-first, because Windows draws
//! a hard line between reserving address space and committing pages to it that
//! Linux blurs: [`reserve`] takes address space with no access, [`commit`]
//! backs a sub-range of a prior reservation with pages at a protection, and
//! [`release`] returns a whole reservation. [`map_anon`] is the one-shot
//! reserve-and-commit an ordinary anonymous mapping wants.

use crate::Error;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as backend;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as backend;

/// Page protection for a committed host mapping. The DBT core needs only these
/// three combinations; a reservation has no access until [`commit`] gives it
/// one, and anything the guest itself asks for goes through its own `mprotect`,
/// not this module.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Prot {
    /// Read only.
    Read,
    /// Read and write.
    ReadWrite,
    /// Read, write, and execute — the translated-code cache.
    ReadWriteExec,
}

/// Host page size, cached after the first query.
pub fn page_size() -> usize {
    backend::page_size()
}

/// Reserve `len` bytes of address space with no access and no committed pages,
/// at an address of the host's choosing. The reservation costs virtual address
/// space only; [`commit`] backs part of it with pages before use, and
/// [`release`] returns the whole thing. Used for the code cache's
/// guard+buffer+guard span.
pub fn reserve(len: usize) -> Result<*mut u8, Error> {
    backend::reserve(len)
}

/// Back `[addr, addr+len)` — a sub-range of a prior [`reserve`] — with pages at
/// `prot`. On Linux this is an `mprotect` over already-reserved address space;
/// on Windows a `MEM_COMMIT` `VirtualAlloc`.
pub fn commit(addr: *mut u8, len: usize, prot: Prot) -> Result<(), Error> {
    backend::commit(addr, len, prot)
}

/// Reserve and commit `len` bytes at `prot` in one call, at an address of the
/// host's choosing. The ordinary anonymous-mapping path (the indirect-branch
/// table, a guest stack).
pub fn map_anon(len: usize, prot: Prot) -> Result<*mut u8, Error> {
    backend::map_anon(len, prot)
}

/// Change the protection of already-committed pages `[addr, addr+len)`. Used to
/// arm a code page read-only for SMC detection and to restore it read-write
/// after the trap fires. Failure is reported but callers on the fault path
/// ignore it, matching the raw-`mprotect` sites this replaced.
pub fn protect(addr: *mut u8, len: usize, prot: Prot) -> Result<(), Error> {
    backend::protect(addr, len, prot)
}

/// Release a whole reservation returned by [`reserve`] or [`map_anon`]. On
/// Windows a reservation is freed as a unit (`MEM_RELEASE`), so `addr` must be
/// the base a reserve/map call returned; `len` is advisory and used only by the
/// Linux `munmap`.
pub fn release(addr: *mut u8, len: usize) {
    backend::release(addr, len)
}

/// Unmap a mapping (or a page-aligned sub-range of guest mappings) the guest
/// owns. On Linux a plain `munmap`, which may split a mapping; on Windows a
/// whole-reservation `MEM_RELEASE`.
pub fn unmap(addr: *mut u8, len: usize) {
    backend::unmap(addr, len)
}

/// Copy `buf` into guest memory at `addr`, tolerating an unmapped or read-only
/// destination the way the kernel's `copy_to_user` does: a failed or short copy
/// returns false rather than faulting the runtime. Chimera and the guest share
/// one address space, so this is a fault-guarded store, not a cross-process
/// write.
pub fn copy_to_guest(addr: u64, buf: &[u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    if addr == 0 {
        return false;
    }
    backend::copy_to_guest(addr, buf)
}

/// One-time process setup the memory layer needs (on Linux, a `pthread_atfork`
/// hook that drops a pid cache in the child). Idempotent.
pub fn init() -> Result<(), Error> {
    backend::init()
}

/// Drop any cached process identity after a raw-`clone` fork the C library's
/// fork handlers never saw. A no-op where the memory layer caches nothing.
pub fn reset_after_fork() {
    backend::reset_after_fork()
}
