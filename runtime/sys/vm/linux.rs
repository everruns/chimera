//! Linux backend for [`super`]: `mmap`/`mprotect`/`munmap` and the
//! self-targeted `process_vm_writev` behind [`copy_to_guest`].

use std::{
    io,
    sync::{
        OnceLock,
        atomic::{AtomicI32, Ordering},
    },
};

use crate::Error;

use super::Prot;

fn prot_bits(prot: Prot) -> libc::c_int {
    match prot {
        Prot::Read => libc::PROT_READ,
        Prot::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
        Prot::ReadWriteExec => libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
    }
}

pub fn page_size() -> usize {
    static PAGE_SIZE: OnceLock<usize> = OnceLock::new();

    *PAGE_SIZE.get_or_init(|| {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert!(page_size > 0, "host page size unavailable");
        page_size as usize
    })
}

pub fn reserve(len: usize) -> Result<*mut u8, Error> {
    let region = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };
    if region == libc::MAP_FAILED {
        return Err(Error::last_os_error("mmap reservation"));
    }
    Ok(region as *mut u8)
}

pub fn commit(addr: *mut u8, len: usize, prot: Prot) -> Result<(), Error> {
    // The reservation already backs this address space; opening it to `prot` is
    // an `mprotect`, and the pages fault in lazily on first touch.
    if unsafe { libc::mprotect(addr as *mut libc::c_void, len, prot_bits(prot)) } != 0 {
        return Err(Error::last_os_error("mprotect commit"));
    }
    Ok(())
}

pub fn map_anon(len: usize, prot: Prot) -> Result<*mut u8, Error> {
    let region = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            prot_bits(prot),
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if region == libc::MAP_FAILED {
        return Err(Error::last_os_error("mmap anon"));
    }
    Ok(region as *mut u8)
}

pub fn protect(addr: *mut u8, len: usize, prot: Prot) -> Result<(), Error> {
    if unsafe { libc::mprotect(addr as *mut libc::c_void, len, prot_bits(prot)) } != 0 {
        return Err(Error::last_os_error("mprotect"));
    }
    Ok(())
}

pub fn release(addr: *mut u8, len: usize) {
    let ret = unsafe { libc::munmap(addr as *mut libc::c_void, len) };
    debug_assert_eq!(ret, 0, "munmap failed");
}

pub fn unmap(addr: *mut u8, len: usize) {
    let ret = unsafe { libc::munmap(addr as *mut libc::c_void, len) };
    debug_assert_eq!(ret, 0, "munmap failed");
}

/// The runtime's pid, cached for the self-targeted `process_vm_writev` copies.
/// glibc has not cached `getpid()` since 2.25, so taking it per copy doubles
/// each copy's syscall bill. A fork invalidates the value (a stale pid would
/// aim the copies at the *parent's* address space), so Chimera registers a
/// `pthread_atfork` child hook for host forks and drops the cache from
/// [`reset_after_fork`] for the guest's raw-`clone` fork path, which never runs
/// libc's fork handlers.
static CACHED_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn reset_cached_pid_after_fork() {
    reset_after_fork();
}

fn own_pid() -> libc::pid_t {
    let pid = CACHED_PID.load(Ordering::Relaxed);
    if pid != 0 {
        return pid;
    }
    let pid = unsafe { libc::getpid() };
    CACHED_PID.store(pid, Ordering::Relaxed);
    pid
}

pub fn copy_to_guest(addr: u64, buf: &[u8]) -> bool {
    let local = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let copied = unsafe { libc::process_vm_writev(own_pid(), &local, 1, &remote, 1, 0) };
    copied == buf.len() as isize
}

pub fn init() -> Result<(), Error> {
    static INIT: OnceLock<Result<(), i32>> = OnceLock::new();

    match INIT.get_or_init(|| {
        let ret = unsafe { libc::pthread_atfork(None, None, Some(reset_cached_pid_after_fork)) };
        if ret == 0 { Ok(()) } else { Err(ret) }
    }) {
        Ok(()) => Ok(()),
        Err(err) => Err(Error::io(
            "pthread_atfork",
            io::Error::from_raw_os_error(*err),
        )),
    }
}

pub fn reset_after_fork() {
    CACHED_PID.store(0, Ordering::Relaxed);
}
