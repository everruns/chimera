//! Host-OS-specific support code. Each submodule is gated on the matching
//! `target_os`; an unsupported host yields a compile error at the use site.
//! [`vm`] is the host-neutral virtual-memory seam every backend shares.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(windows)]
pub mod windows;

#[cfg(target_arch = "x86_64")]
pub mod mmap;

// PE parsing feeds the Windows guest loader; it is host-neutral byte work, so
// it is also compiled into test builds everywhere to keep its unit tests
// running on the Linux CI host.
#[cfg(any(windows, test))]
pub mod pe;

#[cfg(target_arch = "x86_64")]
pub mod vm;

// Host-neutral seams over the per-OS backends. `exec` is the guest run entry,
// `host_syscall` the forward-to-kernel bridge the default handler uses, and
// `fault` the guarded-copy recovery installer.
#[cfg(target_os = "linux")]
pub use linux::{exec, fault, syscall::host_syscall};

#[cfg(windows)]
pub use windows::{exec, fault, syscall::host_syscall};
