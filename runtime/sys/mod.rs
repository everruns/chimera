//! Host-OS-specific support code. Each submodule is gated on the matching
//! `target_os`; an unsupported host yields a compile error at the use site.
//! [`vm`] is the host-neutral virtual-memory seam every backend shares.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_arch = "x86_64")]
pub mod mmap;

#[cfg(target_arch = "x86_64")]
pub mod vm;

#[cfg(target_os = "linux")]
pub use linux::exec;
