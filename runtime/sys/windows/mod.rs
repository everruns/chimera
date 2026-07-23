//! Windows-specific glue for a Windows (PE) guest on a Windows host: the
//! vectored-exception fault handler behind the fault-guarded guest copies, the
//! NT system-call bridge, and the guest run entry.
//!
//! Much of the Linux port's userspace — the ELF loader, the auxv stack, the
//! Linux syscall driver, the VFS — has no Windows analogue and is absent here.
//! What this module needs from the shared core is the same as the Linux port's:
//! the host virtual-memory layer ([`crate::sys::vm`]), the DBT primitives in
//! [`crate::arch::x86`], and the embedder [`crate::SystemCalls`] trait. The PE
//! loader and the guest run loop that tie those together land in later stages;
//! today [`exec::execv`] reports the guest run as unimplemented.

pub mod exec;
pub mod fault;
pub mod run;
pub mod syscall;
