//! The Windows NT system-call bridge — the analogue of the Linux
//! `host_syscall`, and the one place a Windows-host build would reach the NT
//! kernel to forward a guest call.
//!
//! Unlike Linux, whose syscall numbers are a stable kernel ABI, Windows NT
//! syscall numbers are an implementation detail that shifts between builds; a
//! forwarding [`crate::Passthrough`] on Windows must therefore route through the
//! NT stubs by name rather than by raw number, which is part of the guest run
//! loop still to be built. Until then this reports every forwarded call as
//! unimplemented, so a handler that relies on the default forward gets a clean
//! error rather than a wild kernel entry.

use crate::{SyscallResult, SystemCall};

/// `STATUS_NOT_IMPLEMENTED` mapped onto the errno-shaped [`SyscallResult`] the
/// embedder trait speaks. The forwarding path is not yet wired on a Windows
/// host.
pub fn host_syscall(_call: &SystemCall) -> SyscallResult {
    SyscallResult::Error(38 /* ENOSYS */)
}
