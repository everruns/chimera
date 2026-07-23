//! Vectored exception handler for the fault-guarded guest copies.
//!
//! The Windows analogue of the Linux `SIGSEGV`/`SIGBUS` handler
//! ([`crate::sys::linux::fault`]), narrowed to the recoveries the shared core
//! needs. Chimera reads and writes untrusted guest memory through two guarded
//! primitives that must tolerate an unmapped or wrongly-protected address the
//! way the kernel's `copy_from_user` exception table does: a fault whose
//! instruction pointer lies inside the translator's `chimera_fetch_copy` span
//! resumes at its fixup label (reporting the readable decode-window prefix), and
//! a fault inside [`crate::arch::x86::trampoline::guarded_copy`] resumes at that
//! routine's failure tail (reporting a failed read or write). Any other access
//! violation is left for the next handler in the chain — a genuine guest fault,
//! or one in Chimera's own code.
//!
//! Self-modifying-code write recovery, which the Linux handler also does, needs
//! the running guest's shared process state and arrives with the Windows run
//! loop; until then this handler only performs the copy fixups, which need no
//! per-thread state and are recognized purely by instruction-pointer range.

use std::sync::Once;

use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, EXCEPTION_POINTERS,
};

use crate::arch::x86::trampoline::{fetch_copy_span, guarded_copy_fixup, in_guarded_copy};

/// `STATUS_ACCESS_VIOLATION` and `STATUS_IN_PAGE_ERROR` — the exception codes a
/// bad read or write raises (the second on a file-backed mapping whose backing
/// store cannot satisfy the page, the Windows counterpart of `SIGBUS`).
const STATUS_ACCESS_VIOLATION: i32 = 0xC000_0005u32 as i32;
const STATUS_IN_PAGE_ERROR: i32 = 0xC000_0006u32 as i32;

/// Vectored-handler dispositions (from `<minwinbase.h>`): resume the thread at
/// the (possibly rewritten) context, or fall through to the next handler.
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/// Install the vectored exception handler once per process. Registered first in
/// the chain so it classifies the copy-fixup faults before any other handler.
pub fn install() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| unsafe {
        AddVectoredExceptionHandler(1, Some(chimera_veh));
    });
}

unsafe extern "system" fn chimera_veh(info: *mut EXCEPTION_POINTERS) -> i32 {
    let record = unsafe { (*info).ExceptionRecord };
    let context = unsafe { (*info).ContextRecord };
    if record.is_null() || context.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let code = unsafe { (*record).ExceptionCode };
    if code != STATUS_ACCESS_VIOLATION && code != STATUS_IN_PAGE_ERROR {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let rip = unsafe { (*context).Rip } as usize;

    // A fault inside the guarded decode-window fetch resumes at the fixup label,
    // which returns the readable prefix length to the translator.
    let (fetch_start, fetch_fixup) = fetch_copy_span();
    if (fetch_start..fetch_fixup).contains(&rip) {
        unsafe { (*context).Rip = fetch_fixup as u64 };
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // A fault inside the guarded copy is a failed read or write of untrusted
    // guest memory: resume at the routine's failure tail, which reports it.
    if in_guarded_copy(rip) {
        unsafe { (*context).Rip = guarded_copy_fixup() as u64 };
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    EXCEPTION_CONTINUE_SEARCH
}
