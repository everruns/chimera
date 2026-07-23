//! The Windows guest run loop — the translate-execute-intercept cycle for a PE
//! guest, the counterpart of the Linux [`crate::arch::x86::dispatch`] loop.
//!
//! It is deliberately narrower than the Linux run loop: no host signals, no
//! `clone` threads, no `execve` re-entry yet. What it establishes is the core
//! that everything else builds on — bind the context segment, translate the
//! next block, enter the cache through the shared trampoline, and on a cache
//! exit either service a guest `syscall` through the embedder or resume.
//!
//! ## Segment setup
//!
//! Translated code reaches the [`ThreadState`] through the `fs` base on Windows
//! (`gs` holds the TEB and cannot be repurposed — see the translator's
//! `CTX_SEG`). The run loop therefore writes `&ThreadState` into the `fs` base
//! with `wrfsbase` before entering the cache. The runtime's own TLS lives on
//! `gs`, untouched by this, so Rust code between blocks keeps working. The
//! guest's `gs` is the virtualized segment: the run loop records the runtime's
//! `gs` base in `chimera_fs_base` so the exit trampoline can restore it after a
//! block that installed the guest's, and `guest_fs_base` holds the guest's TEB
//! base for the block prologue to load.
//!
//! ## Exit
//!
//! A guest that returns to program counter zero — a top-level `ret` whose return
//! address the loader seeded to null — is a clean exit, with the guest's `rax`
//! as the status. This mirrors the Darwin port's `pc == 0` sentinel and needs
//! no build-specific `NtTerminateProcess` number; richer NT-call interception,
//! including terminate, belongs to the embedder handler and later stages.

use std::arch::asm;

use crate::{
    Error, SystemCall, SystemCalls,
    arch::x86::{
        state::ThreadState,
        trampoline::{dispatch, exit_block, exit_syscall, exit_trap},
    },
    sys::mmap::AddressSpace,
};

const RAX: usize = 0;
const EXIT_KIND_SYSCALL: u64 = crate::arch::x86::state::EXIT_KIND_SYSCALL;
const EXIT_KIND_TRAP: u64 = crate::arch::x86::state::EXIT_KIND_TRAP;

/// A running guest: its register file, the address space it translates from, and
/// the embedder syscall handler. One guest, one host thread, for now.
pub struct Guest {
    state: Box<ThreadState>,
    addr: AddressSpace,
    handler: Box<dyn SystemCalls>,
    running: bool,
    exit_code: i32,
}

impl Guest {
    /// Create a guest with a fresh register file entering at `rip`, stack
    /// pointer `rsp`, and guest TEB base `teb_base` (the `gs` base the guest's
    /// own code reads). The caller has already mapped the guest's code and stack
    /// and, if it tracks them, added them to `addr` as regions.
    pub fn new(
        handler: Box<dyn SystemCalls>,
        addr: AddressSpace,
        rip: u64,
        rsp: u64,
        teb_base: u64,
    ) -> Self {
        Self {
            state: ThreadState::fresh(rip, rsp, teb_base),
            addr,
            handler,
            running: false,
            exit_code: 0,
        }
    }

    /// Run the guest to termination, returning its exit status.
    pub fn run(&mut self) -> Result<i32, Error> {
        // Bind the context segment to this thread's ThreadState, and record the
        // runtime's own gs (TEB) base so the exit trampoline can restore it
        // after a block that installed the guest's gs.
        let ctx = &mut *self.state as *mut ThreadState;
        unsafe { set_fs_base(ctx as u64) };
        self.state.chimera_fs_base = unsafe { read_gs_base() };
        self.running = true;

        let block_exit = exit_block as *const () as u64;
        let syscall_exit = exit_syscall as *const () as u64;
        let trap_exit = exit_trap as *const () as u64;
        self.state.ib_lookup = self.addr.code.ensure_ib_lookup(block_exit)?;

        while self.running {
            let ts: *mut ThreadState = &mut *self.state;
            let rip = unsafe { (*ts).rip };

            // The clean-exit sentinel: a top-level `ret` to a null return address.
            if rip == 0 {
                self.exit_code = unsafe { (*ts).regs[RAX] } as i32;
                break;
            }

            let host_pc = self
                .addr
                .resolve(rip, block_exit, syscall_exit, trap_exit)?;
            unsafe { (*ts).exit_kind = 0 };
            self.addr.code_deny_writes();
            unsafe { dispatch(ts, host_pc) };
            self.addr.code_allow_writes();

            match unsafe { (*ts).exit_kind } {
                EXIT_KIND_SYSCALL => self.handle_syscall(),
                EXIT_KIND_TRAP => {
                    // A guest `int3`. Guest exception delivery is not modeled
                    // yet; surface it rather than silently resuming.
                    return Err(Error::Unsupported("guest breakpoint (int3)".into()));
                }
                _ => {}
            }
        }
        Ok(self.exit_code)
    }

    /// Package the guest register file into a [`SystemCall`], run it through the
    /// embedder hooks, and write the result back. Arguments follow the NT
    /// convention the `Nt`/`Zw` stubs use at the `syscall` instruction: the
    /// number in `rax`, then `r10, rdx, r8, r9` (arguments past the fourth live
    /// on the stack and are not yet passed). `rcx` and `r11` were overwritten by
    /// the syscall's architectural side effects, which the exit stub already
    /// materialized into the register file.
    fn handle_syscall(&mut self) {
        let r = &self.state.regs;
        let mut call = SystemCall::new(r[RAX], [r[10], r[3], r[8], r[9], 0, 0]);
        self.handler.pre_syscall(&call);
        self.handler.do_syscall(&mut call);
        self.handler.post_syscall(&call);
        if call.result().is_some() {
            self.state.regs[RAX] = call.return_value() as u64;
        }
    }
}

/// Write the `fs` base (the context segment) with `wrfsbase`. Requires user-mode
/// FSGSBASE, which every Windows build Chimera targets enables.
#[inline]
unsafe fn set_fs_base(base: u64) {
    unsafe {
        asm!("wrfsbase {}", in(reg) base, options(nomem, nostack, preserves_flags));
    }
}

/// Read the current `gs` base (the runtime's TEB) with `rdgsbase`.
#[inline]
unsafe fn read_gs_base() -> u64 {
    let base: u64;
    unsafe {
        asm!("rdgsbase {}", out(reg) base, options(nomem, nostack, preserves_flags));
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        SyscallResult,
        sys::vm::{self, Prot},
    };
    use std::sync::Mutex;

    /// A handler that records every syscall it sees and answers with a fixed
    /// value, so a test can prove the guest's `syscall` reached the embedder.
    struct Recorder {
        seen: Mutex<Vec<SystemCall>>,
    }

    impl SystemCalls for Recorder {
        fn do_syscall(&self, call: &mut SystemCall) {
            self.seen
                .lock()
                .unwrap()
                .push(SystemCall::new(call.number, call.args));
            call.set_result(SyscallResult::Ok(0));
        }
    }

    /// Map a guest code buffer and a stack, run it, and return (exit_code, the
    /// syscalls the handler observed). The stack top holds a null return address,
    /// so a top-level `ret` exits.
    fn run_code(code: &[u8]) -> (i32, Vec<(u64, [u64; 6])>) {
        let page = vm::page_size();
        let code_region = vm::map_anon(page, Prot::ReadWrite).unwrap();
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), code_region, code.len()) };

        let stack_len = 64 * 1024;
        let stack = vm::map_anon(stack_len, Prot::ReadWrite).unwrap();
        // rsp points at a null return address at the top of the stack.
        let rsp = stack as u64 + stack_len as u64 - 8;
        unsafe { std::ptr::write(rsp as *mut u64, 0u64) };

        let mut addr = AddressSpace::new(crate::DEFAULT_CODE_CACHE_SIZE).unwrap();
        addr.add_region(code_region as usize, page);
        addr.add_region(stack as usize, stack_len);

        let recorder = Box::new(Recorder {
            seen: Mutex::new(Vec::new()),
        });
        let seen_handle = &recorder.seen as *const Mutex<Vec<SystemCall>>;
        let mut guest = Guest::new(recorder, addr, code_region as u64, rsp, 0);
        let exit = guest.run().unwrap();

        let seen: Vec<(u64, [u64; 6])> = unsafe { &*seen_handle }
            .lock()
            .unwrap()
            .iter()
            .map(|c| (c.number, c.args))
            .collect();
        (exit, seen)
    }

    #[test]
    fn runs_a_block_returns_exit_code() {
        // mov eax, 42 ; ret   (ret -> null return address -> clean exit)
        let code = [0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];
        let (exit, seen) = run_code(&code);
        assert_eq!(exit, 42);
        assert!(seen.is_empty());
    }

    #[test]
    fn intercepts_syscall_and_exits() {
        // mov eax, 0x1234      ; syscall number
        // mov r10, 7           ; NT arg1
        // syscall              ; -> handler
        // mov eax, 99          ; exit code
        // ret                  ; -> null -> exit
        let code = [
            0xB8, 0x34, 0x12, 0x00, 0x00, // mov eax, 0x1234
            0x49, 0xC7, 0xC2, 0x07, 0x00, 0x00, 0x00, // mov r10, 7
            0x0F, 0x05, // syscall
            0xB8, 0x63, 0x00, 0x00, 0x00, // mov eax, 99
            0xC3, // ret
        ];
        let (exit, seen) = run_code(&code);
        assert_eq!(exit, 99);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, 0x1234);
        assert_eq!(seen[0].1[0], 7);
    }
}
