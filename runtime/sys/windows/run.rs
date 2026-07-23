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
        // Own the vectored exception handler (guarded-copy fixups and
        // self-modifying-code write traps) and publish this guest's address
        // space so the handler can reach it.
        crate::sys::fault::install();
        crate::sys::fault::set_address_space(&self.addr);

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

    /// Map a guest code buffer, a stack, and a synthetic TEB at `teb_base` (0 for
    /// none), run it, and return the exit code and the syscalls the handler saw.
    /// The stack top holds a null return address, so a top-level `ret` exits.
    fn run_with_teb(code: &[u8], teb_base: u64) -> (i32, Vec<(u64, [u64; 6])>) {
        let page = vm::page_size();
        let code_region = vm::map_anon(page, Prot::ReadWrite).unwrap();
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), code_region, code.len()) };

        let stack_len = 64 * 1024;
        let stack = vm::map_anon(stack_len, Prot::ReadWrite).unwrap();
        let rsp = stack as u64 + stack_len as u64 - 8;
        unsafe { std::ptr::write(rsp as *mut u64, 0u64) };

        let mut addr = AddressSpace::new(crate::DEFAULT_CODE_CACHE_SIZE).unwrap();
        addr.add_region(code_region as usize, page);
        addr.add_region(stack as usize, stack_len);

        let recorder = Box::new(Recorder {
            seen: Mutex::new(Vec::new()),
        });
        let seen_handle = &recorder.seen as *const Mutex<Vec<SystemCall>>;
        let mut guest = Guest::new(recorder, addr, code_region as u64, rsp, teb_base);
        let exit = guest.run().unwrap();

        let seen: Vec<(u64, [u64; 6])> = unsafe { &*seen_handle }
            .lock()
            .unwrap()
            .iter()
            .map(|c| (c.number, c.args))
            .collect();
        (exit, seen)
    }

    fn run_code(code: &[u8]) -> (i32, Vec<(u64, [u64; 6])>) {
        run_with_teb(code, 0)
    }

    #[test]
    fn runs_a_block_returns_exit_code() {
        // mov eax, 42 ; ret   (ret -> null return address -> clean exit)
        let (exit, seen) = run_code(&[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3]);
        assert_eq!(exit, 42);
        assert!(seen.is_empty());
    }

    #[test]
    fn intercepts_syscall_and_exits() {
        // mov eax, 0x1234 ; mov r10, 7 ; syscall ; mov eax, 99 ; ret
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

    #[test]
    fn loop_with_back_edge() {
        // Sum 10+9+...+1 = 55, closing the loop with a back-edge whose linked
        // form carries the safepoint poll (jrcxz on the exit flag), so this also
        // exercises that the poll preserves the guest's rcx loop counter.
        //   xor eax,eax ; mov ecx,10 ; L: add eax,ecx ; dec ecx ; jnz L ; ret
        let code = [
            0x31, 0xC0, // xor eax, eax
            0xB9, 0x0A, 0x00, 0x00, 0x00, // mov ecx, 10
            0x01, 0xC8, // add eax, ecx        (loop top @7)
            0xFF, 0xC9, // dec ecx
            0x75, 0xFA, // jnz -6 -> @7
            0xC3, // ret
        ];
        assert_eq!(run_code(&code).0, 55);
    }

    #[test]
    fn conditional_branch() {
        // mov eax,5 ; cmp eax,3 ; jg end ; mov eax,0 ; end: ret
        let code = [
            0xB8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5
            0x83, 0xF8, 0x03, // cmp eax, 3
            0x7F, 0x05, // jg +5 -> ret
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0 (skipped)
            0xC3, // ret
        ];
        assert_eq!(run_code(&code).0, 5);
    }

    #[test]
    fn memory_push_pop() {
        // push 0x2A ; pop rax ; ret   — a store then load through the guest stack
        assert_eq!(run_code(&[0x6A, 0x2A, 0x58, 0xC3]).0, 42);
    }

    #[test]
    fn fp_roundtrip_uses_xsave_prologue() {
        // mov eax,3 ; cvtsi2sd xmm0,eax ; cvtsd2si eax,xmm0 ; ret
        // Touching xmm0 makes the block open with the FP-restore prologue
        // (xrstor of fpstate through the context segment).
        let code = [
            0xB8, 0x03, 0x00, 0x00, 0x00, // mov eax, 3
            0xF2, 0x0F, 0x2A, 0xC0, // cvtsi2sd xmm0, eax
            0xF2, 0x0F, 0x2D, 0xC0, // cvtsd2si eax, xmm0
            0xC3, // ret
        ];
        assert_eq!(run_code(&code).0, 3);
    }

    #[test]
    fn indirect_call_and_return() {
        // lea rax,[rip+3] ; call rax ; ret ; func: mov eax,88 ; ret
        // Exercises the inline indirect-branch table on both the call and the two
        // returns.
        let code = [
            0x48, 0x8D, 0x05, 0x03, 0x00, 0x00, 0x00, // lea rax, [rip+3] -> func
            0xFF, 0xD0, // call rax
            0xC3, // ret  (returns to null -> exit with rax)
            0xB8, 0x58, 0x00, 0x00, 0x00, // func: mov eax, 88
            0xC3, // ret
        ];
        assert_eq!(run_code(&code).0, 88);
    }

    #[test]
    fn self_modifying_code_reexecutes() {
        // Block A stores 5 over the immediate of a `mov eax, 0` that lives in a
        // second block B, then jumps to B. The store hits the armed code page and
        // traps into the vectored handler, which drops the stale translation and
        // restores write permission; B is then translated fresh from the modified
        // bytes, so the guest sees `mov eax, 5`.
        //   mov byte [rip+3], 5 ; jmp B ; B: mov eax, 0 ; ret
        let code = [
            0xC6, 0x05, 0x03, 0x00, 0x00, 0x00, 0x05, // mov byte [rip+3], 5  (patches @10)
            0xEB, 0x00, // jmp +0 -> B (block boundary)
            0xB8, 0x00, 0x00, 0x00, 0x00, // B: mov eax, 0   (imm@10 -> 5)
            0xC3, // ret
        ];
        assert_eq!(run_code(&code).0, 5);
    }

    #[test]
    fn guest_gs_segment_is_virtualized() {
        // The guest reads gs:[0x30] (its TEB self-slot). The block prologue must
        // install the guest's gs base (wrgsbase of guest_fs_base) so the read hits
        // the synthetic TEB, and the exit trampoline must restore the runtime's gs
        // afterward — if it did not, the run loop's own Rust would fault next.
        //   mov rax, gs:[0x30] ; ret
        let teb = vm::map_anon(vm::page_size(), Prot::ReadWrite).unwrap();
        unsafe { std::ptr::write((teb as u64 + 0x30) as *mut u64, 0x77) };
        let code = [
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, // mov rax, gs:[0x30]
            0xC3, // ret
        ];
        assert_eq!(run_with_teb(&code, teb as u64).0, 0x77);
    }
}
