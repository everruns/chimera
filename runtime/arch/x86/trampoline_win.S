// Windows x64 trampolines that cross between Chimera and translated guest code.
//
// The Windows counterpart of `trampoline.S`. Three things differ from the
// System V version:
//
//   * Calling convention. `dispatch(ctx, host_pc)` receives `ctx` in rcx and
//     `host_pc` in rdx, and the guarded copies receive (dst, src, len) in
//     rcx/rdx/r8. rdi and rsi are callee-saved on Win64, so every routine that
//     clobbers them (all of them — the register shuffle and `rep movsb`) saves
//     and restores them.
//
//   * Context register. Windows keeps the thread's TEB in gs, so gs cannot hold
//     the ThreadState pointer the way it does on Linux. The context is reached
//     through fs: instead, and it is the guest's gs base that is virtualized —
//     the *_fs_base / fs_is_guest ThreadState slots hold the guest's gs values,
//     and the segment swap is `wrgsbase` rather than `wrfsbase`.
//
//   * Object format. COFF has no `.type`/`.size`/`@function` directives, so this
//     file omits them; only `.globl` and labels are used.
//
// All TS_* placeholders are field offsets into ThreadState, supplied by
// global_asm! via offset_of! — the same values the System V file receives.

.text

// fn dispatch(ctx: *mut ThreadState /* rcx */, host_pc: u64 /* rdx */)
.globl dispatch
dispatch:
    // Save Win64 callee-saved integer registers on Chimera's stack.
    push rbx
    push rbp
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    // Stash Chimera state in ThreadState (reached via fs).
    mov fs:[{TS_CHIMERA_RSP}], rsp
    mov fs:[{TS_HOST_PC}], rdx
    // Defer the guest segment base and FP/SIMD restore to the first block that
    // needs them (see the System V file for the rationale); clear the flags.
    mov dword ptr [rcx + {TS_FP_IN_REGS}], 0
    mov qword ptr [rcx + {TS_FS_IS_GUEST}], 0
    // Load guest GPRs from *ctx (rcx). rcx and rsp are loaded last: rcx is the
    // base register, and rsp must stay on Chimera's stack until after popfq.
    mov rax, [rcx + {TS_RAX}]
    mov rbx, [rcx + {TS_RBX}]
    mov rdx, [rcx + {TS_RDX}]
    mov rsi, [rcx + {TS_RSI}]
    mov rdi, [rcx + {TS_RDI}]
    mov rbp, [rcx + {TS_RBP}]
    mov r8,  [rcx + {TS_R8}]
    mov r9,  [rcx + {TS_R9}]
    mov r10, [rcx + {TS_R10}]
    mov r11, [rcx + {TS_R11}]
    mov r12, [rcx + {TS_R12}]
    mov r13, [rcx + {TS_R13}]
    mov r14, [rcx + {TS_R14}]
    mov r15, [rcx + {TS_R15}]
    // Restore rflags while rsp is still Chimera's stack, so the push does not
    // touch the guest's red zone.
    push qword ptr [rcx + {TS_RFLAGS}]
    popfq
    // Switch to the guest stack, then load the last two registers with moves
    // (which leave flags untouched).
    mov rsp, [rcx + {TS_RSP}]
    mov rcx, [rcx + {TS_RCX}]
    jmp qword ptr fs:[{TS_HOST_PC}]

// Continuation of every per-block exit stub (normal exit). Pre-conditions match
// the System V file: TS_RAX holds guest rax, TS_RIP the next guest PC, and the
// guest rsp still points into the guest stack.
.globl exit_block
exit_block:
    mov fs:[{TS_RBX}], rbx
    mov fs:[{TS_RCX}], rcx
    mov fs:[{TS_RDX}], rdx
    mov fs:[{TS_RSI}], rsi
    mov fs:[{TS_RDI}], rdi
    mov fs:[{TS_RBP}], rbp
    mov fs:[{TS_RSP}], rsp
    mov fs:[{TS_R8}],  r8
    mov fs:[{TS_R9}],  r9
    mov fs:[{TS_R10}], r10
    mov fs:[{TS_R11}], r11
    mov fs:[{TS_R12}], r12
    mov fs:[{TS_R13}], r13
    mov fs:[{TS_R14}], r14
    mov fs:[{TS_R15}], r15
    mov rsp, fs:[{TS_CHIMERA_RSP}]
    pushfq
    pop rax
    mov fs:[{TS_RFLAGS}], rax
    cmp dword ptr fs:[{TS_FP_IN_REGS}], 0
    je 1f
    mov eax, 0xe7
    xor edx, edx
    xsaveopt64 fs:[{TS_FPSTATE}]
1:
    cmp qword ptr fs:[{TS_FS_IS_GUEST}], 0
    je 3f
    mov rax, fs:[{TS_CHIMERA_FS}]
    wrgsbase rax
3:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    pop rbx
    ret

// Same as exit_block, but sets exit_kind = SYSCALL. rcx, r11, and rflags are
// NOT saved here: the per-block syscall exit stub has already written their
// architectural post-syscall values into TS_RCX, TS_R11, and TS_RFLAGS.
.globl exit_syscall
exit_syscall:
    mov fs:[{TS_RBX}], rbx
    mov fs:[{TS_RDX}], rdx
    mov fs:[{TS_RSI}], rsi
    mov fs:[{TS_RDI}], rdi
    mov fs:[{TS_RBP}], rbp
    mov fs:[{TS_RSP}], rsp
    mov fs:[{TS_R8}],  r8
    mov fs:[{TS_R9}],  r9
    mov fs:[{TS_R10}], r10
    mov fs:[{TS_R12}], r12
    mov fs:[{TS_R13}], r13
    mov fs:[{TS_R14}], r14
    mov fs:[{TS_R15}], r15
    cmp dword ptr fs:[{TS_FP_IN_REGS}], 0
    je 2f
    mov eax, 0xe7
    xor edx, edx
    xsaveopt64 fs:[{TS_FPSTATE}]
2:
    mov qword ptr fs:[{TS_EXIT_KIND}], {EXIT_KIND_SYSCALL}
    cmp qword ptr fs:[{TS_FS_IS_GUEST}], 0
    je 4f
    mov rax, fs:[{TS_CHIMERA_FS}]
    wrgsbase rax
4:
    mov rsp, fs:[{TS_CHIMERA_RSP}]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    pop rbx
    ret

// Same as exit_block, but sets exit_kind = TRAP. int3 clobbers no registers, so
// every guest register (including rcx, r11, and rflags) is saved as in
// exit_block.
.globl exit_trap
exit_trap:
    mov fs:[{TS_RBX}], rbx
    mov fs:[{TS_RCX}], rcx
    mov fs:[{TS_RDX}], rdx
    mov fs:[{TS_RSI}], rsi
    mov fs:[{TS_RDI}], rdi
    mov fs:[{TS_RBP}], rbp
    mov fs:[{TS_RSP}], rsp
    mov fs:[{TS_R8}],  r8
    mov fs:[{TS_R9}],  r9
    mov fs:[{TS_R10}], r10
    mov fs:[{TS_R11}], r11
    mov fs:[{TS_R12}], r12
    mov fs:[{TS_R13}], r13
    mov fs:[{TS_R14}], r14
    mov fs:[{TS_R15}], r15
    mov rsp, fs:[{TS_CHIMERA_RSP}]
    pushfq
    pop rax
    mov fs:[{TS_RFLAGS}], rax
    cmp dword ptr fs:[{TS_FP_IN_REGS}], 0
    je 5f
    mov eax, 0xe7
    xor edx, edx
    xsaveopt64 fs:[{TS_FPSTATE}]
5:
    mov qword ptr fs:[{TS_EXIT_KIND}], {EXIT_KIND_TRAP}
    cmp qword ptr fs:[{TS_FS_IS_GUEST}], 0
    je 6f
    mov rax, fs:[{TS_CHIMERA_FS}]
    wrgsbase rax
6:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    pop rbx
    ret

// fn chimera_fetch_copy(dst /* rcx */, src /* rdx */, len /* r8 */) -> usize /* rax */
//
// Win64 version of the fault-guarded decode-window fetch. rsi/rdi are callee-
// saved, so they are preserved around the `rep movsb`; the original length is
// parked in r9 so the fixup can report `len - rcx` bytes copied.
.globl chimera_fetch_copy
chimera_fetch_copy:
    push rdi
    push rsi
    mov rdi, rcx
    mov rsi, rdx
    mov rcx, r8
    mov r9, r8
    cld
.globl chimera_fetch_copy_start
chimera_fetch_copy_start:
    rep movsb
.globl chimera_fetch_fixup
chimera_fetch_fixup:
    mov rax, r9
    sub rax, rcx
    pop rsi
    pop rdi
    ret

// fn guarded_copy(dst /* rcx */, src /* rdx */, len /* r8 */) -> i64
//
// Win64 version of the guarded copy: 1 on a complete copy, 0 on a fault. The
// exception handler resumes a faulting copy at guarded_copy_fault, which still
// pops the saved rsi/rdi before returning.
.globl guarded_copy
guarded_copy:
    push rdi
    push rsi
    mov rdi, rcx
    mov rsi, rdx
    mov rcx, r8
    rep movsb
    mov eax, 1
    pop rsi
    pop rdi
    ret
.globl guarded_copy_fault
guarded_copy_fault:
    xor eax, eax
    pop rsi
    pop rdi
    ret
.globl guarded_copy_end
guarded_copy_end:
