//! The guest register file and cache-exit protocol shared by the translator,
//! the trampolines, and the run loop.
//!
//! [`ThreadState`] is host-OS-neutral: its byte layout is an ABI contract with
//! `trampoline.S` and the per-block exit stubs the translator emits, and that
//! contract is the same whether the host kernel is Linux or Windows. Only the
//! run loop that drives a thread through the cache ([`super::dispatch`]) is
//! host-specific, so it lives apart from this file.
//!
//! The one place the two hosts diverge is which segment register carries the
//! `ThreadState` pointer. On Linux the context is reached through `gs:` and the
//! guest's `fs` base is virtualized; on Windows `gs` is the thread's TEB and
//! cannot be repurposed, so the context is reached through `fs:` and the
//! guest's `gs` base is virtualized instead. The field offsets are identical
//! either way, so the `*_fs_base` / `fs_is_guest` slots below name the
//! virtualized-segment state generically — they hold the guest's `gs` values on
//! a Windows host.

use std::sync::atomic::{AtomicI32, AtomicU32};

/// A block exited the cache at an ordinary basic-block boundary.
pub const EXIT_KIND_BLOCK: u64 = 0;
/// A block exited on a guest `syscall`: the run loop invokes the embedder's
/// `SystemCalls` handler before re-entering.
pub const EXIT_KIND_SYSCALL: u64 = 1;
/// A guest breakpoint (`int3`) exited the cache: the run loop raises `SIGTRAP`.
pub const EXIT_KIND_TRAP: u64 = 2;

/// Size of the XSAVE area in [`ThreadState::fpstate`]. The standard (non-
/// compacted) XSAVE layout for x87+SSE+AVX+AVX-512 ends at architecturally
/// fixed offsets totaling ~2688 bytes; 4096 leaves comfortable margin. The
/// trampoline saves/restores with the `0xe7` component mask, which never
/// selects AMX, so the area size is bounded regardless of the host's XCR0.
pub const XSAVE_AREA_SIZE: usize = 4096;

/// Guest register file plus a few bookkeeping slots. The exact byte layout is
/// load-bearing: the offsets are consumed by `trampoline.S` (via `offset_of!`
/// in [`super::trampoline`]) and by the per-block exit stubs emitted by the
/// translator. The struct is 64-byte aligned, and the fields are arranged so
/// `fpstate` falls on a 64-byte boundary (offset 256) — XSAVE/XRSTOR `#GP`
/// on a misaligned save area.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct ThreadState {
    /// Guest GPRs: rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8..r15.
    pub regs: [u64; 16],
    /// Guest program counter; set on exit, read on entry.
    pub rip: u64,
    /// Guest rflags; set on exit, read on entry.
    pub rflags: u64,
    /// Chimera's stack pointer, saved on entry and restored on exit.
    pub chimera_rsp: u64,
    /// Host PC for the next entry, used by `dispatch` after it has already
    /// clobbered `rsi`.
    pub host_pc_target: u64,
    /// Why the last exit happened. Read by the run loop after every entry,
    /// reset to `BLOCK` before each entry.
    pub exit_kind: u64,
    /// Guest's virtualized-segment base (`fs` on Linux, `gs` on Windows).
    /// Loaded into the segment base on every entry, restored on every exit.
    /// Updated by `syscall` when it intercepts the guest's thread-pointer set.
    pub guest_fs_base: u64,
    /// Chimera's own base for the virtualized segment, captured on the host
    /// thread immediately before guest execution starts. Restored on every exit
    /// so the runtime's own TLS works after the guest has changed the segment.
    pub chimera_fs_base: u64,
    /// Host address of the shared inline indirect-branch lookup routine in the
    /// code cache (`CodeCache::ensure_ib_lookup`). Each translated indirect
    /// branch ends in `jmp <ctx>:[ib_lookup]`; set once per run before the loop.
    pub ib_lookup: u64,
    /// Scratch slots used only by the inline indirect-branch lookup routine,
    /// which has no free registers of its own: the guest's flags (via
    /// `lahf`/`seto`), the branch target, the borrowed rcx/rdx, and the
    /// resolved host PC. Live only for the duration of one lookup.
    pub ib_flags: u64,
    pub ib_target: u64,
    pub ib_rcx: u64,
    pub ib_rdx: u64,
    pub ib_host: u64,
    /// Asynchronous-exit flag polled by translated code at loop-closing edges.
    /// The host signal catcher sets it; the run loop recomputes it each iteration
    /// as "a deliverable signal is pending" so it self-clears. When set, a fully
    /// linked, syscall-free guest loop is dragged back to the run loop within one
    /// iteration, where a pending signal is delivered at a real block boundary.
    /// Reached from translated code as `<ctx>:[]`.
    ///
    /// `AtomicU32` because the signal catcher writes it asynchronously (from the
    /// handler, via `<ctx>:[]`) while the run loop reads and writes it; plain
    /// accesses would be a data race the compiler could miscompile (e.g. drop the
    /// clear in [`super::dispatch::Thread::refresh_exit_requested`] as a dead
    /// store). The in-memory layout is an identical 32-bit word at the same
    /// offset, so the `<ctx>:[]` poll is unaffected.
    pub exit_requested: AtomicU32,
    /// Whether the physical FP/SIMD registers currently hold this thread's
    /// guest state. `dispatch` clears it on every cache entry (the Rust code
    /// that ran since the last exit has clobbered the vector registers); the
    /// first translated block that actually touches FP restores `fpstate` and
    /// sets it (see the translator's block prologue). The exit trampolines save
    /// `fpstate` only when it is set, so a residency that never touches FP pays
    /// neither XRSTOR nor XSAVE. Read and written by both `trampoline.S` and the
    /// emitted prologue, so it sits in the context-reachable region.
    /// 32-bit so it packs against `exit_requested` and `fpstate` stays at
    /// offset 256; only 0 and 1 are ever stored.
    pub fp_in_regs: u32,
    /// Scratch slot the block prologue uses to park the guest's status flags
    /// (via `lahf`/`seto`) across its checks, for the blocks whose first
    /// instructions read flags set by a predecessor. Live only for the few
    /// instructions of one prologue.
    pub fp_flags: u64,
    /// Scratch slot the block prologue uses to park the guest's rdx across the
    /// `xrstor64` (whose `edx` mask half clobbers it). Live only for the
    /// duration of one restore.
    pub fp_scratch: u64,
    /// XSAVE area for the guest's extended FP/SIMD state (x87, SSE, AVX,
    /// AVX-512). The canonical copy whenever no translated code is running;
    /// saved and restored only around blocks that touch FP (see `fp_in_regs`).
    /// Must be 64-byte aligned; the field layout above guarantees offset 256.
    pub fpstate: [u8; XSAVE_AREA_SIZE],
    /// Whether the virtualized-segment base currently holds the guest's base
    /// (rather than Chimera's, used by Rust TLS). Mirrors `fp_in_regs` for the
    /// segment-base swap: `dispatch` clears it and leaves the segment holding
    /// Chimera's base, the first block that reads guest TLS installs
    /// `guest_fs_base` and sets it, and the exit trampolines restore Chimera's
    /// base only when it is set. A residency that never touches the segment keeps
    /// both writes off the path. Placed after `fpstate` so that field stays
    /// 64-byte aligned.
    pub fs_is_guest: u64,
    /// Address of this thread's `PendingSet` (owned by its `Signals`), read by
    /// the host signal catcher via `<ctx>:[]` so a caught signal is recorded on
    /// the thread that caught it — pending state is per-thread, and this
    /// pointer is how the async-signal-safe catcher finds the right set with
    /// no TLS. Placed after `fpstate` so every offset above is unchanged.
    pub pending_set: u64,
    /// The kernel TID of the host thread backing this guest thread. Written by
    /// the owning thread at run entry — and rewritten in a fork child, where
    /// the copied value names a thread that no longer exists — and read by
    /// siblings through the thread list as the target for the reserved interrupt
    /// signal. Atomic because those reads are cross-thread; placed after
    /// `fpstate` so every `<ctx>:[]` offset above is unchanged.
    pub tid: AtomicI32,
    /// Save slot for the register a far-RIP-relative rewrite borrows to
    /// materialize an absolute guest address (see `rewrite_far_rip_operand` in
    /// the translator). Live only across the few instructions of one rewritten
    /// guest instruction, always within a block body; placed after `fpstate`
    /// so every `<ctx>:[]` offset above is unchanged.
    pub riprel_scratch: u64,
}

// XSAVE/XRSTOR #GP unless the save area is 64-byte aligned. The struct's
// align(64) handles the allocation; this guards the field offset against a
// future reordering.
const _: () = assert!(
    core::mem::offset_of!(ThreadState, fpstate) % 64 == 0,
    "ThreadState::fpstate must be 64-byte aligned for XSAVE/XRSTOR"
);

/// x86-64 `RSP` register index in [`ThreadState::regs`]. The Linux run loop has
/// its own copy in `dispatch`; this one serves the Windows [`fresh`] builder.
///
/// [`fresh`]: ThreadState::fresh
#[cfg(windows)]
pub const RSP: usize = 7;

#[cfg(windows)]
impl ThreadState {
    /// A fresh register file for a guest entering at `rip` with stack pointer
    /// `rsp` and virtualized-segment base `seg_base` (the guest's `fs` base on
    /// Linux, `gs`/TEB base on Windows). Every other register is zero, the
    /// flags carry the reserved bit and interrupt flag a fresh thread has, and
    /// the FP save area is seeded so the first `XRSTOR` loads the ABI-default
    /// `MXCSR` (all SSE exceptions masked) rather than an all-zero word that
    /// would fault ordinary float math.
    pub fn fresh(rip: u64, rsp: u64, seg_base: u64) -> Box<Self> {
        let mut ts = Box::new(Self {
            regs: [0; 16],
            rip,
            rflags: 0x202,
            chimera_rsp: 0,
            host_pc_target: 0,
            exit_kind: 0,
            guest_fs_base: seg_base,
            chimera_fs_base: 0,
            ib_lookup: 0,
            ib_flags: 0,
            ib_target: 0,
            ib_rcx: 0,
            ib_rdx: 0,
            ib_host: 0,
            exit_requested: AtomicU32::new(0),
            fp_in_regs: 0,
            fp_flags: 0,
            fp_scratch: 0,
            fpstate: [0; XSAVE_AREA_SIZE],
            fs_is_guest: 0,
            pending_set: 0,
            tid: AtomicI32::new(0),
            riprel_scratch: 0,
        });
        ts.regs[RSP] = rsp;
        ts.fpstate[24..28].copy_from_slice(&0x0000_1f80u32.to_le_bytes());
        ts
    }
}
