//! Guest run entry on a Windows host.
//!
//! The Linux port builds a System V process image — ELF segments, an auxv
//! stack, an in-place dynamic link — and hands control to the dispatcher. The
//! Windows equivalent maps a PE, builds the Windows entry state (a TEB and the
//! `(argc, argv)`-free thread-start frame), virtualizes `gs` for the guest, and
//! runs the same translate-execute loop with `syscall` interception routed to
//! the embedder. That loader and run loop are the next stage of the port; until
//! they land, a guest run reports itself unimplemented rather than pretending to
//! have run.

use std::{ffi::OsString, path::Path};

use crate::{Error, SystemCalls};

pub fn execv(
    _program: &Path,
    _args: &[OsString],
    _envs: Option<&[(OsString, OsString)]>,
    _handler: Box<dyn SystemCalls>,
    _code_cache_size: usize,
) -> Result<i32, Error> {
    Err(Error::Unsupported(
        "running a guest on a Windows host is not yet implemented".into(),
    ))
}
