//! A global allocator that fails any single allocation larger than a limit,
//! like libFuzzer's `-malloc_limit_mb`.
//!
//! Without it, whether an untrusted size reaching an allocation crashes
//! depends on the machine: Linux overcommits, so `vec![0u8; n]` succeeds for
//! anything up to about the size of RAM and only touches the pages that get
//! written. With it, every allocation above the limit fails the same way
//! everywhere: it prints "memory allocation of N bytes failed" (the message
//! Rust uses for a failed allocation, which `scripts/triage.sh` groups as one
//! signature) and aborts, which the fuzzer records as a crash.
//!
//! Like libFuzzer, it aborts even when the caller could have handled the
//! failure (`try_reserve`, or `read_to_end`, which uses it). Returning null
//! instead would hand the failure to Rust's handler, which symbolizes a
//! backtrace with more allocations; refusing those deadlocks on the
//! backtrace lock. The code under test has no fallible allocations.
//!
//! A target opts in with
//!
//! ```ignore
//! #[global_allocator]
//! static ALLOC: longfellow_fuzz::alloc_limit::LimitAlloc = longfellow_fuzz::alloc_limit::LimitAlloc;
//! ```
//!
//! and calls [`init`] at the start of `main`. `LF_FUZZ_MALLOC_LIMIT_MB`
//! overrides the default of 2048 MB; 0 turns the limit off.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{Cursor, Write};
use std::sync::atomic::{AtomicUsize, Ordering};

const DEFAULT_LIMIT_MB: usize = 2048;

static LIMIT: AtomicUsize = AtomicUsize::new(DEFAULT_LIMIT_MB << 20);

pub struct LimitAlloc;

/// Aborts if `size` is over the limit. Writes the message without
/// allocating.
fn check(size: usize) {
    if size <= LIMIT.load(Ordering::Relaxed) {
        return;
    }
    let mut buf = [0u8; 80];
    let mut msg = Cursor::new(&mut buf[..]);
    let _ = write!(msg, "memory allocation of {size} bytes failed\n");
    let n = msg.position() as usize;
    let _ = std::io::stderr().write_all(&buf[..n]);
    std::process::abort();
}

// SAFETY: forwards to the system allocator; the limit only adds aborts.
unsafe impl GlobalAlloc for LimitAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        check(layout.size());
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        check(layout.size());
        System.alloc_zeroed(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        check(new_size);
        System.realloc(ptr, layout, new_size)
    }
}

/// Reads `LF_FUZZ_MALLOC_LIMIT_MB`. Call before fuzzing starts; reading the
/// environment allocates, so the allocator itself can't do it.
pub fn init() {
    let mb = std::env::var("LF_FUZZ_MALLOC_LIMIT_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_LIMIT_MB);
    let bytes = if mb == 0 { usize::MAX } else { mb.saturating_mul(1 << 20) };
    LIMIT.store(bytes, Ordering::Relaxed);
}
