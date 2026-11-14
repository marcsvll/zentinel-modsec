//! Counts the allocations of the calling thread, for tests that assert on
//! what the engine allocates. A test file opts in with `mod common;`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

/// Per thread, so tests running in parallel do not see each other's.
struct Counting;

// SAFETY: every call is forwarded unchanged to the system allocator; the
// counter is a thread-local `Cell` with a const initializer, which neither
// allocates nor registers a destructor.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Allocations made so far by the calling thread.
pub fn allocations() -> u64 {
    ALLOCATIONS.with(Cell::get)
}
