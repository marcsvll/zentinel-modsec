//! Running a phase borrows the ruleset's rules: what a transaction allocates
//! does not grow with the number of rules it never evaluates.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use zentinel_modsec::ModSecurity;

thread_local! {
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

/// Counts the allocations of the calling thread, so tests running in parallel
/// do not see each other's.
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

/// A phase-1 ruleset whose first rule jumps over `skipped` rules.
fn rules(skipped: usize) -> String {
    let mut text = String::from(
        "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,skipAfter:END\"\n",
    );
    for i in 0..skipped {
        text.push_str(&format!(
            "SecRule REQUEST_HEADERS:X-Probe \"@rx ^probe-{i}$\" \
             \"id:{},phase:1,deny,t:none,t:lowercase,msg:'probe {i}',tag:'probe'\"\n",
            1000 + i
        ));
    }
    text.push_str("SecMarker END\n");
    text
}

/// Allocations made by one transaction's request-headers phase.
fn allocations_of_a_transaction(skipped: usize) -> u64 {
    let msc = ModSecurity::from_string(&rules(skipped)).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();

    let before = ALLOCATIONS.with(Cell::get);
    tx.process_request_headers().unwrap();
    let after = ALLOCATIONS.with(Cell::get);

    assert!(tx.intervention().is_none(), "the skipped rules never ran");
    after - before
}

#[test]
fn rules_that_are_skipped_cost_no_allocation() {
    let few = allocations_of_a_transaction(10);
    let many = allocations_of_a_transaction(2000);
    assert_eq!(
        few, many,
        "a phase with 2000 skipped rules allocated {many} times, one with 10 allocated {few}"
    );
}
