//! Running a phase borrows the ruleset's rules: what a transaction allocates
//! does not grow with the number of rules it never evaluates.

mod common;

use common::allocations;
use zentinel_modsec::ModSecurity;

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

    let before = allocations();
    tx.process_request_headers().unwrap();
    let after = allocations();

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
