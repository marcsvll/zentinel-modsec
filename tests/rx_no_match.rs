//! `@rx` on a value that does not match allocates nothing: the room for the
//! capture groups is only reserved once there is a match to report.

mod common;

use common::allocations;
use zentinel_modsec::operators::{compile_operator, Operator};
use zentinel_modsec::parser::{OperatorName, OperatorSpec};

fn rx(pattern: &str) -> std::sync::Arc<dyn Operator> {
    compile_operator(&OperatorSpec {
        negated: false,
        name: OperatorName::Rx,
        argument: pattern.to_string(),
    })
    .expect("pattern should compile")
}

#[test]
fn a_value_that_does_not_match_costs_no_allocation() {
    let op = rx(r"(?i)(select)\s+(\w+)\s+(from)\s+(\w+)");
    // The first call builds the automaton, and the first pass over a given
    // text may still grow the matcher's state.
    assert!(!op.execute("an ordinary form field value").matched);

    let before = allocations();
    for _ in 0..100 {
        assert!(!op.execute("an ordinary form field value").matched);
    }
    assert_eq!(allocations() - before, 0);
}

#[test]
fn a_match_still_reports_its_groups() {
    let op = rx(r"(?i)(select)\s+(\w+)\s+(from)\s+(\w+)");
    let result = op.execute("x SELECT name FROM users");
    assert!(result.matched);
    assert_eq!(
        result.matched_value.as_deref(),
        Some("SELECT name FROM users")
    );
    assert_eq!(result.captures, ["SELECT", "name", "FROM", "users"]);
}
