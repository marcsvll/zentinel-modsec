//! `capture` numbers the groups of the regex, not the groups that happened to
//! take part in the match: `TX:2` is the second group even when the first one
//! matched nothing.
//!
//! The groups that did not take part used to be dropped, so every later group
//! moved down one slot and a rule reading `%{tx.2}` got the third group.

use zentinel_modsec::engine::Transaction;
use zentinel_modsec::ModSecurity;

fn run(rules: &str, uri: &str) -> Transaction {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx
}

fn tx_var(tx: &Transaction, name: &str) -> String {
    use zentinel_modsec::variables::Collection;
    tx.tx()
        .get(name)
        .and_then(|v| v.first().map(|s| s.to_string()))
        .unwrap_or_else(|| "-".to_string())
}

const RULES: &str = "SecRuleEngine On\n\
    SecRule REQUEST_URI \"@rx /(a)?(b)?(c)$\" \"id:1,phase:1,pass,nolog,capture,\
    setvar:tx.one=%{tx.1},setvar:tx.two=%{tx.2},setvar:tx.three=%{tx.3}\"";

#[test]
fn a_group_that_did_not_take_part_keeps_its_slot() {
    let tx = run(RULES, "/bc");
    assert_eq!(tx_var(&tx, "one"), "");
    assert_eq!(tx_var(&tx, "two"), "b");
    assert_eq!(tx_var(&tx, "three"), "c");
}

#[test]
fn groups_that_all_take_part_are_unchanged() {
    let tx = run(RULES, "/abc");
    assert_eq!(tx_var(&tx, "one"), "a");
    assert_eq!(tx_var(&tx, "two"), "b");
    assert_eq!(tx_var(&tx, "three"), "c");
}
