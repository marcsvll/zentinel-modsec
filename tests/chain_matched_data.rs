//! What a chained rule matched on, link by link.
//!
//! ModSecurity expands a chain's `msg` and `logdata` once its last rule has
//! matched: `%{MATCHED_VAR}` and `%{MATCHED_VAR_NAME}` are then the last link's
//! match and `%{TX.0}` the latest `capture`. Many CRS chains start with a
//! condition and read the offending input in a later link (920360: "is a limit
//! configured", then "is an argument name longer"), so a record of the first
//! rule alone says which limit, not which argument. The matches of every link
//! are recorded under the chain's id, with the link's position.

use zentinel_modsec::engine::transaction::MatchedData;
use zentinel_modsec::{ModSecurity, Transaction};

fn run(rules: &str, uri: &str) -> Transaction {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx
}

fn of<'a>(tx: &'a Transaction, id: &str) -> Vec<&'a MatchedData> {
    tx.matched_data()
        .iter()
        .filter(|m| m.rule_id.as_deref() == Some(id))
        .collect()
}

/// The shape of CRS 920360: a guard, then the input.
const GUARDED: &str = "SecRuleEngine On\n\
    SecAction \"id:900,phase:1,pass,nolog,setvar:tx.arg_name_length=5\"\n\
    SecRule &TX:ARG_NAME_LENGTH \"@eq 1\" \"id:920360,phase:2,deny,status:400,chain\"\n\
    SecRule ARGS_NAMES \"@gt %{tx.arg_name_length}\" \"t:none,t:length\"\n";

#[test]
fn a_link_is_recorded_under_the_id_of_its_chain() {
    let tx = run(GUARDED, "/?ok=1&much_too_long=1");
    assert!(tx.has_intervention());
    let records = of(&tx, "920360");
    assert_eq!(records.len(), 2, "{records:?}");
    assert_eq!(records[0].link, 0);
    assert_eq!(records[0].value, "1", "the guard: one limit is configured");
    assert_eq!(records[1].link, 1);
    assert_eq!(records[1].variable, "ARGS_NAMES:much_too_long");
    assert!(
        tx.matched_data().iter().all(|m| m.rule_id.is_some()),
        "no match is left without the rule it belongs to: {:?}",
        tx.matched_data()
    );
}

#[test]
fn a_rule_on_its_own_is_link_zero() {
    let tx = run(
        "SecRuleEngine On\nSecRule ARGS \"@contains evil\" \"id:1,phase:2,pass,log\"\n",
        "/?q=evil",
    );
    let records = of(&tx, "1");
    assert_eq!(records.len(), 1);
    assert_eq!((records[0].link, records[0].captured), (0, false));
}

/// The shape of CRS 932207: the capture that `%{TX.0}` reports is a middle
/// link's, and `%{MATCHED_VAR}` the last link's.
#[test]
fn the_record_says_which_link_captured() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS:u \"@rx #.*\" \"id:932207,phase:2,deny,status:403,capture,chain\"\n\
        SecRule TX:0 \"@rx \\$[a-z]\" \"capture,chain\"\n\
        SecRule MATCHED_VAR \"@rx /\"\n";
    let tx = run(rules, "/?u=x%23a;cat$u+/etc");
    assert!(tx.has_intervention());
    let records = of(&tx, "932207");
    let links: Vec<(usize, bool)> = records.iter().map(|m| (m.link, m.captured)).collect();
    assert_eq!(links, [(0, true), (1, true), (2, false)], "{records:?}");
    let last_capture = records.iter().rev().find(|m| m.captured).unwrap();
    assert_eq!(last_capture.matched_portion.as_deref(), Some("$u"));
    assert_eq!(records.last().unwrap().value, "#a;cat$u /etc");
}

/// A chain whose later link does not match leaves its first rule's record
/// behind, as before; the rule is not among the matched rules.
#[test]
fn a_chain_that_does_not_complete_is_not_a_matched_rule() {
    let tx = run(GUARDED, "/?ok=1");
    assert!(!tx.has_intervention());
    assert!(tx.matched_rules().iter().all(|id| id != "920360"));
    assert!(of(&tx, "920360").iter().all(|m| m.link == 0));
}

/// Two chains in a row: the second one's links are not counted from the first.
#[test]
fn link_positions_start_over_with_each_chain() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS:a \"@eq 1\" \"id:1,phase:2,pass,log,chain\"\n\
        SecRule ARGS:b \"@eq 2\" \"t:none\"\n\
        SecRule ARGS:a \"@eq 1\" \"id:2,phase:2,pass,log,chain\"\n\
        SecRule ARGS:b \"@eq 2\" \"t:none,chain\"\n\
        SecRule ARGS:c \"@eq 3\" \"t:none\"\n";
    let tx = run(rules, "/?a=1&b=2&c=3");
    assert_eq!(tx.matched_rules(), ["1", "2"]);
    let links = |id| of(&tx, id).iter().map(|m| m.link).collect::<Vec<_>>();
    assert_eq!(links("1"), [0, 1]);
    assert_eq!(links("2"), [0, 1, 2]);
}
