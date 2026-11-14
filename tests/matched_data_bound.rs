//! What a transaction keeps to explain its matches is bounded (S8): a rule
//! matching every value of a large body does not leave a copy of the body
//! behind. The rule itself still sees every match.

use zentinel_modsec::engine::transaction::{MATCHED_DATA_PER_RULE, MATCHED_DATA_VALUE_BYTES};
use zentinel_modsec::ModSecurity;

fn run(rules: &str, uri: &str) -> zentinel_modsec::Transaction {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx
}

#[test]
fn a_rule_that_matches_many_values_keeps_the_first_and_the_latest() {
    let query: Vec<String> = (0..100).map(|i| format!("a{i}=v{i}")).collect();
    let uri = format!("/?{}", query.join("&"));
    let tx = run(
        "SecRuleEngine On\n\
         SecRule ARGS \"@rx ^v\" \"id:1,phase:1,pass,nolog,t:none,setvar:tx.seen=+1\"\n\
         SecRule ARGS:a7 \"@rx ^v\" \"id:2,phase:1,pass,nolog,t:none\"\n\
         SecRule TX:seen \"@eq 100\" \"id:3,phase:1,deny,t:none\"",
        &uri,
    );

    // Every match ran the rule's setvar: the bound is on the record only.
    assert_eq!(
        tx.intervention()
            .and_then(|i| i.rule_ids.first().cloned())
            .as_deref(),
        Some("3")
    );

    let of_rule_1: Vec<_> = tx
        .matched_data()
        .iter()
        .filter(|m| m.rule_id.as_deref() == Some("1"))
        .collect();
    assert_eq!(of_rule_1.len(), MATCHED_DATA_PER_RULE);
    assert_eq!(of_rule_1[0].variable, "ARGS:a0");
    assert_eq!(of_rule_1[MATCHED_DATA_PER_RULE - 2].variable, "ARGS:a14");
    // The last place holds the latest match, which is what a log line reads.
    assert_eq!(of_rule_1[MATCHED_DATA_PER_RULE - 1].variable, "ARGS:a99");

    // The next rule's record is its own, after the first rule's.
    let of_rule_2: Vec<_> = tx
        .matched_data()
        .iter()
        .filter(|m| m.rule_id.as_deref() == Some("2"))
        .collect();
    assert_eq!(of_rule_2.len(), 1);
    assert_eq!(of_rule_2[0].variable, "ARGS:a7");
}

#[test]
fn a_long_value_is_kept_up_to_the_bound_and_matched_var_is_whole() {
    // Two-byte characters, so that the cut has to respect a boundary.
    let long = "%C3%A9".repeat(MATCHED_DATA_VALUE_BYTES);
    let tx = run(
        "SecRuleEngine On\n\
         SecRule ARGS:a \"@rx .\" \"id:1,phase:1,pass,nolog,t:none,setvar:tx.len=%{MATCHED_VAR}\"\n\
         SecRule TX:len \"@rx .\" \"id:2,phase:1,pass,nolog,t:none,t:length,setvar:tx.n=%{MATCHED_VAR}\"",
        &format!("/?a={long}"),
    );
    let record = &tx.matched_data()[0];
    assert!(record.value.len() <= MATCHED_DATA_VALUE_BYTES);
    assert!(record.value.len() >= MATCHED_DATA_VALUE_BYTES - 1);
    assert!(record.value.chars().all(|c| c == '\u{e9}'));

    // MATCHED_VAR, which rules read, was the whole value.
    let whole = (2 * MATCHED_DATA_VALUE_BYTES).to_string();
    assert_eq!(tx.matched_data()[1].value, whole);
}

#[test]
fn a_short_value_is_kept_as_it_is() {
    let tx = run(
        "SecRuleEngine On\n\
         SecRule ARGS \"@contains evil\" \"id:1,phase:1,pass,nolog,t:none\"",
        "/?q=something-evil-here",
    );
    let record = &tx.matched_data()[0];
    assert_eq!(record.value, "something-evil-here");
    assert_eq!(record.matched_portion.as_deref(), Some("evil"));
}
