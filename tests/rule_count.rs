//! `ctl:ruleCountById` and `ctl:ruleCountByTag` (neblina extension, ADR-0015).
//!
//! A counted rule is evaluated and reported (matched rules, matched data, the log)
//! but none of its actions run: no `setvar` (so it adds nothing to the anomaly
//! score), no disruptive action, no `ctl`, no flow control. It is how a managed
//! rule is put in "count" mode on the delegate path without editing the CRS.
//! ModSecurity has no equivalent: `SecRuleUpdateActionById` cannot remove a rule's
//! `setvar`, so this is an extension and configurations using it are not portable.

use zentinel_modsec::variables::Collection;
use zentinel_modsec::{ModSecurity, Transaction};

/// Matched rule ids without the helper rules (id 900) that carry the `ctl`.
fn matched(tx: &Transaction) -> Vec<String> {
    tx.matched_rules()
        .iter()
        .filter(|id| *id != "900")
        .cloned()
        .collect()
}

fn run(rules: &str, uri: &str) -> Transaction {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx
}

const SCORING: &str = "SecRuleEngine On\n\
    SecRule ARGS \"@contains evil\" \"id:1001,phase:2,pass,log,tag:attack-test,setvar:tx.score=+5\"\n\
    SecRule TX:SCORE \"@ge 5\" \"id:1002,phase:2,deny,status:403\"\n";

#[test]
fn without_the_ctl_the_rule_scores_and_the_request_is_blocked() {
    let tx = run(SCORING, "/?q=evil");
    assert!(
        tx.has_intervention(),
        "baseline: the scoring rule leads to a block"
    );
    assert_eq!(matched(&tx), ["1001", "1002"]);
}

#[test]
fn counted_rule_is_reported_but_does_not_score_or_block() {
    let rules =
        format!("SecAction \"id:900,phase:1,pass,nolog,ctl:ruleCountById=1001\"\n{SCORING}");
    let tx = run(&rules, "/?q=evil");
    assert!(
        !tx.has_intervention(),
        "a counted rule must not lead to a block"
    );
    assert_eq!(matched(&tx), ["1001"], "the match is still reported");
    assert!(
        tx.matched_data()
            .iter()
            .any(|m| m.rule_id.as_deref() == Some("1001")),
        "matched data is still recorded"
    );
    assert!(
        tx.tx().get("score").is_none(),
        "the counted rule's setvar did not run"
    );
}

#[test]
fn counted_rule_with_a_disruptive_action_does_not_act() {
    let rules = "SecRuleEngine On\n\
        SecAction \"id:900,phase:1,pass,nolog,ctl:ruleCountById=2000-2099\"\n\
        SecRule REQUEST_URI \"@contains /admin\" \"id:2050,phase:1,deny,status:403\"\n";
    let tx = run(rules, "/admin");
    assert!(!tx.has_intervention());
    assert_eq!(matched(&tx), ["2050"]);
}

#[test]
fn count_by_tag_covers_every_rule_with_the_tag() {
    let rules = format!(
        "SecAction \"id:900,phase:1,pass,nolog,ctl:ruleCountByTag=attack-test\"\n{SCORING}"
    );
    let tx = run(&rules, "/?q=evil");
    assert!(!tx.has_intervention());
    assert_eq!(matched(&tx), ["1001"]);
}

#[test]
fn count_is_scoped_to_the_transaction_that_set_it() {
    let rules = format!(
        "SecRule REQUEST_URI \"@beginsWith /api/\" \"id:900,phase:1,pass,nolog,ctl:ruleCountById=1001\"\n{SCORING}"
    );
    let msc = ModSecurity::from_string(&rules).unwrap();
    let mut api = msc.new_transaction();
    api.process_uri("/api/x?q=evil", "GET", "HTTP/1.1").unwrap();
    api.process_request_headers().unwrap();
    api.process_request_body().unwrap();
    assert!(!api.has_intervention(), "counted on /api/");
    let mut other = msc.new_transaction();
    other.process_uri("/web?q=evil", "GET", "HTTP/1.1").unwrap();
    other.process_request_headers().unwrap();
    other.process_request_body().unwrap();
    assert!(other.has_intervention(), "scores elsewhere");
}

#[test]
fn counted_chain_does_not_run_its_actions() {
    let rules = "SecRuleEngine On\n\
        SecAction \"id:900,phase:1,pass,nolog,ctl:ruleCountById=3000\"\n\
        SecRule ARGS:a \"@eq 1\" \"id:3000,phase:2,deny,status:403,chain,setvar:tx.c=1\"\n\
        SecRule ARGS:b \"@eq 2\" \"t:none,setvar:tx.d=1\"\n";
    let tx = run(rules, "/?a=1&b=2");
    assert!(!tx.has_intervention());
    assert_eq!(matched(&tx), ["3000"]);
    assert!(
        tx.tx().get("c").is_none() && tx.tx().get("d").is_none(),
        "no link setvar ran"
    );
}
