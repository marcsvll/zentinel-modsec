//! A phase resolves a request variable once, transforms each of its values
//! once per distinct chain of transformations, and its rules share the result.
//! What must not be shared is not: each rule's own exclusions, the targets a
//! `ctl` removed, the variables rules write to while the phase runs, and what
//! a different chain makes of the same value.

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

const ARGUMENTS: usize = 50;

/// `/?a0=v0&a1=v1&...`
fn uri(arguments: usize) -> String {
    let query: Vec<String> = (0..arguments).map(|i| format!("a{i}=v{i}")).collect();
    format!("/?{}", query.join("&"))
}

/// Whether the request is denied, and by which rule.
fn denied_by(rules: &str, uri: &str) -> Option<String> {
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.intervention()
        .map(|i| i.rule_ids.first().cloned().unwrap_or_default())
}

/// Allocations of the request-headers phase with `rules` rules over ARGS, all
/// with the same `transformations`, none of which matches.
fn allocations_with(rules: usize, transformations: &str, uri: &str) -> u64 {
    let mut text = String::from("SecRuleEngine On\n");
    for i in 0..rules {
        text.push_str(&format!(
            "SecRule ARGS \"@streq never-{i}\" \"id:{},phase:1,deny,{transformations}\"\n",
            1000 + i
        ));
    }
    let msc = ModSecurity::from_string(&text).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();

    let before = ALLOCATIONS.with(Cell::get);
    tx.process_request_headers().unwrap();
    let after = ALLOCATIONS.with(Cell::get);

    assert!(tx.intervention().is_none());
    after - before
}

#[test]
fn a_second_rule_over_the_same_variable_does_not_resolve_it_again() {
    let uri = uri(ARGUMENTS);
    let per_rule =
        (allocations_with(40, "t:none", &uri) - allocations_with(20, "t:none", &uri)) / 20;
    // Resolving ARGS again would cost two allocations per argument (its name
    // and its value) on top of what testing the values costs.
    assert!(
        per_rule < 3 * ARGUMENTS as u64,
        "each further rule over ARGS allocated {per_rule} times for {ARGUMENTS} arguments"
    );
}

#[test]
fn a_second_rule_with_the_same_chain_does_not_transform_the_values_again() {
    // Upper case, so that t:lowercase has to build a new string for each.
    let uri = uri(ARGUMENTS).to_uppercase().replace("/?", "/?x=1&");
    let chain = "t:none,t:urlDecodeUni,t:lowercase";
    let per_rule = (allocations_with(40, chain, &uri) - allocations_with(20, chain, &uri)) / 20;
    // Transforming again would cost at least one allocation per argument.
    assert!(
        per_rule < ARGUMENTS as u64 / 2,
        "each further rule with the same chain allocated {per_rule} times for {ARGUMENTS} arguments"
    );
}

#[test]
fn each_chain_sees_its_own_result_for_the_same_value() {
    // The chain that changes the value runs second: it must not be answered
    // with the untouched value the first rule tested.
    let rules = "SecRuleEngine On\n\
        SecRule ARGS \"@streq attack\" \"id:1,phase:1,deny,t:none\"\n\
        SecRule ARGS \"@streq attack\" \"id:2,phase:1,deny,t:none,t:lowercase\"";
    assert_eq!(denied_by(rules, "/?a=ATTACK").as_deref(), Some("2"));
    assert_eq!(denied_by(rules, "/?a=attack").as_deref(), Some("1"));

    // And the other way around: the untouched value after the changed one.
    let rules = "SecRuleEngine On\n\
        SecRule ARGS \"@streq ATTACK\" \"id:1,phase:1,deny,t:none,t:lowercase\"\n\
        SecRule ARGS \"@streq ATTACK\" \"id:2,phase:1,deny,t:none\"";
    assert_eq!(denied_by(rules, "/?a=ATTACK").as_deref(), Some("2"));

    // The same transformations in another order are another chain.
    let rules = "SecRuleEngine On\n\
        SecRule ARGS \"@streq %41\" \"id:1,phase:1,deny,t:none,t:urlDecodeUni,t:urlEncode\"\n\
        SecRule ARGS \"@streq %41\" \"id:2,phase:1,deny,t:none,t:urlEncode,t:urlDecodeUni\"";
    assert_eq!(denied_by(rules, "/?a=%2541").as_deref(), Some("2"));

    // Two arguments with the same value in one variable, and the same value in
    // two variables: each is tested, under its own name.
    let rules = "SecRuleEngine On\n\
        SecRule ARGS_NAMES|ARGS \"@streq attack\" \"id:1,phase:1,pass,nolog,t:none,t:lowercase,setvar:tx.hits=+1\"\n\
        SecRule TX:hits \"@eq 3\" \"id:2,phase:1,deny,t:none\"";
    assert_eq!(
        denied_by(rules, "/?ATTACK=Attack&b=ATTACK").as_deref(),
        Some("2")
    );
}

#[test]
fn each_rule_keeps_its_own_exclusions() {
    // Rule 1 resolves ARGS for the phase and leaves `a` out; rule 2 does not.
    let rules = "SecRuleEngine On\n\
        SecRule ARGS|!ARGS:a \"@streq attack\" \"id:1,phase:1,deny,t:none\"\n\
        SecRule ARGS \"@streq attack\" \"id:2,phase:1,deny,t:none\"";
    assert_eq!(denied_by(rules, "/?a=attack").as_deref(), Some("2"));
    assert_eq!(denied_by(rules, "/?b=attack").as_deref(), Some("1"));

    // And the other way around: the rule with the exclusion comes second.
    let rules = "SecRuleEngine On\n\
        SecRule ARGS \"@streq other\" \"id:1,phase:1,deny,t:none\"\n\
        SecRule ARGS|!ARGS:a \"@streq attack\" \"id:2,phase:1,deny,t:none\"";
    assert_eq!(denied_by(rules, "/?a=attack"), None);
    assert_eq!(denied_by(rules, "/?b=attack").as_deref(), Some("2"));
}

#[test]
fn a_selection_is_not_answered_with_another_selection_s_values() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS:a \"@streq attack\" \"id:1,phase:1,deny,t:none\"\n\
        SecRule ARGS:b \"@streq attack\" \"id:2,phase:1,deny,t:none\"\n\
        SecRule ARGS:/^c/ \"@streq attack\" \"id:3,phase:1,deny,t:none\"\n\
        SecRule ARGS_NAMES \"@streq attack\" \"id:4,phase:1,deny,t:none\"";
    assert_eq!(denied_by(rules, "/?a=attack").as_deref(), Some("1"));
    assert_eq!(denied_by(rules, "/?b=attack").as_deref(), Some("2"));
    assert_eq!(denied_by(rules, "/?cc=attack").as_deref(), Some("3"));
    assert_eq!(denied_by(rules, "/?attack=1").as_deref(), Some("4"));
    assert_eq!(denied_by(rules, "/?d=attack"), None);
}

#[test]
fn a_count_follows_the_rule_s_exclusions() {
    // Both rules count ARGS; only the first leaves `a` out.
    let rules = "SecRuleEngine On\n\
        SecRule &ARGS|!ARGS:a \"@eq 2\" \"id:1,phase:1,deny,t:none\"\n\
        SecRule &ARGS \"@eq 2\" \"id:2,phase:1,deny,t:none\"";
    assert_eq!(denied_by(rules, "/?a=1&b=2&c=3").as_deref(), Some("1"));
    assert_eq!(denied_by(rules, "/?b=2&c=3").as_deref(), Some("1"));
    assert_eq!(denied_by(rules, "/?a=1&b=2").as_deref(), Some("2"));
}

#[test]
fn a_target_removed_by_ctl_stays_removed_for_that_rule_only() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS \"@streq other\" \"id:1,phase:1,pass,nolog,t:none\"\n\
        SecAction \"id:2,phase:1,pass,nolog,ctl:ruleRemoveTargetById=3;ARGS:a\"\n\
        SecRule ARGS \"@streq attack\" \"id:3,phase:1,deny,t:none\"\n\
        SecRule ARGS \"@streq attack\" \"id:4,phase:1,deny,t:none\"";
    assert_eq!(denied_by(rules, "/?a=attack").as_deref(), Some("4"));
    assert_eq!(denied_by(rules, "/?b=attack").as_deref(), Some("3"));
}

#[test]
fn what_a_rule_writes_is_seen_by_the_next_rule_of_the_phase() {
    // TX changes while the phase runs: rule 2 must read what rule 1 wrote,
    // and rule 4 what rule 3 wrote over it.
    let rules = "SecRuleEngine On\n\
        SecAction \"id:1,phase:1,pass,nolog,setvar:tx.seen=first\"\n\
        SecRule TX:seen \"@streq second\" \"id:2,phase:1,deny,t:none\"\n\
        SecAction \"id:3,phase:1,pass,nolog,setvar:tx.seen=second\"\n\
        SecRule TX:seen \"@streq second\" \"id:4,phase:1,deny,t:none\"";
    assert_eq!(denied_by(rules, "/").as_deref(), Some("4"));

    // MATCHED_VAR is the previous rule's match, whatever came before it.
    let rules = "SecRuleEngine On\n\
        SecRule ARGS:a \"@rx .\" \"id:1,phase:1,pass,nolog,t:none\"\n\
        SecRule MATCHED_VAR \"@streq attack\" \"id:2,phase:1,pass,nolog,t:none\"\n\
        SecRule ARGS:b \"@rx .\" \"id:3,phase:1,pass,nolog,t:none\"\n\
        SecRule MATCHED_VAR \"@streq attack\" \"id:4,phase:1,deny,t:none\"";
    assert_eq!(denied_by(rules, "/?a=x&b=attack").as_deref(), Some("4"));
    assert_eq!(denied_by(rules, "/?a=attack&b=x"), None);
}

#[test]
fn a_later_phase_sees_what_arrived_after_the_earlier_one() {
    // The body's arguments are not there in phase 1 and are in phase 2.
    let rules = "SecRuleEngine On\n\
        SecRequestBodyAccess On\n\
        SecRule ARGS \"@streq attack\" \"id:1,phase:1,deny,t:none\"\n\
        SecRule ARGS \"@streq attack\" \"id:2,phase:2,deny,t:none\"";
    let msc = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri("/?a=fine", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
        .unwrap();
    tx.process_request_headers().unwrap();
    assert!(tx.intervention().is_none());
    tx.append_request_body(b"b=attack").unwrap();
    tx.process_request_body().unwrap();
    let denied = tx.intervention().expect("phase 2 sees the body");
    assert_eq!(denied.rule_ids.first().map(String::as_str), Some("2"));
}
