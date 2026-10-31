//! A rule's `capture` and `setvar` run once per matched variable, as in
//! ModSecurity. CRS 920450 collects `tx.header_name_920450_<name>` for every
//! request header and tests the collection in the next link; 922150 counts
//! multipart content types with `setvar:tx.counter=+1`. Stopping at the first
//! matched variable made both depend on which value happened to come first.

use zentinel_modsec::ModSecurity;

fn blocked_with_headers(rules: &str, headers: &[(&str, &str)]) -> bool {
    let m = ModSecurity::from_string(rules).expect("rules load");
    let mut tx = m.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    for (k, v) in headers {
        tx.add_request_header(k, v).unwrap();
    }
    tx.process_request_headers().unwrap();
    tx.has_intervention()
}

fn blocked_with_query(rules: &str, uri: &str) -> bool {
    let m = ModSecurity::from_string(rules).expect("rules load");
    let mut tx = m.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

// CRS 920450's shape: one TX variable per header name, then a lookup.
const RESTRICTED: &str = "SecRuleEngine On\n\
    SecRule REQUEST_HEADERS_NAMES \"@rx ^.*$\" \"id:920450,phase:1,deny,capture,t:none,t:lowercase,setvar:'tx.header_name_920450_%{tx.0}=/%{tx.0}/',chain\"\n\
    SecRule TX:/^header_name_920450_/ \"@within /content-range/ /if/\"";

#[test]
fn every_header_name_is_collected_whatever_its_position() {
    let restricted_last = [
        ("Host", "x"),
        ("User-Agent", "t"),
        ("Accept", "*/*"),
        ("If", "test"),
    ];
    let restricted_first = [
        ("If", "test"),
        ("Host", "x"),
        ("User-Agent", "t"),
        ("Accept", "*/*"),
    ];
    assert!(
        blocked_with_headers(RESTRICTED, &restricted_last),
        "restricted header last"
    );
    assert!(
        blocked_with_headers(RESTRICTED, &restricted_first),
        "restricted header first"
    );
    assert!(
        !blocked_with_headers(
            RESTRICTED,
            &[("Host", "x"), ("User-Agent", "t"), ("Accept", "*/*")]
        ),
        "no restricted header"
    );
}

#[test]
fn a_setvar_increment_counts_the_matched_values() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS \"@rx .\" \"id:1,phase:2,pass,nolog,t:none,setvar:tx.c=+1\"\n\
        SecRule TX:c \"@eq 3\" \"id:2,phase:2,deny\"";
    assert!(blocked_with_query(rules, "/?a=1&b=2&c=3"));
    assert!(!blocked_with_query(rules, "/?a=1&b=2"));
}

#[test]
fn matched_vars_holds_every_variable_the_rule_matched() {
    // The second link reads MATCHED_VARS; only `b` carries the `y`.
    let rules = "SecRuleEngine On\n\
        SecRule ARGS \"@rx x\" \"id:1,phase:2,deny,t:none,chain\"\n\
        SecRule MATCHED_VARS \"@rx y\"";
    assert!(blocked_with_query(rules, "/?a=x1&b=xy"));
    assert!(blocked_with_query(rules, "/?b=xy&a=x1"));
    assert!(!blocked_with_query(rules, "/?a=x1&b=x2"));
}

#[test]
fn a_secaction_runs_its_setvars_once() {
    let rules = "SecRuleEngine On\n\
        SecAction \"id:1,phase:1,pass,nolog,setvar:tx.c=+1\"\n\
        SecRule TX:c \"@eq 1\" \"id:2,phase:1,deny\"";
    assert!(blocked_with_headers(
        rules,
        &[("Host", "x"), ("A", "1"), ("B", "2")]
    ));
}
