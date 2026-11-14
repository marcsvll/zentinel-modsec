//! Full-width forms (`＜script＞`) reach the rules as the ASCII they stand
//! for through `t:utf8toUnicode,t:urlDecodeUni`, the pair the CRS uses, and a
//! malformed escape does not hide the well-formed one after it.

use zentinel_modsec::ModSecurity;

const RULES: &str = "SecRuleEngine On\n\
    SecRule ARGS \"@rx (?i)<script\" \
    \"id:1,phase:1,deny,t:none,t:utf8toUnicode,t:urlDecodeUni\"\n\
    SecRule ARGS \"@contains ' or \" \
    \"id:2,phase:1,deny,t:none,t:urlDecodeUni\"";

fn denied_by(uri: &str) -> Option<String> {
    let msc = ModSecurity::from_string(RULES).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.intervention().and_then(|i| i.rule_ids.first().cloned())
}

#[test]
fn full_width_text_is_tested_as_ascii() {
    // U+FF1C and U+FF1E as UTF-8, percent-encoded in the query.
    assert_eq!(
        denied_by("/?q=%EF%BC%9Cscript%EF%BC%9E").as_deref(),
        Some("1")
    );
    // The same characters as %u escapes that survive the query decoding
    // (`%25u` is a literal `%u` once the query is decoded).
    assert_eq!(
        denied_by("/?q=%25uFF1Cscript%25uFF1E").as_deref(),
        Some("1")
    );
    assert_eq!(denied_by("/?q=script"), None);
    // Other non-ASCII text goes through and comes back as it was.
    assert_eq!(denied_by("/?q=caf%C3%A9"), None);
}

#[test]
fn a_malformed_escape_does_not_swallow_the_next_one() {
    // After the query decoding the value is `%u%27 or 1`: the second escape
    // is well formed and must be decoded.
    assert_eq!(denied_by("/?q=%25u%2527%20or%201").as_deref(), Some("2"));
    assert_eq!(denied_by("/?q=%25%2527%20or%201").as_deref(), Some("2"));
}
