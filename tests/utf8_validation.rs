//! `@validateUtf8Encoding` over arguments: the decoded bytes are checked, as
//! ModSecurity checks them, even though the engine keeps argument values as
//! `String`s (CRS 920250).

use zentinel_modsec::ModSecurity;

fn blocked(rules: &str, uri: &str) -> bool {
    let m = ModSecurity::from_string(rules).expect("rules load");
    let mut tx = m.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

const ARGS_RULE: &str = "SecRuleEngine On\n\
    SecRule REQUEST_URI|REQUEST_HEADERS|ARGS|ARGS_NAMES \"@validateUtf8Encoding\" \"id:920250,phase:2,deny,t:none\"";

#[test]
fn invalid_sequences_in_an_argument_value_are_flagged() {
    // The four CRS 920250 payloads: overlong, truncated, above U+10FFFF, truncated.
    for uri in [
        "/?param=%c0%af",
        "/?param=%c0",
        "/?param=%F5%80%BF%BF",
        "/?param=%E2%A3",
    ] {
        assert!(blocked(ARGS_RULE, uri), "{uri}");
    }
}

#[test]
fn an_invalid_argument_name_is_flagged_too() {
    assert!(blocked(ARGS_RULE, "/?%c0%af=1"));
}

#[test]
fn valid_utf8_passes_including_a_literal_replacement_character() {
    // `%EF%BF%BD` is U+FFFD sent on purpose: valid UTF-8, so not a finding,
    // which a check for U+FFFD in the decoded string would get wrong.
    for uri in [
        "/?param=%C3%A9",
        "/?param=%EF%BF%BD",
        "/?param=plain",
        "/?caf%C3%A9=1",
    ] {
        assert!(!blocked(ARGS_RULE, uri), "{uri}");
    }
}
