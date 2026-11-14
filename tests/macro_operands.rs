//! A macro in an operand is expanded per evaluation. That is fine for a value
//! to compare with and refused, when the rules load, for an operand that would
//! have to be compiled from it (S9).

use zentinel_modsec::ModSecurity;

fn load(rule: &str) -> Result<ModSecurity, String> {
    ModSecurity::from_string(&format!("SecRuleEngine On\n{rule}")).map_err(|e| e.to_string())
}

#[test]
fn an_operand_compiled_from_a_macro_is_a_load_error() {
    for operator in [
        "@rx ^%{tx.pattern}$",
        "@pm %{tx.words}",
        "@pmf %{tx.file}",
        "@pmFromFile %{tx.file}",
        "@ipMatch %{tx.networks}",
        "@ipMatchF %{tx.file}",
        "@ipMatchFromFile %{tx.file}",
        "!@rx %{MATCHED_VAR}",
    ] {
        let Err(error) = load(&format!(
            "SecRule ARGS \"{operator}\" \"id:4711,phase:1,deny,t:none\""
        )) else {
            panic!("{operator} should not load");
        };
        assert!(error.contains("4711"), "{operator}: {error}");
        assert!(error.contains("macro"), "{operator}: {error}");
    }
}

#[test]
fn a_chain_link_is_checked_too() {
    let Err(error) = load(
        "SecRule ARGS \"@rx a\" \"id:1,phase:1,deny,t:none,chain\"\n\
         SecRule ARGS \"@rx %{tx.pattern}\" \"t:none\"",
    ) else {
        panic!("the second link should not load");
    };
    assert!(error.contains("macro"), "{error}");
}

#[test]
fn a_literal_percent_or_brace_is_not_a_macro() {
    assert!(load("SecRule ARGS \"@rx ^100%$\" \"id:1,phase:1,deny,t:none\"").is_ok());
    assert!(load("SecRule ARGS \"@rx a{2,3}\" \"id:1,phase:1,deny,t:none\"").is_ok());
}

#[test]
fn a_value_to_compare_with_may_be_a_macro() {
    let msc = load(
        "SecAction \"id:1,phase:1,pass,nolog,setvar:tx.limit=2,setvar:tx.methods=GET HEAD\"\n\
         SecRule &ARGS \"@gt %{tx.limit}\" \"id:2,phase:1,deny,t:none\"\n\
         SecRule REQUEST_METHOD \"!@within %{tx.methods}\" \"id:3,phase:1,deny,t:none\"\n\
         SecRule ARGS:a \"@streq %{tx.limit}\" \"id:4,phase:1,deny,t:none\"",
    );
    let Ok(msc) = msc else {
        panic!("comparisons with macros load");
    };

    let denied_by = |uri: &str, method: &str| {
        let mut tx = msc.new_transaction();
        tx.process_uri(uri, method, "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx.intervention().and_then(|i| i.rule_ids.first().cloned())
    };
    assert_eq!(denied_by("/?x=1&y=2&z=3", "GET").as_deref(), Some("2"));
    assert_eq!(denied_by("/?x=1", "DELETE").as_deref(), Some("3"));
    assert_eq!(denied_by("/?a=2", "GET").as_deref(), Some("4"));
    assert_eq!(denied_by("/?a=3", "GET"), None);
}
