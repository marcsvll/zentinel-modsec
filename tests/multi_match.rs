//! `multiMatch`: the operator runs against the value before any transformation
//! and after each one that changed it, as ModSecurity does.
//!
//! CRS 942500 relies on it: `t:none,t:urlDecodeUni,multiMatch` over
//! `9999 or /*+optimizer hint */ true` matches the raw value, while urlDecodeUni
//! turns the `+` into a space and the regex (`/\*[\s\x0b]*?[!\+]`) would miss
//! the decoded one. The CRS regression tests 942500-3 and -4 and 934160-4
//! pass on ModSecurity v2 and v3 for exactly this reason.

use zentinel_modsec::ModSecurity;

fn blocked(rule: &str, uri: &str) -> bool {
    let rules = format!("SecRuleEngine On\n{rule}");
    let m = ModSecurity::from_string(&rules).expect("rules load");
    let mut tx = m.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

const COMMENT: &str = r#"SecRule ARGS "@rx (?i)/\*[\s\x0b]*?[!\+](?:[\s\x0b\(\)\-0-9=A-Z_a-z]+)?\*/" "id:942500,phase:2,deny,t:none,t:urlDecodeUni{MM}""#;
// `%2B` decodes to `+` when the argument is parsed; urlDecodeUni then makes it a space.
const URI: &str = "/get?test=9999+or+%2F*%2Boptimizer+hint+*%2F+true";

#[test]
fn multi_match_sees_the_value_before_the_transformation() {
    assert!(blocked(&COMMENT.replace("{MM}", ",multiMatch"), URI));
}

#[test]
fn without_multi_match_only_the_fully_transformed_value_is_tested() {
    assert!(!blocked(&COMMENT.replace("{MM}", ""), URI));
}

#[test]
fn multi_match_also_sees_the_transformed_value() {
    // The space only exists after urlDecodeUni; multiMatch tests that step too.
    let rule = r#"SecRule ARGS:q "@rx a\sb" "id:1,phase:2,deny,t:none,t:urlDecodeUni,multiMatch""#;
    assert!(blocked(rule, "/get?q=a%2Bb"));
}

#[test]
fn a_transformation_that_changes_nothing_adds_no_step() {
    use zentinel_modsec::transformations::TransformationPipeline;
    let p =
        TransformationPipeline::from_names(&["lowercase".into(), "urlDecodeUni".into()]).unwrap();
    assert_eq!(p.apply_steps("abc"), vec!["abc".to_string()]);
    assert_eq!(
        p.apply_steps("A+b"),
        vec!["A+b".to_string(), "a+b".to_string(), "a b".to_string()]
    );
}
