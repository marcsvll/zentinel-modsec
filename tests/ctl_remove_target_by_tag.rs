//! `ctl:ruleRemoveTargetByTag=TAG;TARGET` drops a target from every rule that
//! carries the tag, for the rest of the transaction. CRS 941xxx uses it to keep
//! `REQUEST_FILENAME` out of the `xss-perf-disable` rules on paths that look
//! like attacks but are not (941180-7: `/get/javascript-manual/document.cookie`).

use zentinel_modsec::ModSecurity;

fn blocked(rules: &str, uri: &str) -> bool {
    let m = ModSecurity::from_string(rules).expect("rules load");
    let mut tx = m.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

const RULES: &str = "SecRuleEngine On\n\
    SecAction \"id:1,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=xss-perf-disable;REQUEST_FILENAME\"\n\
    SecRule REQUEST_FILENAME|ARGS \"@contains document.cookie\" \"id:941180,phase:2,deny,t:none,tag:'attack-xss',tag:'xss-perf-disable'\"\n\
    SecRule REQUEST_FILENAME \"@contains document.write\" \"id:941181,phase:2,deny,t:none,tag:'attack-xss'\"";

#[test]
fn the_target_is_dropped_from_the_tagged_rule() {
    assert!(!blocked(RULES, "/get/javascript-manual/document.cookie"));
}

#[test]
fn the_tagged_rule_keeps_its_other_targets() {
    assert!(blocked(RULES, "/get?q=document.cookie"));
}

#[test]
fn rules_without_the_tag_are_untouched() {
    assert!(blocked(RULES, "/get/javascript-manual/document.write"));
}
