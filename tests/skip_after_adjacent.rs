//! `skipAfter` to a marker that comes right after the rule, with no rule of
//! the same phase in between, skips nothing and evaluation goes on.
//!
//! It used to skip the rest of the phase. The CRS ends each rule file's
//! paranoia sections with a gate per phase (`9xx017`, `9xx018`: "skip to the
//! end of this file unless paranoia is 4") followed by the file's end marker.
//! At paranoia 3 that gate fires with nothing left to skip, so the first file
//! with a gate ended phase 1 and phase 2 for the whole rule set: no detection
//! rule ran at paranoia 3.

use zentinel_modsec::ModSecurity;

fn denied_by(rules: &str, uri: &str) -> Option<String> {
    let msc = ModSecurity::from_string(&format!("SecRuleEngine On\n{rules}")).expect("rules load");
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.intervention().and_then(|i| i.rule_ids.first().cloned())
}

#[test]
fn a_marker_right_after_the_rule_skips_nothing() {
    let rules = "SecAction \"id:1,phase:1,pass,nolog,skipAfter:M\"\n\
                 SecMarker M\n\
                 SecRule ARGS \"@streq attack\" \"id:2,phase:1,deny,t:none\"";
    assert_eq!(denied_by(rules, "/?a=attack").as_deref(), Some("2"));
}

#[test]
fn rules_of_another_phase_in_between_do_not_count() {
    // Between the phase-1 gate and the marker there is only a phase-2 rule.
    let rules = "SecAction \"id:1,phase:1,pass,nolog,skipAfter:M\"\n\
                 SecAction \"id:2,phase:2,pass,nolog,skipAfter:M\"\n\
                 SecMarker M\n\
                 SecRule ARGS \"@streq one\" \"id:3,phase:1,deny,t:none\"\n\
                 SecRule ARGS \"@streq two\" \"id:4,phase:2,deny,t:none\"";
    assert_eq!(denied_by(rules, "/?a=one").as_deref(), Some("3"));
    assert_eq!(denied_by(rules, "/?a=two").as_deref(), Some("4"));
}

#[test]
fn the_crs_paranoia_gates_work_at_every_level() {
    // One file of the CRS in miniature: a rule per paranoia level, each
    // section opened by its gate, and the end marker; then the next file.
    let file = |level: u8| {
        format!(
            "SecAction \"id:900000,phase:1,pass,nolog,setvar:tx.detection_paranoia_level={level}\"\n\
             SecRule TX:DETECTION_PARANOIA_LEVEL \"@lt 1\" \"id:911011,phase:1,pass,nolog,skipAfter:END-911\"\n\
             SecRule ARGS \"@streq pl1\" \"id:911100,phase:1,deny,t:none\"\n\
             SecRule TX:DETECTION_PARANOIA_LEVEL \"@lt 2\" \"id:911013,phase:1,pass,nolog,skipAfter:END-911\"\n\
             SecRule ARGS \"@streq pl2\" \"id:911200,phase:1,deny,t:none\"\n\
             SecRule TX:DETECTION_PARANOIA_LEVEL \"@lt 3\" \"id:911015,phase:1,pass,nolog,skipAfter:END-911\"\n\
             SecRule TX:DETECTION_PARANOIA_LEVEL \"@lt 4\" \"id:911017,phase:1,pass,nolog,skipAfter:END-911\"\n\
             SecMarker END-911\n\
             SecRule ARGS \"@streq next\" \"id:920100,phase:1,deny,t:none\""
        )
    };
    for level in 1..=4u8 {
        let rules = file(level);
        // The next file's rule runs at every level: this is what failed at 3.
        assert_eq!(
            denied_by(&rules, "/?a=next").as_deref(),
            Some("920100"),
            "paranoia {level}"
        );
        assert_eq!(denied_by(&rules, "/?a=pl1").as_deref(), Some("911100"));
        let pl2 = denied_by(&rules, "/?a=pl2");
        if level >= 2 {
            assert_eq!(pl2.as_deref(), Some("911200"), "paranoia {level}");
        } else {
            assert_eq!(pl2, None, "paranoia {level}");
        }
    }
}

#[test]
fn a_marker_before_the_rule_or_unknown_still_ends_the_phase() {
    // ModSecurity does not jump backwards.
    let behind = "SecMarker M\n\
                  SecAction \"id:1,phase:1,pass,nolog,skipAfter:M\"\n\
                  SecRule ARGS \"@streq attack\" \"id:2,phase:1,deny,t:none\"";
    assert_eq!(denied_by(behind, "/?a=attack"), None);

    let unknown = "SecAction \"id:1,phase:1,pass,nolog,skipAfter:NOWHERE\"\n\
                   SecRule ARGS \"@streq attack\" \"id:2,phase:1,deny,t:none\"";
    assert_eq!(denied_by(unknown, "/?a=attack"), None);

    // The phase that follows is not affected.
    let next_phase = "SecAction \"id:1,phase:1,pass,nolog,skipAfter:NOWHERE\"\n\
                      SecRule ARGS \"@streq attack\" \"id:2,phase:2,deny,t:none\"";
    assert_eq!(denied_by(next_phase, "/?a=attack").as_deref(), Some("2"));
}
