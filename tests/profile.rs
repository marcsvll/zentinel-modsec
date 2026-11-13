//! `Transaction::enable_profile` records where a transaction spent its time,
//! per phase and per rule, and changes nothing else.

use zentinel_modsec::ModSecurity;

const RULES: &str = "SecRuleEngine On\n\
    SecRule ARGS \"@rx select\" \"id:1,phase:2,deny,t:none,t:lowercase\"\n\
    SecRule REQUEST_URI \"@contains admin\" \"id:2,phase:1,pass,nolog,chain\"\n\
    SecRule REQUEST_METHOD \"@streq GET\" \"t:none\"\n\
    SecRule REQUEST_HEADERS:Host \"@streq nowhere\" \"id:3,phase:1,pass,nolog\"";

fn run(profiled: bool) -> zentinel_modsec::engine::Transaction {
    let msc = ModSecurity::from_string(RULES).expect("rules should load");
    let mut tx = msc.new_transaction();
    if profiled {
        tx.enable_profile();
    }
    tx.process_uri("/admin?a=SELECT&b=1", "GET", "HTTP/1.1")
        .unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx
}

#[test]
fn a_transaction_is_not_profiled_unless_asked() {
    assert!(run(false).profile().is_none());
}

#[test]
fn the_profile_names_every_rule_of_each_phase_that_ran() {
    let tx = run(true);
    let profile = tx.profile().expect("profiled");

    let phase1 = &profile.phases[0];
    let ids: Vec<_> = phase1
        .rules
        .iter()
        .map(|r| (r.id.as_deref(), r.chain_link))
        .collect();
    // The chain's second link has no id of its own: it carries its starter's.
    assert_eq!(
        ids,
        [(Some("2"), false), (Some("2"), true), (Some("3"), false)]
    );
    assert!(phase1.rules.iter().all(|r| r.evaluations == 1));
    assert!(phase1.total_ns >= phase1.rules.iter().map(|r| r.total_ns).sum::<u64>());

    let phase2 = &profile.phases[1];
    assert_eq!(phase2.rules.len(), 1);
    // ARGS resolved to the two arguments.
    assert_eq!(phase2.rules[0].values, 2);
    assert!(phase2.rules[0].total_ns >= phase2.rules[0].transform_ns + phase2.rules[0].operator_ns);

    // Phases that did not run are empty.
    assert!(profile.phases[2].rules.is_empty());
}

#[test]
fn profiling_does_not_change_the_result() {
    let (plain, profiled) = (run(false), run(true));
    assert_eq!(plain.has_intervention(), profiled.has_intervention());
    assert!(profiled.has_intervention());
    assert_eq!(plain.matched_rules(), profiled.matched_rules());
}
