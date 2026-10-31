//! `REQBODY_PROCESSOR` is known from the request headers on, as in
//! ModSecurity: CRS 920400 (phase 1) chains `REQBODY_PROCESSOR "@streq
//! MULTIPART"` with `REQUEST_HEADERS:Content-Length "@gt %{tx.max_file_size}"`
//! to refuse an oversized upload before the body is read.

use zentinel_modsec::ModSecurity;

fn blocked_in_phase1(rules: &str, content_type: &str, content_length: &str) -> bool {
    let m = ModSecurity::from_string(rules).expect("rules load");
    let mut tx = m.new_transaction();
    tx.process_uri("/upload", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", content_type).unwrap();
    tx.add_request_header("Content-Length", content_length)
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.has_intervention()
}

const RULES: &str = "SecRuleEngine On\n\
    SecAction \"id:900000,phase:1,pass,nolog,setvar:tx.max_file_size=64100\"\n\
    SecRule &TX:MAX_FILE_SIZE \"@eq 1\" \"id:920400,phase:1,deny,t:none,chain\"\n\
    SecRule REQBODY_PROCESSOR \"@streq MULTIPART\" \"chain\"\n\
    SecRule REQUEST_HEADERS:Content-Length \"@gt %{tx.max_file_size}\" \"t:none\"";

#[test]
fn an_oversized_multipart_upload_is_refused_in_phase_1() {
    assert!(blocked_in_phase1(
        RULES,
        "multipart/form-data; boundary=x",
        "64200"
    ));
}

#[test]
fn a_small_upload_and_a_non_multipart_body_pass() {
    assert!(!blocked_in_phase1(
        RULES,
        "multipart/form-data; boundary=x",
        "1000"
    ));
    assert!(!blocked_in_phase1(
        RULES,
        "application/x-www-form-urlencoded",
        "64200"
    ));
}

#[test]
fn the_processor_name_follows_the_content_type() {
    for (ct, name) in [
        ("multipart/form-data; boundary=x", "MULTIPART"),
        ("application/x-www-form-urlencoded", "URLENCODED"),
        ("application/json", "JSON"),
        ("text/xml", "XML"),
    ] {
        let rules = format!(
            "SecRuleEngine On\nSecRule REQBODY_PROCESSOR \"@streq {name}\" \"id:1,phase:1,deny\""
        );
        assert!(blocked_in_phase1(&rules, ct, "10"), "{ct} -> {name}");
    }
}
