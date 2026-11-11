//! `MULTIPART_STRICT_ERROR` and the other `MULTIPART_*` flags, through rules: the
//! rules of `modsecurity.conf-recommended` (200002, 200003, 200004) must see what the
//! multipart processor noticed (neblina's docs/SECURITY_REVIEWS.md S1-S4, S6).

use zentinel_modsec::ModSecurity;

/// modsecurity.conf-recommended's body rules, as libmodsecurity ships them.
const RULES: &str = r#"SecRuleEngine On
SecRequestBodyAccess On
SecRule MULTIPART_LF_LINE "@eq 1" "id:9001,phase:2,pass,log,msg:'lf line'"
SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.'"
SecRule MULTIPART_STRICT_ERROR "!@eq 0" "id:200003,phase:2,t:none,log,deny,status:400,msg:'Multipart request body failed strict validation'"
SecRule MULTIPART_UNMATCHED_BOUNDARY "@eq 1" "id:200004,phase:2,t:none,log,deny,msg:'Multipart parser detected a possible unmatched boundary.'"
"#;

fn run(content_type: &str, body: &str) -> (bool, Vec<String>) {
    let msc = ModSecurity::from_string(RULES).expect("rules load");
    let mut tx = msc.new_transaction();
    tx.process_uri("/upload", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    tx.add_request_header("Content-Type", content_type).unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(body.as_bytes()).unwrap();
    tx.process_request_body().unwrap();
    let ids = tx.matched_rules().iter().map(|r| r.to_string()).collect();
    (tx.has_intervention(), ids)
}

#[test]
fn a_well_formed_body_passes_every_body_rule() {
    let (blocked, ids) = run(
        "multipart/form-data; boundary=B",
        "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\none\r\n--B--\r\n",
    );
    assert!(!blocked, "matched {ids:?}");
}

#[test]
fn lf_only_framing_is_a_strict_error() {
    let (blocked, ids) = run(
        "multipart/form-data; boundary=B",
        "--B\nContent-Disposition: form-data; name=\"a\"\n\none\n--B--\n",
    );
    assert!(blocked, "200003 must block: {ids:?}");
    assert!(
        ids.iter().any(|i| i.contains("200003")) && ids.iter().any(|i| i.contains("9001")),
        "{ids:?}"
    );
}

#[test]
fn a_missing_boundary_is_a_body_error() {
    let (blocked, ids) = run(
        "multipart/form-data",
        "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\none\r\n--B--\r\n",
    );
    assert!(
        blocked && ids.iter().any(|i| i.contains("200002")),
        "{ids:?}"
    );
}

#[test]
fn flags_are_absent_outside_multipart() {
    let msc = ModSecurity::from_string(RULES).expect("rules load");
    let mut tx = msc.new_transaction();
    tx.process_uri("/form", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(b"a=1").unwrap();
    tx.process_request_body().unwrap();
    assert!(!tx.has_intervention());
}
