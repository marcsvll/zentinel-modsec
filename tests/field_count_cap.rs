//! A request cannot bring an unbounded number of fields (S7): past the cap,
//! the rest is not collected and the request carries a body error, which the
//! recommended rule 200002 refuses. The JSON and XML processors had this; the
//! query string, urlencoded and multipart bodies and cookies did not.

use zentinel_modsec::ModSecurity;

const CAP: usize = 4096;

const RULES: &str = "SecRuleEngine On\n\
    SecRequestBodyAccess On\n\
    SecRule ARGS \"@streq attack\" \"id:1,phase:2,deny,status:403,t:none\"\n\
    SecRule &ARGS \"@gt 4096\" \"id:2,phase:2,deny,status:500,t:none\"\n\
    SecRule &REQUEST_COOKIES \"@gt 4096\" \"id:3,phase:2,deny,status:500,t:none\"\n\
    SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,deny,status:400\"";

/// The rule that denied the request, if one did.
fn denied_by(uri: &str, headers: &[(&str, &str)], body: Option<&[u8]>) -> Option<String> {
    let msc = ModSecurity::from_string(RULES).expect("rules should load");
    let mut tx = msc.new_transaction();
    let method = if body.is_some() { "POST" } else { "GET" };
    tx.process_uri(uri, method, "HTTP/1.1").unwrap();
    for (name, value) in headers {
        tx.add_request_header(name, value).unwrap();
    }
    tx.process_request_headers().unwrap();
    if let Some(body) = body {
        tx.append_request_body(body).unwrap();
    }
    tx.process_request_body().unwrap();
    tx.intervention().and_then(|i| i.rule_ids.first().cloned())
}

fn pairs(count: usize) -> String {
    vec!["a=1"; count].join("&")
}

const FORM: (&str, &str) = ("Content-Type", "application/x-www-form-urlencoded");

#[test]
fn a_query_string_at_the_cap_is_inspected_whole() {
    assert_eq!(denied_by(&format!("/?{}", pairs(CAP)), &[], None), None);
    let last = format!("/?{}&x=attack", pairs(CAP - 1));
    assert_eq!(denied_by(&last, &[], None).as_deref(), Some("1"));
}

#[test]
fn a_query_string_past_the_cap_is_a_body_error() {
    // Rule 2 would fire if more than the cap had been collected; rule 1 does
    // not see the argument past the cap; 200002 refuses the request.
    let uri = format!("/?{}&x=attack", pairs(CAP));
    assert_eq!(denied_by(&uri, &[], None).as_deref(), Some("200002"));
}

#[test]
fn a_form_body_past_the_cap_is_a_body_error() {
    let body = format!("{}&x=attack", pairs(CAP));
    assert_eq!(
        denied_by("/", &[FORM], Some(body.as_bytes())).as_deref(),
        Some("200002")
    );
    // The shape of the review: `a&a&a...`, two bytes per argument.
    let bare = vec!["a"; 100_000].join("&");
    assert_eq!(
        denied_by("/", &[FORM], Some(bare.as_bytes())).as_deref(),
        Some("200002")
    );
}

#[test]
fn the_query_and_the_body_share_one_cap() {
    let uri = format!("/?{}", pairs(CAP / 2));
    let within = pairs(CAP / 2);
    assert_eq!(denied_by(&uri, &[FORM], Some(within.as_bytes())), None);
    let over = pairs(CAP / 2 + 1);
    assert_eq!(
        denied_by(&uri, &[FORM], Some(over.as_bytes())).as_deref(),
        Some("200002")
    );
}

#[test]
fn a_multipart_body_past_the_cap_is_a_body_error() {
    let part = |name: &str, value: &str| {
        format!("--B\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
    };
    let content_type = ("Content-Type", "multipart/form-data; boundary=B");

    let mut within = String::new();
    for _ in 0..CAP - 1 {
        within.push_str(&part("a", "1"));
    }
    within.push_str(&part("x", "attack"));
    within.push_str("--B--\r\n");
    assert_eq!(
        denied_by("/", &[content_type], Some(within.as_bytes())).as_deref(),
        Some("1")
    );

    let mut over = String::new();
    for _ in 0..CAP {
        over.push_str(&part("a", "1"));
    }
    over.push_str(&part("x", "attack"));
    over.push_str("--B--\r\n");
    assert_eq!(
        denied_by("/", &[content_type], Some(over.as_bytes())).as_deref(),
        Some("200002")
    );
}

#[test]
fn cookies_past_the_cap_are_a_body_error() {
    let within = vec!["c=1"; CAP].join("; ");
    assert_eq!(denied_by("/", &[("Cookie", &within)], None), None);
    let over = vec!["c=1"; CAP + 1].join("; ");
    assert_eq!(
        denied_by("/", &[("Cookie", &over)], None).as_deref(),
        Some("200002")
    );
    // Across several Cookie headers too.
    let half = vec!["c=1"; CAP / 2 + 1].join("; ");
    assert_eq!(
        denied_by("/", &[("Cookie", &half), ("Cookie", &half)], None).as_deref(),
        Some("200002")
    );
}
