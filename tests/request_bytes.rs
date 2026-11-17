//! Request data is bytes, as the client sent it. A rule may be looking for
//! bytes that are not UTF-8: CRS 944200 looks for the Java serialization magic
//! `AC ED 00 05`, which used to become U+FFFD before any rule saw it (its
//! regression test 944200-1 sends it in a urlencoded body).

use zentinel_modsec::ModSecurity;

/// CRS 944200's targets and pattern, denying.
const JAVA_MAGIC: &str = "SecRuleEngine On\n\
    SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_BODY|REQUEST_HEADERS|!REQUEST_HEADERS:Cookie|XML:/*|XML://@* \
    \"@rx \\xac\\xed\\x00\\x05\" \"id:944200,phase:2,deny,t:none\"";

fn denied(uri: &[u8], headers: &[(&[u8], &[u8])], body: &[u8]) -> bool {
    let msc = ModSecurity::from_string(JAVA_MAGIC).expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri(uri, "POST", "HTTP/1.1").unwrap();
    for (name, value) in headers {
        tx.add_request_header(name, value).unwrap();
    }
    tx.process_request_headers().unwrap();
    tx.append_request_body(body).unwrap();
    tx.process_request_body().unwrap();
    tx.intervention().is_some()
}

const FORM: (&[u8], &[u8]) = (b"Content-Type", b"application/x-www-form-urlencoded");

#[test]
fn crs_944200_1_raw_bytes_in_a_urlencoded_body() {
    assert!(denied(b"/", &[FORM], b"test=\xac\xed\x00\x05"));
    assert!(!denied(b"/", &[FORM], b"test=\xc2\xac\xc3\xad"));
}

#[test]
fn the_magic_is_seen_wherever_the_rule_looks() {
    // Percent-encoded in the query string, in a name and in a value.
    assert!(denied(b"/?q=%ac%ed%00%05", &[], b""));
    assert!(denied(b"/?%AC%ED%00%05=1", &[], b""));
    // Percent-encoded in a urlencoded body.
    assert!(denied(b"/", &[FORM], b"a=%ac%ed%00%05"));
    // Raw in a header value and in a cookie.
    assert!(denied(b"/", &[(b"X-Data", b"\xac\xed\x00\x05")], b""));
    assert!(denied(b"/", &[(b"Cookie", b"s=\xac\xed\x00\x05")], b""));
    // In a multipart field.
    let multipart: &[u8] =
        b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n\xac\xed\x00\x05\r\n--B--\r\n";
    assert!(denied(
        b"/",
        &[(b"Content-Type", b"multipart/form-data; boundary=B")],
        multipart
    ));
    // In XML text that is not UTF-8: inspected as written.
    assert!(denied(
        b"/",
        &[(b"Content-Type", b"application/xml")],
        b"<a><![CDATA[\xac\xed\x00\x05]]></a>"
    ));
}

#[test]
fn what_a_match_records_and_copies_keeps_its_bytes() {
    let msc = ModSecurity::from_string(
        "SecRuleEngine On\n\
         SecRule ARGS \"@rx \\xff\" \"id:1,phase:1,pass,capture,t:none,setvar:tx.seen=%{MATCHED_VAR}\"\n\
         SecRule TX:seen \"@rx ^\\xfe\\xff$\" \"id:2,phase:1,deny,t:none\"",
    )
    .expect("rules should load");
    let mut tx = msc.new_transaction();
    tx.process_uri(b"/?n%80=%fe%ff", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    assert!(
        tx.intervention().is_some(),
        "MATCHED_VAR kept its bytes through setvar"
    );
    let record = &tx.matched_data()[0];
    assert_eq!(record.variable, b"ARGS:n\x80");
    assert_eq!(record.value, b"\xfe\xff");
    assert_eq!(record.matched_portion.as_deref(), Some(&b"\xff"[..]));
}

#[test]
fn validate_utf8_encoding_reads_the_bytes() {
    let msc = ModSecurity::from_string(
        "SecRuleEngine On\n\
         SecRule ARGS|ARGS_NAMES \"@validateUtf8Encoding\" \"id:920250,phase:1,deny,t:none\"",
    )
    .expect("rules should load");
    for (uri, invalid) in [
        (&b"/?a=caf%C3%A9"[..], false),
        (b"/?a=%C0%AF", true),
        (b"/?a=%e9", true),
        (b"/?%ff=1", true),
        (b"/?a=%ED%A0%80", true),
    ] {
        let mut tx = msc.new_transaction();
        tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(
            tx.intervention().is_some(),
            invalid,
            "{}",
            uri.escape_ascii()
        );
    }
}

#[test]
fn a_boundary_that_is_not_ascii_still_frames_the_body() {
    // The boundary comes from the header's bytes, as the body is read as bytes:
    // a lossy header against a raw body used to find no part at all.
    let body: &[u8] = b"--\xff\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n\xac\xed\x00\x05\r\n--\xff--\r\n";
    assert!(denied(
        b"/",
        &[(b"Content-Type", b"multipart/form-data; boundary=\xff")],
        body
    ));
}
