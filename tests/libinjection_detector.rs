//! `@detectSQLi` and `@detectXSS` give libinjection's verdicts: ordinary paths
//! and prose are not injections, and what `@detectSQLi` reports as matched is the
//! fingerprint.

use zentinel_modsec::operators::{DetectSqliOperator, DetectXssOperator, Operator};

fn sqli(value: &str) -> bool {
    DetectSqliOperator.execute(value.as_bytes()).matched
}

fn xss(value: &str) -> bool {
    DetectXssOperator.execute(value.as_bytes()).matched
}

#[test]
fn ordinary_paths_and_prose_are_not_sql_injection() {
    for value in [
        "/vulnerabilities/exec/",
        "/users/v1/name1",
        "Delivery was quick; 5/5.",
        "O'Brien",
        "select a plan and update your profile",
        "",
    ] {
        assert!(!sqli(value), "{value:?} was reported as SQL injection");
    }
}

#[test]
fn sql_injection_is_reported() {
    for value in [
        "1' OR '1'='1",
        "name1' UNION SELECT password FROM users--",
        "1; DROP TABLE users",
        "-1 UNION ALL SELECT NULL,NULL,version()",
    ] {
        assert!(sqli(value), "{value:?} was not reported");
    }
}

#[test]
fn detect_sqli_reports_the_fingerprint() {
    let result = DetectSqliOperator.execute(b"1' OR '1'='1");
    assert!(result.matched);
    assert_eq!(result.matched_value.as_deref(), Some(&b"s&sos"[..]));
}

#[test]
fn ordinary_text_is_not_xss() {
    for value in [
        "a < b and c > d",
        "Tom & Jerry",
        "https://example.com/?q=1",
        "",
    ] {
        assert!(!xss(value), "{value:?} was reported as XSS");
    }
}

#[test]
fn xss_is_reported() {
    for value in [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "\" onmouseover=\"alert(1)",
    ] {
        assert!(xss(value), "{value:?} was not reported");
    }
}

#[test]
fn what_the_translation_missed_and_the_c_library_reports() {
    // Found by differential/: keywords of three words, and INTO OUTFILE in
    // lower case. The fingerprints are the C library's.
    for (value, fingerprint) in [
        ("1' IN BOOLEAN MODE) AND 1", "sk)&1"),
        ("1 LOCK IN SHARE MODE UNION SELECT 1", "1kUE1"),
        ("1; CREATE OR REPLACE FUNCTION SLEEP(int)", "1;Tkf"),
        ("1 into outfile 'a'", "1ks"),
    ] {
        let result = DetectSqliOperator.execute(value.as_bytes());
        assert_eq!(
            result.matched_value.as_deref(),
            Some(fingerprint.as_bytes()),
            "{value:?}"
        );
    }
}

#[test]
fn a_single_word_or_number_is_never_sql_injection() {
    // Answered without running libinjection; the C library agrees
    // (differential/).
    for value in [
        "",
        "select",
        "UNION",
        "0x41",
        "1e5",
        "sleep",
        "sp_password",
        "a_b_1",
        "NULL",
    ] {
        assert!(!sqli(value), "{value:?}");
    }
    // One character more and libinjection decides.
    assert!(sqli("1 union select 1"));
    assert!(sqli("1'or'1'='1"));
}
