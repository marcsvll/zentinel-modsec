//! Tests for the XML request body processor.
//!
//! XML bodies were not inspected at all: they fell through to the urlencoded
//! parser, which finds nothing in them, so rules like CRS 942100 had nothing
//! to look at — the same gap the JSON processor closed, and the last one from
//! zentinelproxy/zentinel#340. The processor fills what ModSecurity's two XML
//! selectors yield: `XML:/*`, the document's text, and `XML://@*`, every
//! attribute value. Nothing goes into `ARGS` (ModSecurity leaves it alone for
//! an XML body), and element or attribute names are never values.
//!
//! XML brings hazards JSON does not, and most of this file is about them.
//! Expanding attacker-supplied entity definitions is the mechanism behind
//! both XXE and billion-laughs, so this engine does not expand them — and
//! says so through `REQBODY_ERROR` rather than quietly inspecting less than
//! the origin application will.

use zentinel_modsec::ModSecurity;

fn run(rules: &str, content_type: &str, body: &[u8]) -> bool {
    let m = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = m.new_transaction();
    tx.process_uri("/api", "POST", "HTTP/1.1").unwrap();
    if !content_type.is_empty() {
        tx.add_request_header("Content-Type", content_type).unwrap();
    }
    tx.process_request_headers().unwrap();
    tx.append_request_body(body).unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

fn contains(body: &[u8], needle: &str) -> bool {
    let rules =
        format!("SecRuleEngine On\nSecRule XML:/* \"@contains {needle}\" \"id:1,phase:2,deny\"");
    run(&rules, "application/xml", body)
}

const SQLI_RULE: &str = "SecRuleEngine On\n\
     SecRule XML:/*|XML://@* \"@detectSQLi\" \"id:942100,phase:2,deny,status:403\"";

const BODY_ERROR_RULE: &str = "SecRuleEngine On\n\
     SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,deny,status:400\"";

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

#[test]
fn sqli_in_element_text_is_detected() {
    assert!(run(
        SQLI_RULE,
        "application/xml",
        br#"<order><q>1 UNION SELECT password FROM users</q></order>"#
    ));
}

#[test]
fn sqli_in_an_attribute_is_detected() {
    assert!(run(
        SQLI_RULE,
        "application/xml",
        br#"<order q="1 UNION SELECT password FROM users"/>"#
    ));
}

/// CDATA is text deliberately marked as not-markup, which makes it an obvious
/// place to hide a payload.
#[test]
fn sqli_in_cdata_is_detected() {
    assert!(run(
        SQLI_RULE,
        "application/xml",
        br#"<o><q><![CDATA[1 UNION SELECT password FROM users]]></q></o>"#
    ));
}

#[test]
fn sqli_nested_deeply_is_detected() {
    assert!(run(
        SQLI_RULE,
        "application/xml",
        br#"<a><b><c><d>1 UNION SELECT password FROM users</d></c></b></a>"#
    ));
}

#[test]
fn clean_xml_traffic_passes() {
    assert!(!run(
        SQLI_RULE,
        "application/xml",
        br#"<order><q>laptop</q><qty>2</qty></order>"#
    ));
}

#[test]
fn xml_content_types_are_recognised() {
    let payload = br#"<o><q>1 UNION SELECT password FROM users</q></o>"#;
    for ct in [
        "application/xml",
        "text/xml",
        "APPLICATION/XML",
        "application/xml; charset=utf-8",
        // RFC 6839 structured suffix — SOAP is the one that matters here.
        "application/soap+xml",
        "application/atom+xml",
    ] {
        assert!(run(SQLI_RULE, ct, payload), "{ct} should be parsed as XML");
    }
}

#[test]
fn ctl_can_force_the_xml_processor() {
    let rules = "SecRuleEngine On\n\
         SecAction \"id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=XML\"\n\
         SecRule XML:/* \"@detectSQLi\" \"id:942100,phase:2,deny\"";
    assert!(run(
        rules,
        "",
        br#"<o><q>1 UNION SELECT password FROM users</q></o>"#
    ));
}

#[test]
fn reqbody_processor_reports_xml() {
    let rules = "SecRuleEngine On\n\
         SecRule REQBODY_PROCESSOR \"@streq XML\" \"id:1,phase:2,deny\"";
    assert!(run(rules, "application/xml", br#"<a>x</a>"#));
}

// ---------------------------------------------------------------------------
// What the selectors yield, and what they do not
// ---------------------------------------------------------------------------

#[test]
fn xml_is_not_exposed_through_args() {
    // ModSecurity does not populate ARGS from an XML body.
    let rules = "SecRuleEngine On\n\
         SecRule ARGS|ARGS_NAMES \"@contains widget\" \"id:1,phase:2,deny\"";
    assert!(!run(
        rules,
        "application/xml",
        br#"<order><item widget="7">widget</item></order>"#
    ));
}

#[test]
fn element_and_attribute_names_are_not_values() {
    // CRS 944100: `java.lang.runtime` in ARGS_NAMES|XML:/*|XML://@* must not
    // fire on an element or attribute *named* that way (its regression tests
    // 944100-11/12/15/16), only on text or attribute values.
    let rules = "SecRuleEngine On\n\
         SecRule ARGS|ARGS_NAMES|XML:/*|XML://@* \"@rx java\\.lang\\.(?:runtime|processbuilder)\" \
         \"id:944100,phase:2,deny,t:none,t:lowercase\"";
    for body in [
        br#"<?xml version="1.0"?><xml><java.lang.Runtime attribute_name="attribute_value">value</java.lang.Runtime></xml>"#.as_slice(),
        br#"<?xml version="1.0"?><xml><element java.lang.Runtime="attribute_value">element_value</element></xml>"#,
    ] {
        assert!(!run(rules, "application/xml", body), "a name is not a value");
    }
    assert!(run(
        rules,
        "application/xml",
        br#"<xml><e>java.lang.Runtime</e></xml>"#
    ));
    assert!(run(
        rules,
        "application/xml",
        br#"<xml><e a="java.lang.ProcessBuilder"/></xml>"#
    ));
}

#[test]
fn request_body_is_empty_under_the_xml_processor() {
    // ModSecurity v2 semantics, and what the CRS suite expects (944100-11):
    // REQUEST_BODY is the URLENCODED processor's; an XML body is reached
    // through XML:/* and XML://@*.
    let rules = "SecRuleEngine On\n\
         SecRule REQUEST_BODY \"@contains java.lang.runtime\" \"id:1,phase:2,deny,t:lowercase\"";
    assert!(!run(
        rules,
        "application/xml",
        br#"<xml><java.lang.Runtime a="v">value</java.lang.Runtime></xml>"#
    ));
    assert!(run(
        rules,
        "application/x-www-form-urlencoded",
        b"q=java.lang.Runtime"
    ));
}

#[test]
fn the_document_text_is_one_value_and_attributes_are_each_one() {
    let rules = "SecRuleEngine On\n\
         SecRule XML:/* \"@streq widget 3\" \"id:1,phase:2,deny\"";
    assert!(run(
        rules,
        "application/xml",
        br#"<order><item id="7">widget</item> <qty>3</qty></order>"#
    ));
    let rules = "SecRuleEngine On\n\
         SecRule XML://@* \"@streq 7\" \"id:1,phase:2,deny\"";
    assert!(run(
        rules,
        "application/xml",
        br#"<order><item id="7" kind="box">widget</item></order>"#
    ));
}

// ---------------------------------------------------------------------------
// Entities: the part that matters
// ---------------------------------------------------------------------------

#[test]
fn predefined_entities_are_decoded() {
    assert!(contains(br#"<a>x&amp;y</a>"#, "x&y"));
    assert!(contains(br#"<a>a&lt;b</a>"#, "a<b"));
}

#[test]
fn numeric_character_references_are_decoded() {
    assert!(contains(br#"<a>UNION&#32;SELECT x</a>"#, "UNION SELECT"));
    assert!(contains(br#"<a>UNION&#x20;SELECT x</a>"#, "UNION SELECT"));
}

/// An evasion the first version of this processor was vulnerable to.
///
/// quick-xml delivers text in fragments split around every entity reference.
/// Emitting each fragment as its own argument would cut a payload into pieces
/// too small for any rule to match, so text is accumulated per element and
/// flushed whole.
#[test]
fn a_payload_split_by_an_entity_reference_is_reassembled() {
    assert!(run(
        SQLI_RULE,
        "application/xml",
        br#"<o><q>1 UNION&#32;SELECT password FROM users</q></o>"#
    ));
}

/// XXE. The file must not be read, and its contents must not reach `ARGS`.
#[test]
fn an_external_entity_is_not_resolved() {
    let xxe = br#"<?xml version="1.0"?>
        <!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]>
        <d>&x;</d>"#;

    assert!(
        !contains(xxe, "root:"),
        "external entity content must never reach ARGS"
    );
}

/// Billion laughs. Must not expand, and must not take measurable time.
#[test]
fn an_entity_expansion_bomb_does_not_expand() {
    let bomb = br#"<?xml version="1.0"?><!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]><lolz>&lol9;</lolz>"#;

    let start = std::time::Instant::now();
    let _ = run(SQLI_RULE, "application/xml", bomb);
    let elapsed = start.elapsed();

    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "entity expansion should not be happening at all, took {elapsed:?}"
    );
}

/// Not expanding a custom entity is safe, but it means the origin application
/// may see content this engine did not. That must be visible rather than
/// silently treated as a fully inspected body — the same reasoning as the
/// JSON processing limits.
#[test]
fn an_unexpanded_custom_entity_sets_reqbody_error() {
    let hidden = br#"<?xml version="1.0"?>
        <!DOCTYPE d [<!ENTITY p "1 UNION SELECT password FROM users">]>
        <d>&p;</d>"#;

    assert!(
        !contains(hidden, "UNION SELECT"),
        "the entity must not be expanded"
    );
    assert!(
        run(BODY_ERROR_RULE, "application/xml", hidden),
        "but the operator must be able to see that something was not inspected"
    );
}

/// The counterpart: ordinary XML, including documents using the predefined
/// entities, must not trip that error. A body-error rule that fires on normal
/// traffic would be turned off within a day.
#[test]
fn ordinary_xml_does_not_set_reqbody_error() {
    assert!(!run(
        BODY_ERROR_RULE,
        "application/xml",
        br#"<order><q>laptop</q></order>"#
    ));
    assert!(!run(
        BODY_ERROR_RULE,
        "application/xml",
        br#"<order><q>Bell &amp; Sons &lt;Ltd&gt;</q></order>"#
    ));
}

// ---------------------------------------------------------------------------
// Malformed input and limits
// ---------------------------------------------------------------------------

#[test]
fn mismatched_tags_set_reqbody_error() {
    assert!(run(BODY_ERROR_RULE, "application/xml", b"<a><b></a>"));
}

#[test]
fn truncated_markup_sets_reqbody_error() {
    assert!(run(BODY_ERROR_RULE, "application/xml", b"<a><b>text"));
}

#[test]
fn an_empty_body_is_not_a_parse_error() {
    // Routine on POST and DELETE; reporting it would be a false positive.
    assert!(!run(BODY_ERROR_RULE, "application/xml", b""));
    assert!(!run(BODY_ERROR_RULE, "application/xml", b"  \n\t "));
}

#[test]
fn deeply_nested_xml_is_reported_rather_than_silently_truncated() {
    let deep = format!("{}payload{}", "<a>".repeat(500), "</a>".repeat(500));
    assert!(run(BODY_ERROR_RULE, "application/xml", deep.as_bytes()));
}

#[test]
fn a_huge_number_of_elements_is_reported() {
    let many: String = (0..5000).map(|i| format!("<v>{i}</v>")).collect();
    let doc = format!("<root>{many}</root>");
    assert!(run(BODY_ERROR_RULE, "application/xml", doc.as_bytes()));
}

#[test]
fn a_malformed_body_does_not_abort_the_transaction() {
    // Phase 2 still runs, so the ruleset decides what to do about the failure.
    let rules = "SecRuleEngine On\n\
         SecRule REQUEST_URI \"@contains /api\" \"id:1,phase:2,deny\"";
    assert!(run(rules, "application/xml", b"<a><b></a>"));
}

#[test]
fn a_non_xml_content_type_is_not_parsed_as_xml() {
    let rules = "SecRuleEngine On\n\
         SecRule ARGS:xml.a \"@rx .\" \"id:1,phase:2,deny\"";
    assert!(!run(rules, "text/plain", b"<a>value</a>"));
}

// ---------------------------------------------------------------------------
// Nothing is dropped quietly (engine security review, S5)
// ---------------------------------------------------------------------------

/// Which of three observations hold for a body: the text carries `needle`, an
/// attribute carries `needle`, the body is reported as an error.
fn seen(body: &[u8], needle: &str) -> (bool, bool, bool) {
    let rules = format!(
        "SecRuleEngine On\n\
         SecRule XML:/* \"@contains {needle}\" \"id:1,phase:2,pass,nolog,t:none\"\n\
         SecRule XML://@* \"@contains {needle}\" \"id:2,phase:2,pass,nolog,t:none\"\n\
         SecRule REQBODY_ERROR \"!@eq 0\" \"id:3,phase:2,pass,nolog\""
    );
    let m = ModSecurity::from_string(&rules).expect("rules should load");
    let mut tx = m.new_transaction();
    tx.process_uri("/api", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "application/xml")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(body).unwrap();
    tx.process_request_body().unwrap();
    let fired = |id: &str| tx.matched_rules().iter().any(|r| r == id);
    (fired("1"), fired("2"), fired("3"))
}

#[test]
fn an_attribute_value_that_does_not_decode_is_inspected_as_written() {
    // Not UTF-8: the value used to become an empty string, with no error.
    let (_, in_attribute, error) = seen(b"<a b=\"\xff' OR 1=1--\"/>", "OR 1=1");
    assert!(in_attribute, "the raw value must reach the rules");
    assert!(error, "and the document is not fully understood");

    // A reference that does not resolve inside an attribute, likewise.
    let (_, in_attribute, error) = seen(b"<a b=\"x &custom; OR 1=1--\"/>", "OR 1=1");
    assert!(in_attribute);
    assert!(error);
}

#[test]
fn a_malformed_attribute_is_a_parse_error_and_what_came_before_is_kept() {
    // The unquoted attribute used to be skipped, and the document accepted.
    let (_, in_attribute, error) =
        seen(b"<a first=\"evil-marker\" b=unquoted>t</a>", "evil-marker");
    assert!(error, "a malformed attribute is not well-formed XML");
    assert!(
        in_attribute,
        "the attribute read before it is still inspected"
    );
}

#[test]
fn text_that_is_not_utf8_is_inspected_as_written() {
    // The text node used to be dropped whole, with no error.
    let (in_text, _, error) = seen(b"<a>\xff UNION SELECT</a>", "UNION SELECT");
    assert!(in_text, "the text must reach the rules");
    assert!(error);
}

#[test]
fn text_read_before_a_parse_error_is_still_inspected() {
    // REQUEST_BODY is empty under the XML processor, so text discarded on an
    // error was text no rule could see.
    let (in_text, _, error) = seen(b"<a>evil-marker</b>", "evil-marker");
    assert!(error);
    assert!(in_text, "what was read before the error is inspected");

    let (in_text, _, error) = seen(b"<a><b>evil-marker</b>", "evil-marker");
    assert!(error, "a truncated document");
    assert!(in_text);
}

#[test]
fn a_well_formed_document_reports_nothing() {
    let (in_text, in_attribute, error) = seen(
        "<a b=\"evil-marker &amp; caf\u{e9}\">evil-marker &lt; caf\u{e9}</a>".as_bytes(),
        "evil-marker",
    );
    assert!(in_text && in_attribute);
    assert!(!error);
}

#[test]
fn a_declared_encoding_that_is_not_utf8_is_reported() {
    // UTF-7 `<script>`: ASCII to this parser, markup to one that honours the
    // declaration.
    let body = b"<?xml version=\"1.0\" encoding=\"UTF-7\"?><a>+ADw-script+AD4-</a>";
    let (in_text, _, error) = seen(body, "+ADw-script");
    assert!(in_text, "the text is inspected as written");
    assert!(error, "and the document is not fully understood");

    let utf8 = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><a>evil-marker</a>";
    let (in_text, _, error) = seen(utf8, "evil-marker");
    assert!(in_text);
    assert!(!error, "UTF-8 is what the parser reads");
}

#[test]
fn a_doctype_with_an_internal_subset_is_reported() {
    // A default attribute value: the application sees an attribute this
    // parser never builds.
    let body = b"<!DOCTYPE a [<!ATTLIST a b CDATA \"evil-marker\">]><a>text</a>";
    let (_, _, error) = seen(body, "evil-marker");
    assert!(error);

    let plain = b"<!DOCTYPE a><a>evil-marker</a>";
    let (in_text, _, error) = seen(plain, "evil-marker");
    assert!(in_text);
    assert!(!error, "a DOCTYPE that declares nothing changes nothing");
}
