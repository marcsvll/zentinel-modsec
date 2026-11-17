//! `t:urlDecodeUni` reads `%uXXXX` through a best-fit table: the built-in one
//! (code page 20127, what ModSecurity's recommended configuration sets), or
//! the one a `SecUnicodeMapFile` directive names.

use std::io::Write;

use zentinel_modsec::transformations::create_transformation;
use zentinel_modsec::ModSecurity;

fn decoded(input: &str) -> String {
    let out = create_transformation("urlDecodeUni")
        .unwrap()
        .transform(input.as_bytes())
        .into_owned();
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn typographic_quotes_and_guillemets_fold_to_what_a_backend_would_see() {
    // CRS tests 942100-17, 941100-8 and 941100-9.
    assert_eq!(decoded("%u2019 or %u2019a%u2019=%u2019a"), "' or 'a'='a");
    assert_eq!(
        decoded("%u00abscript%u00bbalert(1)%u00ab/script%u00bb"),
        "<script>alert(1)</script>"
    );
    assert_eq!(decoded("%u2039script%u203a"), "<script>");
}

#[test]
fn what_the_table_does_not_fold_decodes_as_before() {
    assert_eq!(decoded("%u0041%u4e2d%uFF1C"), "A中<");
    // Accented letters are in the table too: a backend on that code page drops the accent.
    assert_eq!(decoded("%u00e9"), "e");
    assert_eq!(decoded("%27+%zz%u12"), "' %zz%u12");
}

const RULE: &str = "SecRuleEngine On\n\
    SecRule ARGS \"@streq 'x\" \"id:1,phase:1,deny,t:none,t:urlDecodeUni\"\n";

fn blocked(config: &str, query: &str) -> bool {
    let engine = ModSecurity::from_string(config).expect("the rules load");
    let mut tx = engine.new_transaction();
    tx.process_uri(format!("/?q={query}"), "GET", "HTTP/1.1")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.has_intervention()
}

#[test]
fn a_rule_sees_the_folded_value_without_any_directive() {
    assert!(blocked(RULE, "%25u2019x"));
    assert!(!blocked(RULE, "%25u2020x"));
}

#[test]
fn sec_unicode_map_file_replaces_the_table() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        file,
        "1250  (ANSI - Central Europe)\n2019:22\n20127 (US-ASCII)\n2020:27"
    )
    .unwrap();
    let path = file.path().display();

    // In this file's code page 20127, U+2020 is the quote and U+2019 is not folded.
    let config = format!("SecUnicodeMapFile \"{path}\" 20127\n{RULE}");
    assert!(blocked(&config, "%25u2020x"));
    assert!(!blocked(&config, "%25u2019x"));

    // The directive applies to every rule, wherever it stands.
    let config = format!("{RULE}SecUnicodeMapFile \"{path}\" 20127\n");
    assert!(blocked(&config, "%25u2020x"));
}

#[test]
fn a_mapping_that_cannot_be_used_is_a_load_error() {
    let Err(error) =
        ModSecurity::from_string("SecUnicodeMapFile /nonexistent/unicode.mapping 20127\n")
    else {
        panic!("a missing file should not load");
    };
    assert!(error.to_string().contains("SecUnicodeMapFile"), "{error}");

    let mut file = tempfile::NamedTempFile::new().unwrap();
    writeln!(file, "20127 (US-ASCII)\n2019:27").unwrap();
    let config = format!("SecUnicodeMapFile \"{}\" 437\n", file.path().display());
    let Err(error) = ModSecurity::from_string(&config) else {
        panic!("a missing code page should not load");
    };
    assert!(error.to_string().contains("437"), "{error}");
}
