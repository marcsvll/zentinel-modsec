//! `t:escapeSeqDecode` decodes ANSI C escapes as ModSecurity does: an escape
//! it does not know loses its backslash.

use zentinel_modsec::transformations::create_transformation;

fn decoded(input: &str) -> String {
    let out = create_transformation("escapeSeqDecode")
        .unwrap()
        .transform(input.as_bytes())
        .into_owned();
    String::from_utf8(out).expect("these escapes decode to text")
}

#[test]
fn the_c_escapes() {
    assert_eq!(decoded(r"\a\b\f\n\r\t\v"), "\u{7}\u{8}\u{c}\n\r\t\u{b}");
    assert_eq!(decoded(r#"\\ \? \' \""#), r#"\ ? ' ""#);
    assert_eq!(decoded(r"\x41\X42\x4a"), "ABJ");
    assert_eq!(decoded(r"\101\60\0"), "A0\0");
    // Octal stops at three digits and at the first digit that is not octal.
    assert_eq!(decoded(r"\1018\18"), "A8\u{1}8");
    // More than a byte keeps its low eight bits, as in C.
    assert_eq!(decoded(r"\777"), "\u{ff}");
}

#[test]
fn an_escape_that_is_not_one_loses_its_backslash() {
    assert_eq!(decoded(r"\q\u0041\ "), "qu0041 ");
    assert_eq!(decoded(r"\x4\xzz"), "x4xzz");
    assert_eq!(decoded("ends with \\"), "ends with \\");
    assert_eq!(decoded("no escape"), "no escape");
}

#[test]
fn a_quote_hidden_behind_a_backslash_is_seen() {
    // CRS tests 932210-6 and 932210-7: `1;.\"shell whoami`.
    assert_eq!(decoded(r#"1;.\"shell whoami"#), r#"1;."shell whoami"#);
    assert_eq!(decoded(r"1;.\'shell whoami"), "1;.'shell whoami");
}
