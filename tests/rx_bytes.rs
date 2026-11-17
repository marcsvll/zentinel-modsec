//! `@rx` reads a pattern the way ModSecurity's PCRE does, without UTF mode: the
//! value is bytes, `\xHH` and `\x{HH}` are bytes, `.` takes one byte and case
//! folding is ASCII. A pattern that needs Unicode is compiled over characters
//! (UTF-8 sequences in the bytes).

use zentinel_modsec::operators::{Operator, RxOperator};

fn rx(pattern: &str) -> RxOperator {
    RxOperator::new(pattern).expect("the pattern compiles")
}

#[test]
fn hex_escapes_are_bytes_with_or_without_braces() {
    // The spelling CRS 942430 uses for U+00B4, U+2018 and U+2019.
    let quotes = rx(r"\x{c2}\x{b4}|\x{e2}\x80[\x98\x99]");
    for value in ["´", "‘", "’"] {
        assert!(quotes.execute(value.as_bytes()).matched, "{value:?}");
    }
    // U+00C2 followed by U+00B4 is four bytes, not those two.
    assert!(
        !rx(r"^\x{c2}\x{b4}$")
            .execute("\u{c2}\u{b4}".as_bytes())
            .matched
    );
}

#[test]
fn the_special_character_count_of_942430_sees_typographic_quotes() {
    let rule = rx(
        r"((?:(?:[!-\+\-:->@\[\]\^`\{-~]|\x{c2}\x{b4}|\x{e2}\x80[\x98\x99])[^!-\+\-:->@\[\]\^`\{-~]*?){12})",
    );
    for value in [
        "1’ OR ’1’=’x’#;--()",
        "1´ OR ´1´=´x´#;--()",
        "1' OR '1'='x'#;--()",
    ] {
        assert!(rule.execute(value.as_bytes()).matched, "{value:?}");
    }
    assert!(
        !rule
            .execute("an ordinary sentence, with a comma.".as_bytes())
            .matched
    );
}

#[test]
fn a_dot_is_one_byte_and_case_folding_is_ascii() {
    assert!(!rx("^.$").execute("é".as_bytes()).matched);
    assert!(rx("^..$").execute("é".as_bytes()).matched);
    assert!(rx("(?i)^select$").execute("SeLeCt".as_bytes()).matched);
    assert!(!rx("(?i)^é$").execute("É".as_bytes()).matched);
    assert!(!rx(r"^\w$").execute("é".as_bytes()).matched);
}

#[test]
fn a_group_that_ends_inside_a_character_is_the_byte() {
    let result = rx("^(.)").execute("é!".as_bytes());
    assert!(result.matched);
    assert_eq!(result.captures, [b"\xc3".to_vec()]);
}

#[test]
fn a_pattern_that_needs_unicode_is_matched_over_characters() {
    assert!(rx(r"^\p{L}+$").execute("naïve".as_bytes()).matched);
    assert!(rx(r"^\x{2019}$").execute("’".as_bytes()).matched);
    assert!(rx("^[é]$").execute("é".as_bytes()).matched);
}

#[test]
fn an_escaped_backslash_before_x_is_not_an_escape() {
    assert!(rx(r"^\\x\{41\}$").execute(r"\x{41}".as_bytes()).matched);
    assert!(!rx(r"^\\x\{41\}$").execute("A".as_bytes()).matched);
    assert!(rx(r"^\x{41}$").execute("A".as_bytes()).matched);
}
