//! What a value must contain for an operator to match it, decided cheaply.
//!
//! Phase 2 of the CRS runs about 170 rules over every value of the request: a
//! JSON body with 4,000 values is 400,000 operator calls, nearly all of them a
//! regular expression that does not match. Most of those patterns cannot match
//! a value unless it holds certain bytes: a command injection pattern needs
//! one of `; | & $ ( <`, a header injection pattern a CR or LF. A value such
//! as `customer 12` has none of them, and that is known from one pass over the
//! value, shared by every rule.
//!
//! [`classes`] is that pass: which classes of bytes a value holds, as a bit
//! mask. A [`Need`] is what an operator requires, as up to [`MAX_CLAUSES`]
//! masks: the value must hold a byte of every one of them. `need.allows(mask)`
//! false means the operator **cannot** match; true means it may, and the
//! operator runs as before. Everything here errs towards "may": a pattern
//! whose requirement is not understood has no [`Need`] and always runs. The
//! prefilter never decides a match, so it cannot add a false positive; a false
//! negative would be a clause that a matching value does not satisfy, which is
//! what `tests/prefilter_invisible.rs` and the `prefilter` fuzz target look for.

use regex_syntax::hir::{Class, Hir, HirKind};

/// Most clauses kept for one operator.
pub const MAX_CLAUSES: usize = 4;

const SPACE: u32 = 32;
const TAB: u32 = 33;
const LF: u32 = 34;
const CR: u32 = 35;
const NUL: u32 = 36;
const CONTROL: u32 = 37;
const DIGIT: u32 = 38;
const LOWER: u32 = 39;
const UPPER: u32 = 40;
const HIGH: u32 = 41;

/// The class of one byte: each ASCII punctuation character has its own, so
/// do space, tab, LF, CR and NUL; the other control characters share one, as
/// do digits, lower-case letters, capitals and the bytes above `7F`.
const fn class_of(b: u8) -> u32 {
    match b {
        b' ' => SPACE,
        b'\t' => TAB,
        b'\n' => LF,
        b'\r' => CR,
        0 => NUL,
        b'0'..=b'9' => DIGIT,
        b'a'..=b'z' => LOWER,
        b'A'..=b'Z' => UPPER,
        0x21..=0x2f => (b - 0x21) as u32,
        0x3a..=0x40 => (b - 0x3a) as u32 + 15,
        0x5b..=0x60 => (b - 0x5b) as u32 + 22,
        0x7b..=0x7e => (b - 0x7b) as u32 + 28,
        0x80..=0xff => HIGH,
        _ => CONTROL,
    }
}

const TABLE: [u64; 256] = {
    let mut table = [0u64; 256];
    let mut b = 0;
    while b < 256 {
        table[b] = 1 << class_of(b as u8);
        b += 1;
    }
    table
};

/// The class of byte `b`, as a mask of one bit.
pub const fn class(b: u8) -> u64 {
    TABLE[b as usize]
}

/// The classes of the bytes of `bytes`.
pub const fn classes_of(bytes: &[u8]) -> u64 {
    let mut mask = 0;
    let mut i = 0;
    while i < bytes.len() {
        mask |= TABLE[bytes[i] as usize];
        i += 1;
    }
    mask
}

/// Capital letters.
pub const UPPER_CASE: u64 = 1 << UPPER;
/// Lower-case letters.
pub const LOWER_CASE: u64 = 1 << LOWER;
/// Digits.
pub const DIGITS: u64 = 1 << DIGIT;
/// Bytes above `7F`.
pub const NOT_ASCII: u64 = 1 << HIGH;
/// Every byte some transformation reads as whitespace: space, tab, LF, CR,
/// the other control characters (vertical tab and form feed are among them)
/// and the bytes above `7F` (the Unicode spaces).
pub const WHITESPACE: u64 = 1 << SPACE | 1 << TAB | 1 << LF | 1 << CR | 1 << CONTROL | 1 << HIGH;

/// The classes of bytes `value` holds.
pub fn classes(value: &[u8]) -> u64 {
    value.iter().fold(0, |mask, &b| mask | TABLE[b as usize])
}

/// How likely an ordinary value is to satisfy a clause: the lower, the more
/// values it rules out. Letters, digits and spaces are in nearly every value.
fn weight(clause: u64) -> u32 {
    const COMMON: u64 = 1 << SPACE | 1 << DIGIT | 1 << LOWER | 1 << UPPER;
    let usual = classes_of(b".-_/:,@=");
    (clause & COMMON).count_ones() * 1000
        + (clause & usual).count_ones() * 30
        + (clause & !(COMMON | usual)).count_ones()
}

/// What a value must hold for an operator to match it: a byte of every
/// clause. Built so that a matching value always satisfies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Need {
    clauses: [u64; MAX_CLAUSES],
    len: usize,
}

impl Need {
    fn new(mut clauses: Vec<u64>) -> Option<Self> {
        clauses.sort_by_key(|c| (weight(*c), *c));
        clauses.dedup();
        clauses.truncate(MAX_CLAUSES);
        if clauses.is_empty() {
            return None;
        }
        let mut out = [0; MAX_CLAUSES];
        out[..clauses.len()].copy_from_slice(&clauses);
        Some(Self {
            clauses: out,
            len: clauses.len(),
        })
    }

    /// Whether a value with these [`classes`] may match. `false` is certain.
    #[inline]
    pub fn allows(&self, classes: u64) -> bool {
        self.clauses[..self.len].iter().all(|c| classes & c != 0)
    }

    /// The clauses, strongest first.
    pub fn clauses(&self) -> &[u64] {
        &self.clauses[..self.len]
    }

    /// For a value that must contain `literal`: every byte of it is needed.
    /// With `ignore_case`, a letter is needed in either case.
    pub fn of_literal(literal: &[u8], ignore_case: bool) -> Option<Self> {
        Self::new(literal_clauses(literal, ignore_case))
    }

    /// For a value that must contain one of `literals` (`@pm`): the strongest
    /// clause of each, any of which may be the one satisfied.
    pub fn of_any_literal<'a>(
        literals: impl IntoIterator<Item = &'a [u8]>,
        ignore_case: bool,
    ) -> Option<Self> {
        let mut any = 0u64;
        let mut seen = false;
        for literal in literals {
            let best = literal_clauses(literal, ignore_case)
                .into_iter()
                .min_by_key(|c| weight(*c))?;
            any |= best;
            seen = true;
        }
        seen.then(|| Self::new(vec![any])).flatten()
    }

    /// For a value that must hold at least one of `bytes`. `None` when no
    /// byte is given (nothing would satisfy it, which is not a need to state).
    pub fn of_any_byte(bytes: impl IntoIterator<Item = u8>) -> Option<Self> {
        let clause = bytes.into_iter().fold(0, |m, b| m | TABLE[b as usize]);
        (clause != 0).then(|| Self::new(vec![clause])).flatten()
    }

    /// For a value a regular expression must match somewhere in. `None` when
    /// nothing certain is known about it.
    pub fn of_regex(hir: &Hir) -> Option<Self> {
        Self::new(clauses_of(hir)?)
    }
}

fn literal_clauses(literal: &[u8], ignore_case: bool) -> Vec<u64> {
    literal
        .iter()
        .map(|&b| {
            let mut clause = TABLE[b as usize];
            if ignore_case && b.is_ascii_alphabetic() {
                clause |= TABLE[(b ^ 0x20) as usize];
            }
            clause
        })
        .collect()
}

/// The clauses every match of `hir` satisfies, or `None` when there is none
/// to state. A clause is a set of classes of which the matched text holds at
/// least one byte.
///
/// - A literal holds each of its bytes: one clause per byte.
/// - A class matches exactly one byte, which is one of its own: one clause.
/// - A concatenation matches all of its parts: the clauses of all of them.
/// - An alternation matches one branch, unknown which: one clause, the union
///   of the strongest clause of every branch; none if a branch has none.
/// - A repetition that must happen at least once has its operand's clauses;
///   one that may happen zero times has none.
/// - An assertion (`^`, `$`, `\b`) and the empty pattern match no byte.
fn clauses_of(hir: &Hir) -> Option<Vec<u64>> {
    let clauses = match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => return None,
        HirKind::Literal(literal) => literal_clauses(&literal.0, false),
        HirKind::Class(Class::Bytes(class)) => {
            let mut clause = 0u64;
            for range in class.iter() {
                for b in range.start()..=range.end() {
                    clause |= TABLE[b as usize];
                }
            }
            // An empty class matches nothing: a clause no value satisfies.
            vec![clause]
        }
        // Patterns are compiled over bytes; a Unicode class is not expected,
        // and nothing is claimed about one.
        HirKind::Class(Class::Unicode(_)) => return None,
        HirKind::Repetition(repetition) => {
            if repetition.min == 0 {
                return None;
            }
            clauses_of(&repetition.sub)?
        }
        HirKind::Capture(capture) => clauses_of(&capture.sub)?,
        HirKind::Concat(parts) => parts.iter().filter_map(clauses_of).flatten().collect(),
        HirKind::Alternation(branches) => {
            let mut any = 0u64;
            for branch in branches {
                any |= clauses_of(branch)?.into_iter().min_by_key(|c| weight(*c))?;
            }
            vec![any]
        }
    };
    if clauses.is_empty() {
        return None;
    }
    // Keep the strongest: a concatenation of many parts would otherwise grow
    // without bound up the tree.
    let mut clauses = clauses;
    clauses.sort_by_key(|c| (weight(*c), *c));
    clauses.dedup();
    clauses.truncate(MAX_CLAUSES);
    Some(clauses)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn need(pattern: &str) -> Option<Need> {
        let hir = regex_syntax::ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap();
        Need::of_regex(&hir)
    }

    fn may(pattern: &str, value: &[u8]) -> bool {
        need(pattern).is_none_or(|n| n.allows(classes(value)))
    }

    #[test]
    fn every_byte_has_one_class_and_punctuation_is_told_apart() {
        for b in 0..=255u8 {
            assert_eq!(TABLE[b as usize].count_ones(), 1, "{b}");
        }
        let punctuation: Vec<u8> = (0x21..=0x7e)
            .filter(|b: &u8| !b.is_ascii_alphanumeric())
            .collect();
        assert_eq!(punctuation.len(), 32);
        let mut seen = 0u64;
        for b in punctuation {
            assert_eq!(seen & TABLE[b as usize], 0, "{}", b as char);
            seen |= TABLE[b as usize];
        }
        assert_eq!(
            classes(b"a1 B"),
            1 << LOWER | 1 << DIGIT | 1 << SPACE | 1 << UPPER
        );
        assert_eq!(classes(b""), 0);
    }

    #[test]
    fn a_value_without_the_bytes_a_pattern_needs_is_ruled_out() {
        assert!(!may(r"[;|&]\s*cat", b"customer 12"));
        assert!(may(r"[;|&]\s*cat", b"a;cat"));
        assert!(!may(r"<script", b"script"));
        assert!(!may(r"(?i)<SCRIPT", b"<123"));
        assert!(may(r"(?i)<SCRIPT", b"<sCript"));
        assert!(!may(
            r"[\r\n]\W*?(?:content-type|location):",
            b"location: x"
        ));
        // An empty class matches nothing.
        assert!(!may(r"a[^\x00-\xff]", b"a"));
    }

    #[test]
    fn nothing_is_claimed_where_a_match_needs_no_particular_byte() {
        assert_eq!(need(r"^$"), None);
        assert_eq!(need(r"a*"), None);
        assert_eq!(need(r"(?:a|)"), None);
        // Any byte will do, but there must be one.
        assert!(may(r"(?s).+", b"\x00") && !may(r"(?s).+", b""));
        assert_eq!(need(r"\b"), None);
        // One branch can match the empty string: the alternation claims nothing,
        // but what follows it still does.
        assert!(need(r"(?:x|y?);").is_some_and(|n| n.clauses() == [TABLE[b';' as usize]]));
    }

    #[test]
    fn an_alternation_needs_what_one_of_its_branches_needs() {
        let n = need(r"(?:<a|%b|\(c)").unwrap();
        assert_eq!(n.clauses().len(), 1);
        for value in [&b"<a"[..], b"%b", b"(c"] {
            assert!(n.allows(classes(value)));
        }
        assert!(!n.allows(classes(b"abc")));
    }

    #[test]
    fn literals() {
        let n = Need::of_literal(b"a/b", false).unwrap();
        assert!(n.allows(classes(b"xa/b")) && !n.allows(classes(b"ab")));
        assert!(!Need::of_literal(b"A", false).unwrap().allows(classes(b"a")));
        assert!(Need::of_literal(b"A", true).unwrap().allows(classes(b"a")));
        assert_eq!(Need::of_literal(b"", false), None);
        let any = Need::of_any_literal([&b"<x"[..], b"y;"], true).unwrap();
        assert!(
            any.allows(classes(b"<")) && any.allows(classes(b";")) && !any.allows(classes(b"xy"))
        );
        assert_eq!(Need::of_any_literal([&b"a"[..], b""], true), None);
    }
}
