//! Detection operators (@detectSQLi, @detectXSS).
//!
//! Both are libinjection, through the project's fork of its Rust port
//! `libinjectionrs`: the CRS is written against libinjection's verdicts, so
//! anything else here is a source of false positives and misses. `differential/`
//! compares the two.

use super::traits::{Operator, OperatorResult};

/// Whether libinjection would read `value` as a single word or number: only
/// ASCII letters, digits and underscores, or nothing at all.
///
/// Such a value is one token, and the only one-token fingerprint libinjection
/// reports is the one for a token it could not parse, which those characters
/// cannot produce. Most values of most requests are of this kind (names,
/// identifiers, numbers), and answering here costs one pass over the bytes
/// instead of a tokenizer run. `differential/` checks the claim against the C
/// library.
fn is_one_plain_token(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// SQL injection detection operator (@detectSQLi).
pub struct DetectSqliOperator;

impl Operator for DetectSqliOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if is_one_plain_token(value) {
            return OperatorResult::no_match();
        }
        let result = libinjectionrs::detect_sqli(value.as_bytes());
        if result.is_injection() {
            // What matched is libinjection's fingerprint, as in ModSecurity.
            let fingerprint = result.fingerprint.map(|f| f.as_str().to_string());
            OperatorResult::matched(fingerprint.unwrap_or_default())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "detectSQLi"
    }
}

/// XSS detection operator (@detectXSS).
pub struct DetectXssOperator;

impl Operator for DetectXssOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if libinjectionrs::detect_xss(value.as_bytes()).is_injection() {
            // libinjection has no XSS fingerprint; what matched is the input.
            OperatorResult::matched(value.to_string())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "detectXSS"
    }
}
