//! Validation operators (@validateUrlEncoding, @validateUtf8Encoding).

use super::traits::{Operator, OperatorResult};

/// URL encoding validation operator (@validateUrlEncoding).
pub struct ValidateUrlEncodingOperator;

impl Operator for ValidateUrlEncodingOperator {
    fn execute(&self, value: &[u8]) -> OperatorResult {
        if is_valid_url_encoding(value) {
            OperatorResult::no_match() // Valid encoding = no match (not an attack)
        } else {
            OperatorResult::matched("invalid URL encoding".to_string())
        }
    }

    fn name(&self) -> &'static str {
        "validateUrlEncoding"
    }
}

/// UTF-8 encoding validation operator (@validateUtf8Encoding).
pub struct ValidateUtf8EncodingOperator;

impl Operator for ValidateUtf8EncodingOperator {
    fn execute(&self, value: &[u8]) -> OperatorResult {
        // ModSecurity's check is UTF-8 itself (RFC 3629): no stray
        // continuation byte, no truncated sequence, no overlong form, no
        // surrogate, nothing above U+10FFFF. A NUL is a character.
        if std::str::from_utf8(value).is_ok() {
            OperatorResult::no_match()
        } else {
            OperatorResult::matched("invalid UTF-8 encoding".to_string())
        }
    }

    fn name(&self) -> &'static str {
        "validateUtf8Encoding"
    }
}

/// Check if a string has valid URL encoding.
/// Every `%` is followed by two hexadecimal digits.
fn is_valid_url_encoding(value: &[u8]) -> bool {
    let mut i = 0;
    while i < value.len() {
        if value[i] == b'%' {
            match value.get(i + 1..i + 3) {
                Some([h, l]) if h.is_ascii_hexdigit() && l.is_ascii_hexdigit() => i += 3,
                _ => return false,
            }
        } else {
            i += 1;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_url_encoding() {
        assert!(is_valid_url_encoding(b"hello%20world"));
        assert!(is_valid_url_encoding(b"test%2Fpath"));
        assert!(!is_valid_url_encoding(b"hello%2"));
        assert!(!is_valid_url_encoding(b"hello%GG"));
    }

    #[test]
    fn test_validate_url_encoding_operator() {
        let op = ValidateUrlEncodingOperator;
        assert!(!op.execute(b"hello%20world").matched); // Valid = no match
        assert!(op.execute(b"hello%2").matched); // Invalid = match
    }

    #[test]
    fn test_validate_utf8_encoding_operator() {
        let op = ValidateUtf8EncodingOperator;
        assert!(!op.execute("caf\u{e9}\0".as_bytes()).matched);
        for invalid in [
            &b"\xe9"[..],
            b"\xc0\xaf",
            b"\xed\xa0\x80",
            b"\xf5\x80\x80\x80",
            b"\xe2\x82",
        ] {
            assert!(op.execute(invalid).matched, "{invalid:?}");
        }
    }
}
