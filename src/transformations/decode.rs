//! Decoding transformations.

use super::Transformation;
use std::borrow::Cow;

/// URL decode transformation.
pub struct UrlDecode;

impl Transformation for UrlDecode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        // `+` is an encoded space in a query string, and ModSecurity decodes
        // it here too (CRS 932200 reads the space back through MATCHED_VARS).
        if input.contains('+') {
            let spaced = input.replace('+', " ");
            return match percent_encoding::percent_decode_str(&spaced).decode_utf8() {
                Ok(decoded) => Cow::Owned(decoded.into_owned()),
                Err(_) => Cow::Owned(spaced),
            };
        }
        match percent_encoding::percent_decode_str(input).decode_utf8() {
            Ok(decoded) => {
                if decoded == input {
                    Cow::Borrowed(input)
                } else {
                    Cow::Owned(decoded.into_owned())
                }
            }
            Err(_) => Cow::Borrowed(input),
        }
    }

    fn name(&self) -> &'static str {
        "urlDecode"
    }
}

/// URL decode with Unicode support.
pub struct UrlDecodeUni;

impl UrlDecodeUni {
    /// Whether the transformation would leave `input` as it is, decided
    /// without building anything. Only `%` and `+` are decoded.
    fn untouched(input: &str) -> bool {
        !input.contains(['%', '+'])
    }

    /// Decode `%XX`, `%uXXXX` and `+`, as ModSecurity does.
    ///
    /// An escape that is not well formed is not an escape: the `%` is copied
    /// and decoding goes on with the character after it, so `%u%27` is `%u'`
    /// and `%%27` is `%'`. Only hexadecimal digits count as digits (no sign).
    ///
    /// `%uFF01` to `%uFF5E`, the full-width forms, decode to the ASCII
    /// characters they stand for (ModSecurity adds 0x20 to the low byte), so
    /// `%uFF1Cscript%uFF1E` is `<script>`: a backend that normalizes them sees
    /// ASCII, and so must the rules.
    fn full<'a>(input: &'a str) -> Cow<'a, str> {
        let chars: Vec<char> = input.chars().collect();
        let mut result = String::with_capacity(input.len());
        let mut modified = false;
        let mut i = 0;

        while i < chars.len() {
            match chars[i] {
                '%' => {
                    let unicode = matches!(chars.get(i + 1), Some('u' | 'U'))
                        .then(|| hex_digits(&chars[i + 2..], 4))
                        .flatten()
                        .and_then(|code| match code {
                            0xff01..=0xff5e => char::from_u32(code - 0xff00 + 0x20),
                            // A surrogate is not a character: left as written.
                            _ => char::from_u32(code),
                        });
                    if let Some(decoded) = unicode {
                        result.push(decoded);
                        modified = true;
                        i += 6;
                    } else if let Some(byte) = hex_digits(&chars[i + 1..], 2) {
                        result.push(byte as u8 as char);
                        modified = true;
                        i += 3;
                    } else {
                        result.push('%');
                        i += 1;
                    }
                }
                '+' => {
                    // An encoded space, as for urlDecode.
                    result.push(' ');
                    modified = true;
                    i += 1;
                }
                c => {
                    result.push(c);
                    i += 1;
                }
            }
        }

        if modified {
            Cow::Owned(result)
        } else {
            Cow::Borrowed(input)
        }
    }
}

/// The value of the first `count` characters read as hexadecimal digits, or
/// `None` when there are fewer or one of them is not a digit.
fn hex_digits(chars: &[char], count: usize) -> Option<u32> {
    let digits = chars.get(..count)?;
    digits
        .iter()
        .try_fold(0u32, |value, c| Some(value * 16 + c.to_digit(16)?))
}

impl Transformation for UrlDecodeUni {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if Self::untouched(input) {
            return Cow::Borrowed(input);
        }
        Self::full(input)
    }

    fn name(&self) -> &'static str {
        "urlDecodeUni"
    }
}

/// Base64 decode transformation.
pub struct Base64Decode;

impl Transformation for Base64Decode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        use base64::Engine;
        match base64::engine::general_purpose::STANDARD.decode(input) {
            Ok(bytes) => Cow::Owned(String::from_utf8_lossy(&bytes).into_owned()),
            Err(_) => Cow::Borrowed(input),
        }
    }

    fn name(&self) -> &'static str {
        "base64Decode"
    }
}

/// Extended base64 decode (handles URL-safe base64).
pub struct Base64DecodeExt;

impl Transformation for Base64DecodeExt {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        use base64::Engine;
        // Try URL-safe first, then standard
        let result = base64::engine::general_purpose::URL_SAFE
            .decode(input)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(input));

        match result {
            Ok(bytes) => Cow::Owned(String::from_utf8_lossy(&bytes).into_owned()),
            Err(_) => Cow::Borrowed(input),
        }
    }

    fn name(&self) -> &'static str {
        "base64DecodeExt"
    }
}

/// Hex decode transformation.
pub struct HexDecode;

impl Transformation for HexDecode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut result = Vec::new();
        let mut chars = input.chars().peekable();

        while let Some(c1) = chars.next() {
            if let Some(c2) = chars.next() {
                let hex = format!("{}{}", c1, c2);
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte);
                } else {
                    // Invalid hex, keep original
                    return Cow::Borrowed(input);
                }
            } else {
                // Odd number of chars
                return Cow::Borrowed(input);
            }
        }

        Cow::Owned(String::from_utf8_lossy(&result).into_owned())
    }

    fn name(&self) -> &'static str {
        "hexDecode"
    }
}

/// HTML entity decode transformation.
pub struct HtmlEntityDecode;

impl Transformation for HtmlEntityDecode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let decoded = html_escape::decode_html_entities(input);
        if decoded == input {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(decoded.into_owned())
        }
    }

    fn name(&self) -> &'static str {
        "htmlEntityDecode"
    }
}

/// JavaScript decode transformation.
pub struct JsDecode;

impl JsDecode {
    /// Whether the transformation would leave `input` as it is, decided
    /// without building anything. Only a backslash starts an escape.
    fn untouched(input: &str) -> bool {
        !input.contains('\\')
    }

    fn full<'a>(input: &'a str) -> Cow<'a, str> {
        let mut result = String::new();
        let mut chars = input.chars().peekable();
        let mut modified = false;

        while let Some(c) = chars.next() {
            if c == '\\' {
                modified = true;
                match chars.next() {
                    Some('n') => result.push('\n'),
                    Some('r') => result.push('\r'),
                    Some('t') => result.push('\t'),
                    Some('\\') => result.push('\\'),
                    Some('"') => result.push('"'),
                    Some('\'') => result.push('\''),
                    Some('x') => {
                        // \xHH
                        let mut hex = String::new();
                        for _ in 0..2 {
                            if let Some(h) = chars.next() {
                                hex.push(h);
                            }
                        }
                        if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                            result.push(byte as char);
                        } else {
                            result.push('\\');
                            result.push('x');
                            result.push_str(&hex);
                        }
                    }
                    Some('u') => {
                        // \uHHHH
                        let mut hex = String::new();
                        for _ in 0..4 {
                            if let Some(h) = chars.next() {
                                hex.push(h);
                            }
                        }
                        if let Ok(code) = u32::from_str_radix(&hex, 16) {
                            if let Some(decoded) = char::from_u32(code) {
                                result.push(decoded);
                            } else {
                                result.push('\\');
                                result.push('u');
                                result.push_str(&hex);
                            }
                        } else {
                            result.push('\\');
                            result.push('u');
                            result.push_str(&hex);
                        }
                    }
                    Some(other) => {
                        result.push('\\');
                        result.push(other);
                    }
                    None => result.push('\\'),
                }
            } else {
                result.push(c);
            }
        }

        if modified {
            Cow::Owned(result)
        } else {
            Cow::Borrowed(input)
        }
    }
}

impl Transformation for JsDecode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if Self::untouched(input) {
            return Cow::Borrowed(input);
        }
        Self::full(input)
    }

    fn name(&self) -> &'static str {
        "jsDecode"
    }
}

/// CSS decode transformation.
pub struct CssDecode;

impl CssDecode {
    /// Whether the transformation would leave `input` as it is, decided
    /// without building anything. Only a backslash starts an escape.
    fn untouched(input: &str) -> bool {
        !input.contains('\\')
    }

    fn full<'a>(input: &'a str) -> Cow<'a, str> {
        let mut result = String::new();
        let mut chars = input.chars().peekable();
        let mut modified = false;

        while let Some(c) = chars.next() {
            if c == '\\' {
                modified = true;
                // CSS escape: \HH or \HHHHHH
                let mut hex = String::new();
                while hex.len() < 6 {
                    match chars.peek() {
                        Some(h) if h.is_ascii_hexdigit() => {
                            hex.push(chars.next().unwrap());
                        }
                        _ => break,
                    }
                }
                // Skip optional whitespace after hex
                if let Some(' ') | Some('\t') | Some('\n') = chars.peek() {
                    chars.next();
                }

                if !hex.is_empty() {
                    if let Ok(code) = u32::from_str_radix(&hex, 16) {
                        if let Some(decoded) = char::from_u32(code) {
                            result.push(decoded);
                            continue;
                        }
                    }
                }
                result.push('\\');
                result.push_str(&hex);
            } else {
                result.push(c);
            }
        }

        if modified {
            Cow::Owned(result)
        } else {
            Cow::Borrowed(input)
        }
    }
}

impl Transformation for CssDecode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if Self::untouched(input) {
            return Cow::Borrowed(input);
        }
        Self::full(input)
    }

    fn name(&self) -> &'static str {
        "cssDecode"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shortcut of each transformation only ever answers for inputs the
    /// full transformation leaves as they are, and it does answer for an
    /// ordinary value.
    #[test]
    fn test_untouched_implies_unchanged() {
        type Check = (&'static str, fn(&str) -> bool, fn(&str) -> Cow<'_, str>);
        let checks: [Check; 3] = [
            ("UrlDecodeUni", UrlDecodeUni::untouched, UrlDecodeUni::full),
            ("JsDecode", JsDecode::untouched, JsDecode::full),
            ("CssDecode", CssDecode::untouched, CssDecode::full),
        ];
        let inputs = crate::transformations::short_inputs();
        for (name, untouched, full) in checks {
            assert!(untouched("ordinaryvalue123"), "{name}");
            let mut taken = 0;
            for input in &inputs {
                if untouched(input) {
                    taken += 1;
                    assert_eq!(full(input), input.as_str(), "{name} on {input:?}");
                }
            }
            assert!(taken > 0, "{name}");
        }
    }

    #[test]
    fn test_url_decode() {
        let t = UrlDecode;
        assert_eq!(t.transform("hello%20world"), "hello world");
        assert_eq!(t.transform("test%2Fpath"), "test/path");
    }

    #[test]
    fn plus_is_a_space_in_both_url_decoders() {
        // ModSecurity's urlDecode and urlDecodeUni both turn `+` into a space;
        // an encoded plus (`%2B`) stays a plus.
        for t in [&UrlDecode as &dyn Transformation, &UrlDecodeUni] {
            assert_eq!(t.transform("a+b"), "a b", "{}", t.name());
            assert_eq!(t.transform("a%2Bb"), "a+b", "{}", t.name());
            assert_eq!(
                t.transform("c%24%40at%2B%2Fet"),
                "c$@at+/et",
                "{}",
                t.name()
            );
            // Applied to an already decoded argument (what CRS does with
            // t:urlDecodeUni on ARGS), the plus becomes the space the rule
            // looks for.
            assert_eq!(t.transform("c$@at+/et$@c"), "c$@at /et$@c", "{}", t.name());
        }
        assert_eq!(UrlDecodeUni.transform("%u0041+b"), "A b");
    }

    #[test]
    fn test_url_decode_uni_leaves_a_malformed_escape_and_goes_on() {
        let t = UrlDecodeUni;
        // The escape after a malformed one is still decoded (S11): these used
        // to swallow the `%27` into the malformed escape and hide the quote.
        assert_eq!(t.transform("%u%27"), "%u'");
        assert_eq!(t.transform("%%27"), "%'");
        assert_eq!(t.transform("%u00%27"), "%u00'");
        assert_eq!(t.transform("%2%27"), "%2'");
        // A sign is not a hexadecimal digit.
        assert_eq!(t.transform("%+4"), "% 4");
        assert_eq!(t.transform("%-4"), "%-4");
        assert_eq!(t.transform("%u+041"), "%u 041");
        // Cut short at the end of the input.
        assert_eq!(t.transform("a%"), "a%");
        assert_eq!(t.transform("a%4"), "a%4");
        assert_eq!(t.transform("a%u004"), "a%u004");
        // A surrogate is not a character; the escape stays as written.
        assert_eq!(t.transform("%ud800"), "%ud800");
        // Well-formed escapes, either case.
        assert_eq!(t.transform("%41%u0042%U0043"), "ABC");
        assert_eq!(t.transform("%u00e9"), "\u{e9}");
        assert_eq!(t.transform("%e9"), "\u{e9}");
    }

    #[test]
    fn test_url_decode_uni_folds_full_width_forms_to_ascii() {
        let t = UrlDecodeUni;
        assert_eq!(t.transform("%uFF1Cscript%uff1e"), "<script>");
        assert_eq!(t.transform("%uff01%uff5e"), "!~");
        // Outside the full-width block nothing is folded.
        assert_eq!(t.transform("%uff00"), "\u{ff00}");
        assert_eq!(t.transform("%uff5f"), "\u{ff5f}");
    }

    #[test]
    fn test_base64_decode() {
        let t = Base64Decode;
        assert_eq!(t.transform("aGVsbG8="), "hello");
    }

    #[test]
    fn test_html_entity_decode() {
        let t = HtmlEntityDecode;
        assert_eq!(t.transform("&lt;script&gt;"), "<script>");
        assert_eq!(t.transform("&#60;"), "<");
    }

    #[test]
    fn test_js_decode() {
        let t = JsDecode;
        assert_eq!(t.transform(r"\x3cscript\x3e"), "<script>");
        assert_eq!(t.transform(r"\u003c"), "<");
    }
}
