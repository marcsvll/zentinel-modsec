//! Decoding transformations.
//!
//! All of them work on bytes, as ModSecurity's do: a decoded escape is the byte
//! it names, whatever bytes come before or after it. An escape that names a
//! code point above `FF` (`%uXXXX`, `\uXXXX`, `&#NNNN;`, a CSS escape) is where
//! the engines part: ModSecurity keeps the low byte, which is not what the
//! browser or the backend reads (`\u0127` is `ħ` to JavaScript, not `'`). Here
//! such an escape decodes to the character in UTF-8, after the best-fit table
//! (`urlDecodeUni`) and the full-width fold (`FF01` to `FF5E` are the ASCII
//! characters they stand for); one that names no character (a surrogate,
//! anything above `10FFFF`) gets ModSecurity's low byte.

use super::{is_c_space, is_hex, x2c, Transformation, UnicodeMap};
use crate::prefilter::classes_of;
use std::borrow::Cow;
use std::sync::Arc;

/// The value of up to `max` hexadecimal digits at the start of `bytes`, and
/// how many there were.
fn hex_prefix(bytes: &[u8], max: usize) -> (u32, usize) {
    let mut value = 0u32;
    let mut count = 0;
    while count < max && count < bytes.len() && is_hex(bytes[count]) {
        value = value * 16 + (bytes[count] as char).to_digit(16).unwrap_or(0);
        count += 1;
    }
    (value, count)
}

/// Write what an escape naming `code` decodes to (see the module's notes).
/// `low` is the byte ModSecurity would write.
fn push_code_point(out: &mut Vec<u8>, code: u32, low: u8) {
    if code <= 0xff {
        out.push(code as u8);
        return;
    }
    if (0xff01..=0xff5e).contains(&code) {
        out.push((code - 0xff00 + 0x20) as u8);
        return;
    }
    match char::from_u32(code) {
        Some(c) => {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
        None => out.push(low),
    }
}

/// URL decode transformation.
pub struct UrlDecode;

impl UrlDecode {
    /// Whether the transformation would leave `input` as it is, decided
    /// without building anything. Only `%` and `+` are decoded.
    fn untouched(input: &[u8]) -> bool {
        !input.iter().any(|&b| b == b'%' || b == b'+')
    }

    /// ModSecurity's non-strict decoding: `%XX` with two hexadecimal digits is
    /// the byte, any other `%` stays, and `+` is a space (CRS 932200 reads the
    /// space back through MATCHED_VARS).
    fn full(input: &[u8]) -> Cow<'_, [u8]> {
        let mut out = Vec::with_capacity(input.len());
        let mut i = 0;
        while i < input.len() {
            match input[i] {
                b'%' if i + 2 < input.len() && is_hex(input[i + 1]) && is_hex(input[i + 2]) => {
                    out.push(x2c(input[i + 1], input[i + 2]));
                    i += 3;
                }
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                b => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        Cow::Owned(out)
    }
}

impl Transformation for UrlDecode {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if Self::untouched(input) {
            return Cow::Borrowed(input);
        }
        Self::full(input)
    }

    fn name(&self) -> &'static str {
        "urlDecode"
    }

    fn touches(&self) -> Option<u64> {
        Some(classes_of(b"%+"))
    }
}

/// URL decode with Unicode support, `%uXXXX` read through the built-in
/// best-fit table ([`UnicodeMap::us_ascii`]).
pub struct UrlDecodeUni;

/// [`UrlDecodeUni`] with the table a `SecUnicodeMapFile` directive named.
pub struct UrlDecodeUniWith(pub Arc<UnicodeMap>);

impl Transformation for UrlDecodeUniWith {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if UrlDecode::untouched(input) {
            return Cow::Borrowed(input);
        }
        UrlDecodeUni::full(input, &self.0)
    }

    fn name(&self) -> &'static str {
        "urlDecodeUni"
    }

    fn touches(&self) -> Option<u64> {
        Some(classes_of(b"%+"))
    }
}

impl UrlDecodeUni {
    /// Decode `%XX`, `%uXXXX` and `+`, as ModSecurity does.
    ///
    /// An escape that is not well formed is not an escape: the `%` (and the
    /// `u`) is copied and decoding goes on with what follows, so `%u%27` is
    /// `%u'` and `%%27` is `%'`. Only hexadecimal digits count as digits (no
    /// sign).
    ///
    /// A `%uXXXX` up to `00FF` is that byte, unless the best-fit table folds
    /// it (`%u00AB` is `<`); above, what the table folds it to (`%u2019` is
    /// `'`), otherwise as the module says: `%uFF1Cscript%uFF1E` is
    /// `<script>`, `%u4E2D` is the character.
    fn full<'a>(input: &'a [u8], map: &UnicodeMap) -> Cow<'a, [u8]> {
        let mut out = Vec::with_capacity(input.len());
        let mut i = 0;
        while i < input.len() {
            match input[i] {
                b'%' if matches!(input.get(i + 1), Some(b'u' | b'U')) => {
                    if i + 5 < input.len() && input[i + 2..i + 6].iter().all(|&b| is_hex(b)) {
                        let (code, _) = hex_prefix(&input[i + 2..i + 6], 4);
                        match map.get(code) {
                            Some(byte) => out.push(byte),
                            None => {
                                push_code_point(&mut out, code, x2c(input[i + 4], input[i + 5]))
                            }
                        }
                        i += 6;
                    } else {
                        out.extend_from_slice(&input[i..i + 2]);
                        i += 2;
                    }
                }
                b'%' if i + 2 < input.len() && is_hex(input[i + 1]) && is_hex(input[i + 2]) => {
                    out.push(x2c(input[i + 1], input[i + 2]));
                    i += 3;
                }
                b'+' => {
                    // An encoded space, as for urlDecode.
                    out.push(b' ');
                    i += 1;
                }
                b => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        Cow::Owned(out)
    }
}

impl Transformation for UrlDecodeUni {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if UrlDecode::untouched(input) {
            return Cow::Borrowed(input);
        }
        Self::full(input, &UnicodeMap::us_ascii())
    }

    fn name(&self) -> &'static str {
        "urlDecodeUni"
    }

    fn touches(&self) -> Option<u64> {
        Some(classes_of(b"%+"))
    }
}

/// Base64 decode transformation.
///
/// As ModSecurity (mbedTLS): the value up to its first NUL must be valid
/// base64, padding included, or it is left as it is.
pub struct Base64Decode;

impl Transformation for Base64Decode {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        use base64::Engine;
        let text = input.split(|&b| b == 0).next().unwrap_or_default();
        // Most values are not base64 and are told apart without decoding:
        // canonical base64 comes in groups of four characters of its alphabet.
        let alphabet = |b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=');
        if text.is_empty() || text.len() % 4 != 0 || !text.iter().all(alphabet) {
            return Cow::Borrowed(input);
        }
        match base64::engine::general_purpose::STANDARD.decode(text) {
            Ok(bytes) => Cow::Owned(bytes),
            Err(_) => Cow::Borrowed(input),
        }
    }

    fn name(&self) -> &'static str {
        "base64Decode"
    }
}

/// Base64 decoding that forgives what it does not understand
/// (`base64DecodeExt`), as ModSecurity does: characters outside the alphabet
/// are skipped, `-` and `_` count as `+` and `/`, and decoding stops making
/// sense only at a padding character in the wrong place.
pub struct Base64DecodeExt;

impl Base64DecodeExt {
    fn sextet(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }

    /// `decode_forgiven_engine` of libmodsecurity, which gives up (and leaves
    /// an empty value) on a single padding character after one digit of a group.
    fn decode(input: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(input.len() * 3 / 4 + 1);
        let mut i = 0usize;
        let mut last_was_pad = false;
        for (at, &b) in input.iter().enumerate() {
            if b == b'=' {
                last_was_pad = true;
                if input.get(at + 1) != Some(&b'=') && i % 4 == 1 {
                    return Vec::new();
                }
                continue;
            }
            let Some(v) = Self::sextet(b) else {
                // Whitespace and anything else outside the alphabet.
                continue;
            };
            last_was_pad = false;
            match i % 4 {
                0 => out.push(v << 2),
                1 => {
                    if let Some(last) = out.last_mut() {
                        *last |= v >> 4;
                    }
                    out.push((v & 0x0f) << 4);
                }
                2 => {
                    if let Some(last) = out.last_mut() {
                        *last |= v >> 2;
                    }
                    out.push((v & 0x03) << 6);
                }
                _ => {
                    if let Some(last) = out.last_mut() {
                        *last |= v;
                    }
                }
            }
            i += 1;
        }
        // The byte being assembled is only part of the output once complete.
        if !i.is_multiple_of(4) {
            out.pop();
        }
        if last_was_pad && i % 4 == 1 {
            return Vec::new();
        }
        out
    }
}

impl Transformation for Base64DecodeExt {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if input.is_empty() {
            return Cow::Borrowed(input);
        }
        Cow::Owned(Self::decode(input))
    }

    fn name(&self) -> &'static str {
        "base64DecodeExt"
    }
}

/// Hex decode transformation.
///
/// As ModSecurity: every pair of characters is read as two hexadecimal digits,
/// whatever they are, and an odd character at the end is dropped.
pub struct HexDecode;

impl Transformation for HexDecode {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if input.is_empty() {
            return Cow::Borrowed(input);
        }
        Cow::Owned(
            input
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&[h, l]| x2c(h, l))
                .collect(),
        )
    }

    fn name(&self) -> &'static str {
        "hexDecode"
    }
}

/// HTML entity decode transformation.
pub struct HtmlEntityDecode;

/// The named entities ModSecurity decodes: every one the HTML specification
/// expands to a single character up to `7F`, plus `nbsp` and `shy`, compared
/// without regard to case (libmodsecurity's generated table).
const NAMED_ENTITIES: &[(&str, u8)] = &[
    ("amp", b'&'),
    ("apos", b'\''),
    ("ast", b'*'),
    ("bsol", b'\\'),
    ("colon", b':'),
    ("comma", b','),
    ("commat", b'@'),
    ("diacriticalgrave", b'`'),
    ("dollar", b'$'),
    ("equals", b'='),
    ("excl", b'!'),
    ("grave", b'`'),
    ("gt", b'>'),
    ("hat", b'^'),
    ("lbrace", b'{'),
    ("lbrack", b'['),
    ("lcub", b'{'),
    ("lowbar", b'_'),
    ("lpar", b'('),
    ("lsqb", b'['),
    ("lt", b'<'),
    ("midast", b'*'),
    ("nbsp", 0xa0),
    ("newline", b'\n'),
    ("nonbreakingspace", 0xa0),
    ("num", b'#'),
    ("percnt", b'%'),
    ("period", b'.'),
    ("plus", b'+'),
    ("quest", b'?'),
    ("quot", b'"'),
    ("rbrace", b'}'),
    ("rbrack", b']'),
    ("rcub", b'}'),
    ("rpar", b')'),
    ("rsqb", b']'),
    ("semi", b';'),
    ("shy", 0xad),
    ("sol", b'/'),
    ("tab", b'\t'),
    ("underbar", b'_'),
    ("verbar", b'|'),
    ("vert", b'|'),
    ("verticalline", b'|'),
];

impl HtmlEntityDecode {
    fn untouched(input: &[u8]) -> bool {
        !input.contains(&b'&')
    }

    /// `&#NNN;`, `&#xHH;` and the named entities, as ModSecurity reads them:
    /// the semicolon is optional, an entity with no digit or an unknown name
    /// stays as written.
    fn full(input: &[u8]) -> Cow<'_, [u8]> {
        let mut out = Vec::with_capacity(input.len());
        let mut i = 0;
        while i < input.len() {
            if input[i] != b'&' || i + 1 >= input.len() {
                out.push(input[i]);
                i += 1;
                continue;
            }
            let mut j = i + 1;
            let decoded = if input[j] == b'#' {
                j += 1;
                let hex = matches!(input.get(j), Some(b'x' | b'X'));
                if hex {
                    j += 1;
                }
                let start = j;
                while j < input.len()
                    && (if hex {
                        is_hex(input[j])
                    } else {
                        input[j].is_ascii_digit()
                    })
                {
                    j += 1;
                }
                (j > start).then(|| {
                    let digits = std::str::from_utf8(&input[start..j]).unwrap_or("0");
                    let code =
                        u32::from_str_radix(digits, if hex { 16 } else { 10 }).unwrap_or(u32::MAX);
                    let mut bytes = Vec::with_capacity(4);
                    // strtol saturates; its low byte is then FF.
                    let low = if code == u32::MAX { 0xff } else { code as u8 };
                    push_code_point(&mut bytes, code, low);
                    bytes
                })
            } else {
                while j < input.len() && input[j].is_ascii_alphanumeric() {
                    j += 1;
                }
                let name = &input[i + 1..j];
                NAMED_ENTITIES
                    .iter()
                    .find(|(n, _)| n.as_bytes().eq_ignore_ascii_case(name))
                    .map(|&(_, b)| vec![b])
            };
            match decoded {
                Some(bytes) => {
                    out.extend_from_slice(&bytes);
                    i = if input.get(j) == Some(&b';') {
                        j + 1
                    } else {
                        j
                    };
                }
                None => {
                    // Not an entity: what was read is copied and decoding goes
                    // on after it.
                    out.extend_from_slice(&input[i..j]);
                    i = j;
                }
            }
        }
        Cow::Owned(out)
    }
}

impl Transformation for HtmlEntityDecode {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if Self::untouched(input) {
            return Cow::Borrowed(input);
        }
        Self::full(input)
    }

    fn name(&self) -> &'static str {
        "htmlEntityDecode"
    }

    fn touches(&self) -> Option<u64> {
        Some(classes_of(b"&"))
    }
}

/// JavaScript decode transformation.
pub struct JsDecode;

impl JsDecode {
    /// Whether the transformation would leave `input` as it is, decided
    /// without building anything. Only a backslash starts an escape.
    fn untouched(input: &[u8]) -> bool {
        !input.contains(&b'\\')
    }

    /// As ModSecurity: `\uHHHH`, `\xHH`, `\OOO` (up to three octal digits
    /// that fit a byte), the C escapes `\a \b \f \n \r \t \v`, and any other
    /// escaped character without its backslash. A backslash that ends the
    /// input stays.
    fn full(input: &[u8]) -> Cow<'_, [u8]> {
        let mut out = Vec::with_capacity(input.len());
        let mut i = 0;
        while i < input.len() {
            if input[i] != b'\\' {
                out.push(input[i]);
                i += 1;
                continue;
            }
            let rest = &input[i + 1..];
            if rest.len() >= 5 && rest[0] == b'u' && rest[1..5].iter().all(|&b| is_hex(b)) {
                let (code, _) = hex_prefix(&rest[1..5], 4);
                push_code_point(&mut out, code, x2c(rest[3], rest[4]));
                i += 6;
            } else if rest.len() >= 3 && rest[0] == b'x' && is_hex(rest[1]) && is_hex(rest[2]) {
                out.push(x2c(rest[1], rest[2]));
                i += 4;
            } else if rest.first().is_some_and(|b| (b'0'..=b'7').contains(b)) {
                let mut len = rest
                    .iter()
                    .take(3)
                    .take_while(|b| (b'0'..=b'7').contains(*b))
                    .count();
                // Three digits only when they fit a byte.
                if len == 3 && rest[0] > b'3' {
                    len = 2;
                }
                let value = rest[..len]
                    .iter()
                    .fold(0u32, |v, &d| v * 8 + u32::from(d - b'0'));
                out.push(value as u8);
                i += 1 + len;
            } else if let Some(&c) = rest.first() {
                out.push(match c {
                    b'a' => 0x07,
                    b'b' => 0x08,
                    b'f' => 0x0c,
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'v' => 0x0b,
                    other => other,
                });
                i += 2;
            } else {
                out.push(b'\\');
                i += 1;
            }
        }
        Cow::Owned(out)
    }
}

impl Transformation for JsDecode {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if Self::untouched(input) {
            return Cow::Borrowed(input);
        }
        Self::full(input)
    }

    fn name(&self) -> &'static str {
        "jsDecode"
    }

    fn touches(&self) -> Option<u64> {
        Some(classes_of(b"\\"))
    }
}

/// CSS decode transformation.
pub struct CssDecode;

impl CssDecode {
    /// Whether the transformation would leave `input` as it is, decided
    /// without building anything. Only a backslash starts an escape.
    fn untouched(input: &[u8]) -> bool {
        !input.contains(&b'\\')
    }

    /// As ModSecurity: `\` and one to six hexadecimal digits is the character
    /// they name (a single whitespace after them belongs to the escape), a
    /// backslash before a newline or at the end of the input is dropped, and
    /// any other escaped character loses its backslash.
    fn full(input: &[u8]) -> Cow<'_, [u8]> {
        let mut out = Vec::with_capacity(input.len());
        let mut i = 0;
        while i < input.len() {
            if input[i] != b'\\' {
                out.push(input[i]);
                i += 1;
                continue;
            }
            i += 1;
            let Some(&next) = input.get(i) else {
                break;
            };
            let (code, digits) = hex_prefix(&input[i..], 6);
            if digits > 0 {
                let low = if digits == 1 {
                    code as u8
                } else {
                    x2c(input[i + digits - 2], input[i + digits - 1])
                };
                push_code_point(&mut out, code, low);
                i += digits;
                if input.get(i).is_some_and(|b| is_c_space(*b)) {
                    i += 1;
                }
            } else if next == b'\n' {
                i += 1;
            } else {
                out.push(next);
                i += 1;
            }
        }
        Cow::Owned(out)
    }
}

impl Transformation for CssDecode {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if Self::untouched(input) {
            return Cow::Borrowed(input);
        }
        Self::full(input)
    }

    fn name(&self) -> &'static str {
        "cssDecode"
    }

    fn touches(&self) -> Option<u64> {
        Some(classes_of(b"\\"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(tr: &dyn Transformation, input: &[u8]) -> Vec<u8> {
        tr.transform(input).into_owned()
    }

    /// The shortcut of each transformation only ever answers for inputs the
    /// full transformation leaves as they are, and it does answer for an
    /// ordinary value.
    #[test]
    fn test_untouched_implies_unchanged() {
        type Check = (&'static str, fn(&[u8]) -> bool, fn(&[u8]) -> Cow<'_, [u8]>);
        let checks: [Check; 5] = [
            ("UrlDecode", UrlDecode::untouched, UrlDecode::full),
            ("UrlDecodeUni", UrlDecode::untouched, |input| {
                UrlDecodeUni::full(input, &UnicodeMap::us_ascii())
            }),
            (
                "HtmlEntityDecode",
                HtmlEntityDecode::untouched,
                HtmlEntityDecode::full,
            ),
            ("JsDecode", JsDecode::untouched, JsDecode::full),
            ("CssDecode", CssDecode::untouched, CssDecode::full),
        ];
        let inputs = crate::transformations::short_inputs();
        for (name, untouched, full) in checks {
            assert!(untouched(b"ordinaryvalue123"), "{name}");
            let mut taken = 0;
            for input in &inputs {
                if untouched(input) {
                    taken += 1;
                    assert_eq!(
                        full(input).as_ref(),
                        input.as_slice(),
                        "{name} on {input:?}"
                    );
                }
            }
            assert!(taken > 0, "{name}");
        }
    }

    #[test]
    fn test_url_decode() {
        assert_eq!(t(&UrlDecode, b"hello%20world"), b"hello world");
        assert_eq!(t(&UrlDecode, b"test%2Fpath"), b"test/path");
        // The byte an escape names, whether or not it is UTF-8 (CRS 944200's
        // Java serialization magic).
        assert_eq!(t(&UrlDecode, b"%ac%ED%00%05"), b"\xac\xed\x00\x05");
        assert_eq!(t(&UrlDecode, b"%e9t%C3%A9"), b"\xe9t\xc3\xa9");
        // A malformed escape stays.
        assert_eq!(t(&UrlDecode, b"%zz%4"), b"%zz%4");
    }

    #[test]
    fn plus_is_a_space_in_both_url_decoders() {
        // ModSecurity's urlDecode and urlDecodeUni both turn `+` into a space;
        // an encoded plus (`%2B`) stays a plus.
        for tr in [&UrlDecode as &dyn Transformation, &UrlDecodeUni] {
            assert_eq!(t(tr, b"a+b"), b"a b", "{}", tr.name());
            assert_eq!(t(tr, b"a%2Bb"), b"a+b", "{}", tr.name());
            assert_eq!(t(tr, b"c%24%40at%2B%2Fet"), b"c$@at+/et", "{}", tr.name());
            // Applied to an already decoded argument (what CRS does with
            // t:urlDecodeUni on ARGS), the plus becomes the space the rule
            // looks for.
            assert_eq!(t(tr, b"c$@at+/et$@c"), b"c$@at /et$@c", "{}", tr.name());
        }
        assert_eq!(t(&UrlDecodeUni, b"%u0041+b"), b"A b");
    }

    #[test]
    fn test_url_decode_uni_leaves_a_malformed_escape_and_goes_on() {
        let tr = UrlDecodeUni;
        // The escape after a malformed one is still decoded (S11): these used
        // to swallow the `%27` into the malformed escape and hide the quote.
        assert_eq!(t(&tr, b"%u%27"), b"%u'");
        assert_eq!(t(&tr, b"%%27"), b"%'");
        assert_eq!(t(&tr, b"%u00%27"), b"%u00'");
        assert_eq!(t(&tr, b"%2%27"), b"%2'");
        // A sign is not a hexadecimal digit.
        assert_eq!(t(&tr, b"%+4"), b"% 4");
        assert_eq!(t(&tr, b"%-4"), b"%-4");
        assert_eq!(t(&tr, b"%u+041"), b"%u 041");
        // Cut short at the end of the input.
        assert_eq!(t(&tr, b"a%"), b"a%");
        assert_eq!(t(&tr, b"a%4"), b"a%4");
        assert_eq!(t(&tr, b"a%u004"), b"a%u004");
        // A surrogate names no character: ModSecurity's low byte.
        assert_eq!(t(&tr, b"%ud800"), b"\x00");
        // Well-formed escapes, either case.
        assert_eq!(t(&tr, b"%41%u0042%U0043"), b"ABC");
        // What the best-fit table folds decodes folded; above FF the rest is
        // the character, up to FF the byte.
        assert_eq!(t(&tr, b"%u00e9"), b"e");
        assert_eq!(t(&tr, b"%u4e2d"), "\u{4e2d}".as_bytes());
        assert_eq!(t(&tr, b"%e9"), b"\xe9");
        assert_eq!(t(&tr, b"%u0080"), b"\x80");
    }

    #[test]
    fn test_url_decode_uni_folds_full_width_forms_to_ascii() {
        let tr = UrlDecodeUni;
        assert_eq!(t(&tr, b"%uFF1Cscript%uff1e"), b"<script>");
        assert_eq!(t(&tr, b"%uff01%uff5e"), b"!~");
        // Outside the full-width block nothing is folded.
        assert_eq!(t(&tr, b"%uff00"), "\u{ff00}".as_bytes());
        assert_eq!(t(&tr, b"%uff5f"), "\u{ff5f}".as_bytes());
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(t(&Base64Decode, b"aGVsbG8="), b"hello");
        assert_eq!(t(&Base64Decode, b"rO0ABQ=="), b"\xac\xed\x00\x05");
        assert_eq!(t(&Base64Decode, b"not base64!"), b"not base64!");
    }

    #[test]
    fn test_hex_decode() {
        assert_eq!(t(&HexDecode, b"414243"), b"ABC");
        assert_eq!(t(&HexDecode, b"aced0005"), b"\xac\xed\x00\x05");
    }

    #[test]
    fn test_html_entity_decode() {
        assert_eq!(t(&HtmlEntityDecode, b"&lt;script&gt;"), b"<script>");
        assert_eq!(t(&HtmlEntityDecode, b"&#60;&#x3C"), b"<<");
        assert_eq!(t(&HtmlEntityDecode, b"&#233;&nbsp;"), b"\xe9\xa0");
        assert_eq!(t(&HtmlEntityDecode, b"&#x2019;"), "\u{2019}".as_bytes());
        assert_eq!(t(&HtmlEntityDecode, b"&ltest;&foo;&#;"), b"&ltest;&foo;&#;");
    }

    #[test]
    fn test_js_decode() {
        assert_eq!(t(&JsDecode, br"\x3cscript\x3e"), b"<script>");
        assert_eq!(t(&JsDecode, br"\u003c\uff1c"), b"<<");
        assert_eq!(t(&JsDecode, br"\xac\xed\0\5"), b"\xac\xed\x00\x05");
        assert_eq!(t(&JsDecode, br"\u0127"), "\u{127}".as_bytes());
        assert_eq!(t(&JsDecode, br"\q\x\u"), b"qxu");
    }

    #[test]
    fn test_css_decode() {
        assert_eq!(t(&CssDecode, br"\3c script\3E"), b"<script>");
        assert_eq!(t(&CssDecode, br"\ff1c"), b"<");
        assert_eq!(t(&CssDecode, br"\e9 t"), b"\xe9t");
        assert_eq!(t(&CssDecode, b"a\\\nb\\"), b"ab");
    }
}
