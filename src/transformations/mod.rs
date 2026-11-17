//! Transformation functions for ModSecurity.
//!
//! A transformation takes bytes and gives bytes, as in ModSecurity: request
//! data is not text until something proves it is, and an encoded byte that is
//! not UTF-8 (`%AC%ED`, `\xff`) is what a rule may be looking for.

mod decode;
mod encode;
mod normalize;
mod pipeline;
mod unicode_map;

pub use decode::*;
pub use encode::*;
pub use normalize::*;
pub use pipeline::TransformationPipeline;
pub use unicode_map::{UnicodeMap, US_ASCII_CODE_PAGE};

use crate::error::{Error, Result};
use std::borrow::Cow;
use std::sync::Arc;

/// Trait for transformations.
pub trait Transformation: Send + Sync {
    /// Apply the transformation.
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]>;

    /// Get the transformation name.
    fn name(&self) -> &'static str;

    /// Classes of bytes ([`crate::prefilter::classes`]) without which the
    /// transformation has nothing to do: for a value that holds none of them,
    /// `transform` returns the value itself. `None` (the default) when no such
    /// set is known. Lets a value be recognized as unchanged by a whole chain
    /// from one summary of its bytes, without running the chain.
    fn touches(&self) -> Option<u64> {
        None
    }
}

/// Whether `b` is a hexadecimal digit.
pub(crate) fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// libmodsecurity's `x2c`: two characters read as hexadecimal digits, with
/// its arithmetic for characters that are not digits (`hexDecode` decodes
/// every pair, valid or not).
pub(crate) fn x2c(high: u8, low: u8) -> u8 {
    let digit = |c: u8| -> u8 {
        if c >= b'A' {
            (c & 0xdf).wrapping_sub(b'A').wrapping_add(10)
        } else {
            c.wrapping_sub(b'0')
        }
    };
    digit(high).wrapping_mul(16).wrapping_add(digit(low))
}

/// `isspace` in the C locale: space, tab, newline, vertical tab, form feed and
/// carriage return. Bytes above `7F` are not whitespace.
pub(crate) fn is_c_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// Create a transformation from a name.
pub fn create_transformation(name: &str) -> Result<Arc<dyn Transformation>> {
    create_transformation_with(name, None)
}

/// Create a transformation from a name, with the best-fit table a
/// `SecUnicodeMapFile` directive named for `urlDecodeUni` (`None`: the
/// built-in one).
pub fn create_transformation_with(
    name: &str,
    unicode_map: Option<&Arc<UnicodeMap>>,
) -> Result<Arc<dyn Transformation>> {
    if let (true, Some(map)) = (name.eq_ignore_ascii_case("urldecodeuni"), unicode_map) {
        return Ok(Arc::new(UrlDecodeUniWith(Arc::clone(map))));
    }
    match name.to_lowercase().as_str() {
        // Decoding
        "urldecode" => Ok(Arc::new(UrlDecode)),
        "urldecodeuni" => Ok(Arc::new(UrlDecodeUni)),
        "base64decode" => Ok(Arc::new(Base64Decode)),
        "base64decodeext" => Ok(Arc::new(Base64DecodeExt)),
        "hexdecode" => Ok(Arc::new(HexDecode)),
        "htmlentitydecode" => Ok(Arc::new(HtmlEntityDecode)),
        "jsdecode" => Ok(Arc::new(JsDecode)),
        "cssdecode" => Ok(Arc::new(CssDecode)),

        // Encoding
        "base64encode" => Ok(Arc::new(Base64Encode)),
        "hexencode" => Ok(Arc::new(HexEncode)),
        "urlencode" => Ok(Arc::new(UrlEncode)),

        // Normalization
        "lowercase" => Ok(Arc::new(Lowercase)),
        "uppercase" => Ok(Arc::new(Uppercase)),
        "compresswhitespace" => Ok(Arc::new(CompressWhitespace)),
        "removewhitespace" => Ok(Arc::new(RemoveWhitespace)),
        "removenulls" => Ok(Arc::new(RemoveNulls)),
        "replacenulls" => Ok(Arc::new(ReplaceNulls)),
        "trim" => Ok(Arc::new(Trim)),
        "trimleft" => Ok(Arc::new(TrimLeft)),
        "trimright" => Ok(Arc::new(TrimRight)),
        // CRS uses the British spelling (normalise*); accept both.
        "normalizepath" | "normalisepath" => Ok(Arc::new(NormalizePath)),
        "normalizepathwin" | "normalisepathwin" => Ok(Arc::new(NormalizePathWin)),
        "removecomments" => Ok(Arc::new(RemoveComments)),
        "replacecomments" => Ok(Arc::new(ReplaceComments)),
        // libmodsecurity knows it under both names.
        "cmdline" | "cmd_line" => Ok(Arc::new(CmdLine)),
        "removecommentschar" => Ok(Arc::new(RemoveCommentsChar)),

        // Hashing
        "md5" => Ok(Arc::new(Md5)),
        "sha1" => Ok(Arc::new(Sha1)),

        // Special
        "length" => Ok(Arc::new(Length)),
        "none" => Ok(Arc::new(None_)),

        // Additional CRS transformations
        "sqlhexdecode" => Ok(Arc::new(SqlHexDecode)),
        "utf8tounicode" => Ok(Arc::new(Utf8ToUnicode)),
        "escapeseqdecode" => Ok(Arc::new(EscapeSeqDecode)),
        "parityeven7bit" => Ok(Arc::new(Parity7bit::Even)),
        "parityodd7bit" => Ok(Arc::new(Parity7bit::Odd)),
        "parityzero7bit" => Ok(Arc::new(Parity7bit::Zero)),
        "sha256" => Ok(Arc::new(Sha256)),

        _ => Err(Error::UnknownTransformation {
            name: name.to_string(),
        }),
    }
}

/// None transformation (clears the transformation chain).
pub struct None_;

impl Transformation for None_ {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        Cow::Borrowed(input)
    }

    fn touches(&self) -> Option<u64> {
        Some(0)
    }

    fn name(&self) -> &'static str {
        "none"
    }
}

/// Length transformation (returns the length of the input, in bytes).
pub struct Length;

impl Transformation for Length {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        Cow::Owned(input.len().to_string().into_bytes())
    }

    fn name(&self) -> &'static str {
        "length"
    }
}

/// Every value of up to four bytes over the bytes the transformations treat
/// specially, plus a letter, a capital, a digit, a two-byte UTF-8 letter and
/// bytes that are not UTF-8: what the shortcut of each transformation is
/// checked against (`untouched` must imply that the full transformation
/// changes nothing).
#[cfg(test)]
pub(crate) fn short_inputs() -> Vec<Vec<u8>> {
    const ALPHABET: [&[u8]; 28] = [
        b"a",
        b"A",
        b"u",
        b"x",
        b"4",
        "\u{e9}".as_bytes(),
        b"\x80",
        b"\xc0",
        b"\xff",
        b"\xa0",
        b".",
        b"/",
        b"\\",
        b"%",
        b"+",
        b" ",
        b"\t",
        b"\x0b",
        b"*",
        b"-",
        b"#",
        b"\"",
        b"'",
        b"^",
        b"(",
        b",",
        b";",
        b"&",
    ];
    let mut inputs = vec![Vec::new()];
    let mut from = 0;
    for _ in 0..4 {
        let until = inputs.len();
        for i in from..until {
            for piece in ALPHABET {
                let mut longer = inputs[i].clone();
                longer.extend_from_slice(piece);
                inputs.push(longer);
            }
        }
        from = until;
    }
    inputs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x2c_reads_digits_and_does_libmodsecurity_arithmetic_on_the_rest() {
        assert_eq!(x2c(b'4', b'1'), b'A');
        assert_eq!(x2c(b'a', b'C'), 0xac);
        assert_eq!(x2c(b'F', b'f'), 0xff);
        // `0z` in libmodsecurity's hexDecode vector gives `#`.
        assert_eq!(x2c(b'0', b'z'), b'#');
    }

    /// What a transformation says it touches is checked on every short value:
    /// one that holds none of those classes of bytes comes back as it was.
    #[test]
    fn a_value_without_what_a_transformation_touches_is_unchanged() {
        let names = [
            "urlDecode",
            "urlDecodeUni",
            "htmlEntityDecode",
            "jsDecode",
            "cssDecode",
            "lowercase",
            "uppercase",
            "compressWhitespace",
            "removeWhitespace",
            "removeNulls",
            "replaceNulls",
            "trim",
            "trimLeft",
            "trimRight",
            "normalizePath",
            "normalizePathWin",
            "removeComments",
            "replaceComments",
            "removeCommentsChar",
            "cmdLine",
            "utf8toUnicode",
            "escapeSeqDecode",
            "sqlHexDecode",
            "none",
        ];
        let mut inputs = short_inputs();
        // Bytes the alphabet of `short_inputs` lacks.
        for extra in [
            &b"0x41"[..],
            b"<!",
            b"a\0b",
            b"a\x0cb",
            b"-->",
            b"*/",
            b"\r\n",
            b"a=b",
            b"0X4a",
        ] {
            inputs.push(extra.to_vec());
        }
        for name in names {
            let t = create_transformation(name).unwrap();
            let touches = t
                .touches()
                .unwrap_or_else(|| panic!("{name} says what it touches"));
            let mut spared = 0;
            for input in &inputs {
                if crate::prefilter::classes(input) & touches == 0 {
                    spared += 1;
                    assert_eq!(
                        t.transform(input).as_ref(),
                        input.as_slice(),
                        "{name} on {input:?}"
                    );
                }
            }
            assert!(spared > 0, "{name}");
        }
        // The ones that can always change a value say nothing.
        for name in ["base64Decode", "hexDecode", "md5", "length", "urlEncode"] {
            assert_eq!(
                create_transformation(name).unwrap().touches(),
                None,
                "{name}"
            );
        }
    }

    #[test]
    fn length_counts_bytes() {
        assert_eq!(Length.transform(b"\xc3\xa9\xff").as_ref(), b"3");
    }
}
