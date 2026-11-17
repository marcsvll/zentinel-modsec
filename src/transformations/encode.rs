//! Encoding transformations.

use super::Transformation;
use std::borrow::Cow;

/// Base64 encode transformation.
pub struct Base64Encode;

impl Transformation for Base64Encode {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        use base64::Engine;
        Cow::Owned(
            base64::engine::general_purpose::STANDARD
                .encode(input)
                .into_bytes(),
        )
    }

    fn name(&self) -> &'static str {
        "base64Encode"
    }
}

/// Hex encode transformation (lower-case digits).
pub struct HexEncode;

impl Transformation for HexEncode {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        Cow::Owned(hex::encode(input).into_bytes())
    }

    fn name(&self) -> &'static str {
        "hexEncode"
    }
}

/// URL encode transformation.
///
/// As ModSecurity: ASCII letters, digits and `*` stay, a space is `+`, and
/// every other byte is `%` and two lower-case hexadecimal digits.
pub struct UrlEncode;

impl Transformation for UrlEncode {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        let kept = |b: u8| b.is_ascii_alphanumeric() || b == b'*';
        if input.iter().all(|&b| kept(b)) {
            return Cow::Borrowed(input);
        }
        let mut out = Vec::with_capacity(input.len() * 3);
        for &b in input {
            if kept(b) {
                out.push(b);
            } else if b == b' ' {
                out.push(b'+');
            } else {
                out.push(b'%');
                out.extend_from_slice(hex::encode([b]).as_bytes());
            }
        }
        Cow::Owned(out)
    }

    fn name(&self) -> &'static str {
        "urlEncode"
    }
}

/// MD5 hash transformation: the 16 bytes of the digest, as ModSecurity
/// gives them (not hexadecimal).
pub struct Md5;

impl Transformation for Md5 {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        use md5::{Digest, Md5 as Md5Hasher};
        Cow::Owned(Md5Hasher::digest(input).to_vec())
    }

    fn name(&self) -> &'static str {
        "md5"
    }
}

/// SHA1 hash transformation: the 20 bytes of the digest, as ModSecurity
/// gives them (not hexadecimal).
pub struct Sha1;

impl Transformation for Sha1 {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        use sha1::{Digest, Sha1 as Sha1Hasher};
        Cow::Owned(Sha1Hasher::digest(input).to_vec())
    }

    fn name(&self) -> &'static str {
        "sha1"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        assert_eq!(Base64Encode.transform(b"hello").as_ref(), b"aGVsbG8=");
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(HexEncode.transform(b"A\xff").as_ref(), b"41ff");
    }

    #[test]
    fn test_url_encode() {
        assert_eq!(UrlEncode.transform(b"a b/\xe9*").as_ref(), b"a+b%2f%e9*");
    }

    #[test]
    fn test_md5() {
        assert_eq!(
            hex::encode(Md5.transform(b"hello")),
            "5d41402abc4b2a76b9719d911017c592"
        );
    }

    #[test]
    fn test_sha1() {
        assert_eq!(
            hex::encode(Sha1.transform(b"hello")),
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        );
    }
}
