//! The best-fit table `t:urlDecodeUni` reads `%uXXXX` through.
//!
//! IIS and classic ASP accept `%uXXXX` and fold what the target code page
//! cannot hold to the character that looks most like it: U+2019 becomes `'`,
//! U+00AB becomes `<`. ModSecurity mirrors that with `SecUnicodeMapFile
//! unicode.mapping 20127`, which its recommended configuration sets, and the
//! CRS regression tests assume it. This engine has that table (code page
//! 20127, US-ASCII) built in and uses it when no `SecUnicodeMapFile` is given;
//! the directive replaces it with a code page of a file in ModSecurity's
//! format.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

/// Code page 20127 of ModSecurity's `unicode.mapping` (ModSecurity v3.0.14,
/// Apache-2.0), reflowed.
const US_ASCII: &str = include_str!("unicode_20127.mapping");

/// The code page of the built-in table.
pub const US_ASCII_CODE_PAGE: u32 = 20127;

/// What `%uXXXX` decodes to, for the code points a code page folds.
#[derive(Debug)]
pub struct UnicodeMap {
    table: HashMap<u32, u8>,
}

impl UnicodeMap {
    /// The built-in table: code page 20127.
    pub fn us_ascii() -> Arc<Self> {
        static MAP: OnceLock<Arc<UnicodeMap>> = OnceLock::new();
        Arc::clone(MAP.get_or_init(|| {
            let map = Self::parse(US_ASCII, US_ASCII_CODE_PAGE);
            Arc::new(map.unwrap_or(Self {
                table: HashMap::new(),
            }))
        }))
    }

    /// Reads one code page out of a file in ModSecurity's format: a line that
    /// starts with the code page number and its name in parentheses, then
    /// `xxxx:yy` pairs (hexadecimal code point, hexadecimal byte) up to the
    /// next such line. `None` when the code page is not in the text or has no
    /// pair.
    pub fn parse(text: &str, code_page: u32) -> Option<Self> {
        let mut table = HashMap::new();
        let mut inside = false;
        for line in text.lines() {
            if let Some(header) = header(line) {
                if inside {
                    break;
                }
                inside = header == code_page;
                continue;
            }
            if !inside {
                continue;
            }
            for pair in line.split_ascii_whitespace() {
                let Some((code, byte)) = pair.split_once(':') else {
                    continue;
                };
                if let (Ok(code), Ok(byte)) =
                    (u32::from_str_radix(code, 16), u8::from_str_radix(byte, 16))
                {
                    table.insert(code, byte);
                }
            }
        }
        (!table.is_empty()).then_some(Self { table })
    }

    /// The byte a code point folds to, if the code page folds it.
    pub fn get(&self, code: u32) -> Option<u8> {
        self.table.get(&code).copied()
    }
}

/// The code page number of a header line (`20127 (US-ASCII)`).
fn header(line: &str) -> Option<u32> {
    let (number, name) = line.split_once('(')?;
    if !name.trim_end().ends_with(')') {
        return None;
    }
    number.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_built_in_table_folds_typographic_quotes_and_guillemets() {
        let map = UnicodeMap::us_ascii();
        for (code, byte) in [
            (0x2019, b'\''),
            (0x2018, b'\''),
            (0x201c, b'"'),
            (0x00ab, b'<'),
            (0x00bb, b'>'),
            (0x2039, b'<'),
            (0x203a, b'>'),
            (0xff1c, b'<'),
        ] {
            assert_eq!(map.get(code), Some(byte), "U+{code:04X}");
        }
        assert_eq!(map.get(0x0041), None);
        assert_eq!(map.table.len(), 370);
    }

    #[test]
    fn a_code_page_is_read_up_to_the_next_one() {
        let text = "(MAC - Roman)\n\n1250  (ANSI - Central Europe)\n00a1:21 00a2:63\n\
                    20127 (US-ASCII)\n2019:27\n00ab:3c junk zz:1\n20261 (T.61)\n2019:22\n";
        let map = UnicodeMap::parse(text, 20127).expect("the code page is there");
        assert_eq!(map.get(0x2019), Some(0x27));
        assert_eq!(map.get(0x00ab), Some(0x3c));
        assert_eq!(map.get(0x00a1), None);
        assert!(UnicodeMap::parse(text, 437).is_none());
    }
}
