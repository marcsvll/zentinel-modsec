//! Normalization transformations.
//!
//! On bytes, with ModSecurity's notion of a character class: `isspace` and
//! `tolower` of the C locale, so only ASCII letters change case and only ASCII
//! whitespace is whitespace.

use super::{is_c_space, is_hex, x2c, Transformation};
use crate::prefilter::{classes_of, DIGITS, LOWER_CASE, NOT_ASCII, UPPER_CASE, WHITESPACE};
use std::borrow::Cow;

/// Lowercase transformation (ASCII letters only, as ModSecurity's `tolower`).
pub struct Lowercase;

impl Lowercase {
    /// Whether the transformation would leave `input` as it is, decided
    /// without building anything. With no capital letter there is nothing to do.
    fn untouched(input: &[u8]) -> bool {
        !input.iter().any(u8::is_ascii_uppercase)
    }

    fn full(input: &[u8]) -> Cow<'_, [u8]> {
        Cow::Owned(input.to_ascii_lowercase())
    }
}

impl Transformation for Lowercase {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if Self::untouched(input) {
            return Cow::Borrowed(input);
        }
        Self::full(input)
    }

    fn name(&self) -> &'static str {
        "lowercase"
    }

    fn touches(&self) -> Option<u64> {
        Some(UPPER_CASE)
    }
}

/// Uppercase transformation (ASCII letters only).
pub struct Uppercase;

impl Transformation for Uppercase {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if !input.iter().any(u8::is_ascii_lowercase) {
            return Cow::Borrowed(input);
        }
        Cow::Owned(input.to_ascii_uppercase())
    }

    fn name(&self) -> &'static str {
        "uppercase"
    }

    fn touches(&self) -> Option<u64> {
        Some(LOWER_CASE)
    }
}

/// The length of the whitespace character outside ASCII that `input` starts
/// with, if it starts with one: a UTF-8 encoded Unicode `White_Space`
/// character (U+0085, U+00A0, U+1680, U+2000 to U+200A, U+2028, U+2029,
/// U+202F, U+205F, U+3000) or U+FEFF.
///
/// ModSecurity's whitespace is ASCII's. JavaScript reads these as whitespace
/// too (`this\u{3000}.constructor` is `this.constructor`), so a rule that
/// removes or compresses whitespace before matching (CRS 934100) must see them
/// as whitespace: here the engine differs from ModSecurity on purpose.
fn unicode_space(input: &[u8]) -> Option<usize> {
    let len = match *input.first()? {
        0xc2 => 2,
        0xe1..=0xe3 | 0xef => 3,
        _ => return None,
    };
    let c = std::str::from_utf8(input.get(..len)?)
        .ok()?
        .chars()
        .next()?;
    (c.is_whitespace() || c == '\u{feff}').then_some(len)
}

/// Compress whitespace transformation: every run of whitespace is one space.
///
/// Whitespace is ASCII's, as in ModSecurity, and the Unicode whitespace
/// characters of [`unicode_space`].
pub struct CompressWhitespace;

impl CompressWhitespace {
    /// Whether the transformation would leave `input` as it is, decided
    /// without building anything: no whitespace but single spaces.
    fn untouched(input: &[u8]) -> bool {
        let mut after_space = false;
        for (i, &b) in input.iter().enumerate() {
            if b == b' ' {
                if after_space {
                    return false;
                }
                after_space = true;
            } else if is_c_space(b) || unicode_space(&input[i..]).is_some() {
                return false;
            } else {
                after_space = false;
            }
        }
        true
    }

    fn full(input: &[u8]) -> Cow<'_, [u8]> {
        let mut out = Vec::with_capacity(input.len());
        let mut in_space = false;
        let mut i = 0;
        while i < input.len() {
            let space = if is_c_space(input[i]) {
                Some(1)
            } else {
                unicode_space(&input[i..])
            };
            match space {
                Some(len) => {
                    if !in_space {
                        out.push(b' ');
                    }
                    in_space = true;
                    i += len;
                }
                None => {
                    out.push(input[i]);
                    in_space = false;
                    i += 1;
                }
            }
        }
        Cow::Owned(out)
    }
}

impl Transformation for CompressWhitespace {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if Self::untouched(input) {
            return Cow::Borrowed(input);
        }
        Self::full(input)
    }

    fn name(&self) -> &'static str {
        "compressWhitespace"
    }

    fn touches(&self) -> Option<u64> {
        Some(WHITESPACE)
    }
}

/// Remove whitespace transformation.
///
/// As ModSecurity: ASCII whitespace and the two bytes of a UTF-8 no-break
/// space (`C2 A0`), each wherever it is; and the Unicode whitespace characters
/// of [`unicode_space`].
pub struct RemoveWhitespace;

impl RemoveWhitespace {
    fn removed(b: u8) -> bool {
        is_c_space(b) || b == 0xa0 || b == 0xc2
    }

    /// Whether the transformation would leave `input` as it is, decided
    /// without building anything. With nothing to remove there is nothing to do.
    fn untouched(input: &[u8]) -> bool {
        !input
            .iter()
            .enumerate()
            .any(|(i, &b)| Self::removed(b) || unicode_space(&input[i..]).is_some())
    }

    fn full(input: &[u8]) -> Cow<'_, [u8]> {
        let mut out = Vec::with_capacity(input.len());
        let mut i = 0;
        while i < input.len() {
            if let Some(len) = unicode_space(&input[i..]) {
                i += len;
            } else {
                if !Self::removed(input[i]) {
                    out.push(input[i]);
                }
                i += 1;
            }
        }
        Cow::Owned(out)
    }
}

impl Transformation for RemoveWhitespace {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if Self::untouched(input) {
            return Cow::Borrowed(input);
        }
        Self::full(input)
    }

    fn name(&self) -> &'static str {
        "removeWhitespace"
    }

    fn touches(&self) -> Option<u64> {
        Some(WHITESPACE)
    }
}

/// Remove null bytes transformation.
pub struct RemoveNulls;

impl Transformation for RemoveNulls {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if !input.contains(&0) {
            return Cow::Borrowed(input);
        }
        Cow::Owned(input.iter().copied().filter(|&b| b != 0).collect())
    }

    fn name(&self) -> &'static str {
        "removeNulls"
    }

    fn touches(&self) -> Option<u64> {
        Some(classes_of(b"\0"))
    }
}

/// Replace null bytes with spaces transformation.
pub struct ReplaceNulls;

impl Transformation for ReplaceNulls {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if !input.contains(&0) {
            return Cow::Borrowed(input);
        }
        Cow::Owned(
            input
                .iter()
                .map(|&b| if b == 0 { b' ' } else { b })
                .collect(),
        )
    }

    fn name(&self) -> &'static str {
        "replaceNulls"
    }

    fn touches(&self) -> Option<u64> {
        Some(classes_of(b"\0"))
    }
}

fn trim_start(input: &[u8]) -> &[u8] {
    let start = input
        .iter()
        .position(|&b| !is_c_space(b))
        .unwrap_or(input.len());
    &input[start..]
}

fn trim_end(input: &[u8]) -> &[u8] {
    let end = input
        .iter()
        .rposition(|&b| !is_c_space(b))
        .map_or(0, |at| at + 1);
    &input[..end]
}

/// Trim transformation.
pub struct Trim;

impl Transformation for Trim {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        Cow::Borrowed(trim_start(trim_end(input)))
    }

    fn name(&self) -> &'static str {
        "trim"
    }

    fn touches(&self) -> Option<u64> {
        Some(WHITESPACE)
    }
}

/// Trim left transformation.
pub struct TrimLeft;

impl Transformation for TrimLeft {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        Cow::Borrowed(trim_start(input))
    }

    fn name(&self) -> &'static str {
        "trimLeft"
    }

    fn touches(&self) -> Option<u64> {
        Some(WHITESPACE)
    }
}

/// Trim right transformation.
pub struct TrimRight;

impl Transformation for TrimRight {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        Cow::Borrowed(trim_end(input))
    }

    fn name(&self) -> &'static str {
        "trimRight"
    }

    fn touches(&self) -> Option<u64> {
        Some(WHITESPACE)
    }
}

/// Normalize path transformation (Unix-style).
pub struct NormalizePath;

impl NormalizePath {
    /// Whether the transformation would leave `input` as it is, decided
    /// without building anything. No backslash, no repeated slash and no `.` or
    /// `..` segment: the path is already normal.
    fn untouched(input: &[u8]) -> bool {
        !input.contains(&b'\\')
            && !input.windows(2).any(|w| w == b"//")
            && !input
                .split(|&b| b == b'/')
                .any(|part| part == b"." || part == b"..")
    }

    /// libmodsecurity's `normalize_path_inplace`: empty and `.` segments go,
    /// a `..` takes the segment before it with it (but a relative path keeps
    /// the `..` it cannot resolve: `../.history` stays as written, which CRS
    /// 930120 looks for), runs of slashes collapse, and the result ends in a
    /// slash only if the input did. With `win`, backslashes are slashes.
    fn normalize(input: &[u8], win: bool) -> Vec<u8> {
        let mut buf = input.to_vec();
        if buf.is_empty() {
            return buf;
        }
        let is_sep = |b: u8| b == b'/' || (win && b == b'\\');
        let end = buf.len() - 1;
        let relative = !is_sep(buf[0]);
        let trailing = is_sep(buf[end]);
        let (mut src, mut dst) = (0usize, 0usize);
        let mut hitroot = false;
        let mut done = false;
        while !done && src <= end && dst <= end {
            if win {
                if buf[src] == b'\\' {
                    buf[src] = b'/';
                }
                if src < end && buf[src + 1] == b'\\' {
                    buf[src + 1] = b'/';
                }
            }
            let normalize = if src == end {
                done = true;
                true
            } else {
                buf[src + 1] == b'/'
            };
            let mut copy = true;
            if normalize {
                if src != end && buf[src] == b'/' {
                    // An empty segment: the copy below collapses it.
                } else if buf[src] == b'.' {
                    // A back-reference is a whole `..` segment. libmodsecurity
                    // only looks at the dot before, so `passwd..` took the
                    // segment before it too: `/etc/passwd..` became `/etc/`,
                    // and Windows reads `passwd..` as `passwd`.
                    let whole_dots = dst == 1 || (dst > 1 && is_sep(buf[dst - 2]));
                    if dst > 0 && buf[dst - 1] == b'.' && whole_dots {
                        if relative && (hitroot || dst <= 2) {
                            // A back-reference with nothing before it.
                            hitroot = true;
                        } else {
                            // Remove the back-reference and the segment before it.
                            let mut d = dst as isize - 3;
                            while d > 0 && buf[d as usize] != b'/' {
                                d -= 1;
                            }
                            if d <= 0 {
                                hitroot = true;
                                d = 0;
                                if !relative && src == end {
                                    d += 1;
                                }
                            }
                            dst = d as usize;
                            if done {
                                copy = false;
                            } else {
                                src += 1;
                            }
                        }
                    } else if dst == 0 {
                        // A relative self-reference.
                        if done {
                            copy = false;
                        } else {
                            src += 1;
                        }
                    } else if buf[dst - 1] == b'/' {
                        // A self-reference.
                        if done {
                            copy = false;
                        } else {
                            dst -= 1;
                            src += 1;
                        }
                    }
                } else if dst > 0 {
                    hitroot = false;
                }
            }
            if !copy {
                continue;
            }
            if src > end {
                break;
            }
            if buf[src] == b'/' {
                while src < end && is_sep(buf[src + 1]) {
                    src += 1;
                }
                // A relative path does not start with the slash.
                if relative && dst == 0 {
                    src += 1;
                    continue;
                }
            }
            buf[dst] = buf[src];
            dst += 1;
            src += 1;
        }
        if !trailing && dst > 0 && buf[dst - 1] == b'/' {
            dst -= 1;
        }
        buf.truncate(dst);
        buf
    }

    fn full(input: &[u8]) -> Cow<'_, [u8]> {
        Cow::Owned(Self::normalize(input, false))
    }
}

impl Transformation for NormalizePath {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if Self::untouched(input) {
            return Cow::Borrowed(input);
        }
        Self::full(input)
    }

    fn name(&self) -> &'static str {
        "normalizePath"
    }

    fn touches(&self) -> Option<u64> {
        Some(classes_of(b"/\\."))
    }
}

/// Normalize path transformation (Windows-style).
pub struct NormalizePathWin;

impl Transformation for NormalizePathWin {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        // ModSecurity: backslashes are separators, and the result is written
        // with forward slashes; turning them back into backslashes made
        // `/etc/passwd` unmatchable for every CRS rule that uses this.
        if NormalizePath::untouched(input) {
            return Cow::Borrowed(input);
        }
        Cow::Owned(NormalizePath::normalize(input, true))
    }

    fn name(&self) -> &'static str {
        "normalizePathWin"
    }

    fn touches(&self) -> Option<u64> {
        Some(classes_of(b"/\\."))
    }
}

/// Remove comments transformation.
pub struct RemoveComments;

impl RemoveComments {
    /// Whether the transformation would leave `input` as it is, decided
    /// without building anything. None of `/*`, `<!--`, `--` or `#` is there.
    fn untouched(input: &[u8]) -> bool {
        !input.contains(&b'#')
            && !input.windows(2).any(|w| w == b"/*" || w == b"--")
            && !input.windows(4).any(|w| w == b"<!--")
    }

    /// As ModSecurity: `/* … */` and `<!-- … -->` go, an unterminated one
    /// leaves a space, and `--` or `#` ends the value there.
    fn full(input: &[u8]) -> Cow<'_, [u8]> {
        let mut out = Vec::with_capacity(input.len());
        let mut in_comment = false;
        let mut i = 0;
        while i < input.len() {
            let rest = &input[i..];
            if !in_comment {
                if rest.starts_with(b"/*") {
                    in_comment = true;
                    i += 2;
                } else if rest.starts_with(b"<!--") {
                    in_comment = true;
                    i += 4;
                } else if rest.starts_with(b"--") || rest[0] == b'#' {
                    break;
                } else {
                    out.push(rest[0]);
                    i += 1;
                }
            } else if rest.starts_with(b"*/") {
                in_comment = false;
                i += 2;
            } else if rest.starts_with(b"-->") {
                in_comment = false;
                i += 3;
            } else {
                i += 1;
            }
        }
        if in_comment {
            out.push(b' ');
        }
        Cow::Owned(out)
    }
}

impl Transformation for RemoveComments {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if Self::untouched(input) {
            return Cow::Borrowed(input);
        }
        Self::full(input)
    }

    fn name(&self) -> &'static str {
        "removeComments"
    }

    fn touches(&self) -> Option<u64> {
        Some(classes_of(b"*-#"))
    }
}

/// Replace comments transformation (replaces /* ... */ with space).
pub struct ReplaceComments;

impl ReplaceComments {
    /// Whether the transformation would leave `input` as it is, decided
    /// without building anything. Only `/*` opens a comment.
    fn untouched(input: &[u8]) -> bool {
        !input.windows(2).any(|w| w == b"/*")
    }

    /// As ModSecurity: each `/* … */` is one space, and so is an unterminated
    /// one.
    fn full(input: &[u8]) -> Cow<'_, [u8]> {
        let mut out = Vec::with_capacity(input.len());
        let mut in_comment = false;
        let mut i = 0;
        while i < input.len() {
            let rest = &input[i..];
            if !in_comment {
                if rest.starts_with(b"/*") {
                    in_comment = true;
                    i += 2;
                } else {
                    out.push(rest[0]);
                    i += 1;
                }
            } else if rest.starts_with(b"*/") {
                in_comment = false;
                out.push(b' ');
                i += 2;
            } else {
                i += 1;
            }
        }
        if in_comment {
            out.push(b' ');
        }
        Cow::Owned(out)
    }
}

impl Transformation for ReplaceComments {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if Self::untouched(input) {
            return Cow::Borrowed(input);
        }
        Self::full(input)
    }

    fn name(&self) -> &'static str {
        "replaceComments"
    }

    fn touches(&self) -> Option<u64> {
        Some(classes_of(b"*"))
    }
}

/// Remove comment characters transformation.
pub struct RemoveCommentsChar;

impl RemoveCommentsChar {
    /// Whether the transformation would leave `input` as it is, decided
    /// without building anything. None of the markers is there to remove.
    fn untouched(input: &[u8]) -> bool {
        !input.contains(&b'#')
            && !input
                .windows(2)
                .any(|w| w == b"/*" || w == b"*/" || w == b"--" || w == b"<!")
    }

    /// As ModSecurity: `/*`, `*/`, `<!--`, `-->`, `--` and `#` are removed,
    /// whatever is between them stays.
    fn full(input: &[u8]) -> Cow<'_, [u8]> {
        let mut out = Vec::with_capacity(input.len());
        let mut i = 0;
        while i < input.len() {
            let rest = &input[i..];
            let skip = if rest.starts_with(b"/*") || rest.starts_with(b"*/") {
                2
            } else if rest.starts_with(b"<!--") {
                4
            } else if rest.starts_with(b"-->") {
                3
            } else if rest.starts_with(b"--") {
                2
            } else if rest[0] == b'#' {
                1
            } else {
                out.push(rest[0]);
                1
            };
            i += skip;
        }
        Cow::Owned(out)
    }
}

impl Transformation for RemoveCommentsChar {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if Self::untouched(input) {
            return Cow::Borrowed(input);
        }
        Self::full(input)
    }

    fn name(&self) -> &'static str {
        "removeCommentsChar"
    }

    fn touches(&self) -> Option<u64> {
        Some(classes_of(b"*-#"))
    }
}

/// SQL hex decode transformation.
pub struct SqlHexDecode;

impl Transformation for SqlHexDecode {
    /// As ModSecurity: `0x` (or `0X`) followed by pairs of hexadecimal digits
    /// is the bytes they name; `0x` with fewer than two digits stays.
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        let starts = |at: usize| {
            at + 3 < input.len()
                && input[at] == b'0'
                && input[at + 1].eq_ignore_ascii_case(&b'x')
                && is_hex(input[at + 2])
                && is_hex(input[at + 3])
        };
        if !(0..input.len()).any(starts) {
            return Cow::Borrowed(input);
        }
        let mut out = Vec::with_capacity(input.len());
        let mut i = 0;
        while i < input.len() {
            if starts(i) {
                i += 2;
                loop {
                    out.push(x2c(input[i], input[i + 1]));
                    i += 2;
                    if !(i + 1 < input.len() && is_hex(input[i]) && is_hex(input[i + 1])) {
                        break;
                    }
                }
            } else {
                out.push(input[i]);
                i += 1;
            }
        }
        Cow::Owned(out)
    }

    fn name(&self) -> &'static str {
        "sqlHexDecode"
    }

    fn touches(&self) -> Option<u64> {
        Some(DIGITS)
    }
}

/// UTF-8 to Unicode transformation.
pub struct Utf8ToUnicode;

impl Transformation for Utf8ToUnicode {
    /// Every UTF-8 character outside ASCII becomes `%uHHHH` (lower-case
    /// digits, at least four), as in ModSecurity; bytes that are not UTF-8
    /// stay as they are.
    ///
    /// The CRS always follows it with `t:urlDecodeUni`, which reads the
    /// escape back and folds the full-width forms to ASCII on the way: that
    /// pair is how `＜script＞` is seen as `<script>` (S10).
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if input.is_ascii() {
            return Cow::Borrowed(input);
        }
        let mut out = Vec::with_capacity(input.len() + 16);
        for chunk in input.utf8_chunks() {
            for c in chunk.valid().chars() {
                if c.is_ascii() {
                    out.push(c as u8);
                } else {
                    out.extend_from_slice(format!("%u{:04x}", c as u32).as_bytes());
                }
            }
            out.extend_from_slice(chunk.invalid());
        }
        Cow::Owned(out)
    }

    fn name(&self) -> &'static str {
        "utf8ToUnicode"
    }

    fn touches(&self) -> Option<u64> {
        Some(NOT_ASCII)
    }
}

/// Command line normalization transformation.
pub struct CmdLine;

impl CmdLine {
    /// Whether the command line is already in its normal form: no capital
    /// letter, none of the deleted characters or separators, no whitespace but
    /// single spaces, and no space before `/` or `(`.
    fn untouched(input: &[u8]) -> bool {
        let mut after_space = false;
        for &b in input {
            match b {
                b' ' => {
                    if after_space {
                        return false;
                    }
                    after_space = true;
                }
                b'/' | b'(' => {
                    if after_space {
                        return false;
                    }
                }
                b'\\' | b'"' | b'\'' | b'^' | b',' | b';' | b'\t' | b'\r' | b'\n' => return false,
                _ if b.is_ascii_uppercase() => return false,
                _ => after_space = false,
            }
        }
        true
    }

    /// Normalise a Windows/Unix command line the way ModSecurity does.
    ///
    /// The steps, and the order, are ModSecurity's:
    ///
    /// 1. delete backslashes, double quotes, single quotes and carets, which
    ///    a shell treats as noise but which break naive pattern matching;
    /// 2. turn commas, semicolons, spaces, tabs and line breaks (any run of
    ///    them) into a single space;
    /// 3. delete a space that immediately precedes `/` or `(`;
    /// 4. lowercase everything else (ASCII letters).
    ///
    /// Step 3 is the one CRS regexes are written against: rule 932140 looks
    /// for `in\(`, with no space, so `for %v in (set) do cmd` only matches
    /// once `in (set)` has become `in(set)`.
    fn full(input: &[u8]) -> Cow<'_, [u8]> {
        let mut out = Vec::with_capacity(input.len());
        // Whether the last byte written is a space we introduced, and so may
        // still be removed by a following `/` or `(`.
        let mut pending_space = false;
        for &b in input {
            match b {
                b'\\' | b'"' | b'\'' | b'^' => {}
                b' ' | b',' | b';' | b'\t' | b'\r' | b'\n' => {
                    if !pending_space {
                        out.push(b' ');
                        pending_space = true;
                    }
                }
                b'/' | b'(' => {
                    if pending_space {
                        out.pop();
                    }
                    pending_space = false;
                    out.push(b);
                }
                _ => {
                    pending_space = false;
                    out.push(b.to_ascii_lowercase());
                }
            }
        }
        Cow::Owned(out)
    }
}

impl Transformation for CmdLine {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if Self::untouched(input) {
            return Cow::Borrowed(input);
        }
        Self::full(input)
    }

    fn name(&self) -> &'static str {
        "cmdLine"
    }

    fn touches(&self) -> Option<u64> {
        Some(classes_of(b"\\\"'^,; \t\r\n") | UPPER_CASE)
    }
}

/// Escape sequence decode transformation.
pub struct EscapeSeqDecode;

impl EscapeSeqDecode {
    /// Whether the transformation would leave `input` as it is, decided
    /// without building anything. Only a backslash starts an escape.
    fn untouched(input: &[u8]) -> bool {
        !input.contains(&b'\\')
    }

    /// Decode ANSI C escapes, as ModSecurity does: `\a \b \f \n \r \t \v`,
    /// `\\ \? \' \"`, `\xHH` (two hexadecimal digits) and `\OOO` (one to
    /// three octal digits). Any other escape loses its backslash and keeps
    /// the character (`\q` is `q`, `\u0041` is `u0041`); a `\x` without two
    /// digits loses the backslash too. A backslash that ends the input stays.
    fn full(input: &[u8]) -> Cow<'_, [u8]> {
        let mut out = Vec::with_capacity(input.len());
        let mut i = 0;
        while i < input.len() {
            let Some(&next) = (input[i] == b'\\').then(|| input.get(i + 1)).flatten() else {
                out.push(input[i]);
                i += 1;
                continue;
            };
            let simple = match next {
                b'a' => Some(0x07),
                b'b' => Some(0x08),
                b'f' => Some(0x0c),
                b'n' => Some(b'\n'),
                b'r' => Some(b'\r'),
                b't' => Some(b'\t'),
                b'v' => Some(0x0b),
                b'\\' | b'?' | b'\'' | b'"' => Some(next),
                _ => None,
            };
            if let Some(decoded) = simple {
                out.push(decoded);
                i += 2;
                continue;
            }
            if matches!(next, b'x' | b'X')
                && i + 3 < input.len()
                && is_hex(input[i + 2])
                && is_hex(input[i + 3])
            {
                out.push(x2c(input[i + 2], input[i + 3]));
                i += 4;
                continue;
            }
            let octal = input[i + 1..]
                .iter()
                .take(3)
                .take_while(|b| (b'0'..=b'7').contains(*b))
                .count();
            if octal > 0 {
                // Three digits can exceed a byte; C keeps the low eight bits.
                let value = input[i + 1..i + 1 + octal]
                    .iter()
                    .fold(0u32, |v, &d| v * 8 + u32::from(d - b'0'));
                out.push(value as u8);
                i += 1 + octal;
                continue;
            }
            // Not an escape: the backslash goes, the character stays.
            out.push(next);
            i += 2;
        }
        Cow::Owned(out)
    }
}

impl Transformation for EscapeSeqDecode {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if Self::untouched(input) {
            return Cow::Borrowed(input);
        }
        Self::full(input)
    }

    fn name(&self) -> &'static str {
        "escapeSeqDecode"
    }

    fn touches(&self) -> Option<u64> {
        Some(classes_of(b"\\"))
    }
}

/// SHA-256 hash transformation (not a ModSecurity transformation; the digest
/// is written in lower-case hexadecimal).
pub struct Sha256;

impl Transformation for Sha256 {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        use sha2::{Digest, Sha256 as Sha256Hasher};
        let mut hasher = Sha256Hasher::new();
        hasher.update(input);
        Cow::Owned(hex::encode(hasher.finalize()).into_bytes())
    }

    fn name(&self) -> &'static str {
        "sha256"
    }
}

/// `parityEven7bit`, `parityOdd7bit` and `parityZero7bit`: the high bit of
/// every byte set to make its parity even or odd, or cleared.
pub enum Parity7bit {
    /// `parityEven7bit`.
    Even,
    /// `parityOdd7bit`.
    Odd,
    /// `parityZero7bit`.
    Zero,
}

impl Transformation for Parity7bit {
    fn transform<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if input.is_empty() {
            return Cow::Borrowed(input);
        }
        Cow::Owned(
            input
                .iter()
                .map(|&b| {
                    let odd = (b & 0x7f).count_ones() % 2 == 1;
                    let set = match self {
                        Self::Even => odd,
                        Self::Odd => !odd,
                        Self::Zero => false,
                    };
                    if set {
                        b | 0x80
                    } else {
                        b & 0x7f
                    }
                })
                .collect(),
        )
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Even => "parityEven7bit",
            Self::Odd => "parityOdd7bit",
            Self::Zero => "parityZero7bit",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(tr: &dyn Transformation, input: &[u8]) -> Vec<u8> {
        tr.transform(input).into_owned()
    }

    #[test]
    fn test_utf8_to_unicode_escapes_what_is_not_ascii() {
        let tr = Utf8ToUnicode;
        assert_eq!(t(&tr, b"plain ascii"), b"plain ascii");
        assert_eq!(t(&tr, "caf\u{e9}".as_bytes()), b"caf%u00e9");
        assert_eq!(
            t(&tr, "\u{ff1c}script\u{ff1e}".as_bytes()),
            b"%uff1cscript%uff1e"
        );
        // Outside the BMP the escape is longer than four digits, and
        // urlDecodeUni reads only four: as in ModSecurity.
        assert_eq!(t(&tr, "\u{1f600}".as_bytes()), b"%u1f600");
        // Bytes that are not UTF-8 stay.
        assert_eq!(t(&tr, b"a\xe9\xffb"), b"a\xe9\xffb");
    }

    /// The shortcut of each transformation only ever answers for inputs the
    /// full transformation leaves as they are, and it does answer for an
    /// ordinary value.
    #[test]
    fn test_untouched_implies_unchanged() {
        type Check = (&'static str, fn(&[u8]) -> bool, fn(&[u8]) -> Cow<'_, [u8]>);
        let checks: [Check; 9] = [
            ("Lowercase", Lowercase::untouched, Lowercase::full),
            (
                "CompressWhitespace",
                CompressWhitespace::untouched,
                CompressWhitespace::full,
            ),
            (
                "RemoveWhitespace",
                RemoveWhitespace::untouched,
                RemoveWhitespace::full,
            ),
            (
                "NormalizePath",
                NormalizePath::untouched,
                NormalizePath::full,
            ),
            (
                "RemoveComments",
                RemoveComments::untouched,
                RemoveComments::full,
            ),
            (
                "ReplaceComments",
                ReplaceComments::untouched,
                ReplaceComments::full,
            ),
            (
                "RemoveCommentsChar",
                RemoveCommentsChar::untouched,
                RemoveCommentsChar::full,
            ),
            (
                "EscapeSeqDecode",
                EscapeSeqDecode::untouched,
                EscapeSeqDecode::full,
            ),
            ("CmdLine", CmdLine::untouched, CmdLine::full),
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
    fn test_lowercase_is_ascii_only() {
        assert_eq!(t(&Lowercase, b"Hello World"), b"hello world");
        assert_eq!(t(&Lowercase, b"already lower"), b"already lower");
        // As ModSecurity's tolower: other bytes stay, so `\u{212a}` (Kelvin)
        // is not `k` and `\u{c9}` is not `\u{e9}`.
        let input = ["\u{212a}\u{c9}A".as_bytes(), b"\xff"].concat();
        let expected = ["\u{212a}\u{c9}a".as_bytes(), b"\xff"].concat();
        assert_eq!(t(&Lowercase, &input), expected);
    }

    #[test]
    fn test_compress_whitespace() {
        assert_eq!(t(&CompressWhitespace, b"hello   world"), b"hello world");
        assert_eq!(t(&CompressWhitespace, b"a\t\nb"), b"a b");
        assert_eq!(t(&CompressWhitespace, b"a\xa0b"), b"a\xa0b");
    }

    #[test]
    fn unicode_whitespace_is_whitespace() {
        // CRS 934100 removes whitespace before looking for `this.constructor`.
        let ideographic = "this\u{3000}.constructor".as_bytes();
        assert_eq!(t(&RemoveWhitespace, ideographic), b"this.constructor");
        assert_eq!(t(&CompressWhitespace, ideographic), b"this .constructor");
        for c in [
            '\u{85}', '\u{a0}', '\u{1680}', '\u{2000}', '\u{200a}', '\u{2028}', '\u{202f}',
            '\u{205f}', '\u{feff}',
        ] {
            let value = format!("a{c}b");
            assert_eq!(t(&RemoveWhitespace, value.as_bytes()), b"ab", "{c:?}");
            assert_eq!(t(&CompressWhitespace, value.as_bytes()), b"a b", "{c:?}");
        }
        // Not whitespace: a letter of the same lead byte, a zero-width joiner.
        assert_eq!(
            t(&RemoveWhitespace, "\u{e9}\u{200d}".as_bytes()),
            "\u{e9}\u{200d}".as_bytes()
        );
    }

    #[test]
    fn test_remove_whitespace() {
        assert_eq!(t(&RemoveWhitespace, b"hello world"), b"helloworld");
        assert_eq!(t(&RemoveWhitespace, b"a\xc2\xa0b"), b"ab");
    }

    #[test]
    fn test_normalize_path() {
        let tr = NormalizePath;
        assert_eq!(t(&tr, b"/a/b/../c"), b"/a/c");
        assert_eq!(t(&tr, b"/a//b/./c"), b"/a/b/c");
        // A back-reference at the beginning has nothing to remove and stays.
        assert_eq!(t(&tr, b"../.history"), b"../.history");
        assert_eq!(t(&tr, b"../../etc/passwd"), b"../../etc/passwd");
        assert_eq!(t(&tr, b"a/../../b"), b"../b");
        assert_eq!(t(&tr, b"/../etc/passwd"), b"/etc/passwd");
        // A trailing slash stays when there was one.
        assert_eq!(t(&tr, b"dir/foo//bar/"), b"dir/foo/bar/");
        assert_eq!(t(&tr, b"/a/\xff/../b"), b"/a/b");
        // A name that ends in two dots is a name, not a back-reference.
        assert_eq!(t(&tr, b"/etc/passwd.."), b"/etc/passwd..");
        assert_eq!(t(&tr, b"a..b/../c"), b"c");
    }

    #[test]
    fn test_cmdline() {
        let tr = CmdLine;
        // Caret is the Windows escape character - it is simply removed.
        assert_eq!(t(&tr, b"echo^hello"), b"echohello");
        // Backslashes and quotes are deleted, not replaced.
        assert_eq!(t(&tr, br"c:\\windows\\system32"), b"c:windowssystem32");
        assert_eq!(t(&tr, b"\"cat\" '/etc/passwd'"), b"cat/etc/passwd");
        // Commas and semicolons become a space; runs collapse to one.
        assert_eq!(t(&tr, b"DIR,,,X"), b"dir x");
        assert_eq!(t(&tr, b"a \t\n b"), b"a b");
        // A space before `/` or `(` is deleted -- this is what CRS regexes are
        // written against, e.g. 932140 matching `in\(`.
        assert_eq!(t(&tr, b"CMD;/C"), b"cmd/c");
        assert_eq!(t(&tr, b"CMD,/C;DIR"), b"cmd/c dir");
        assert_eq!(t(&tr, b"for %v in (set) do cmd"), b"for %v in(set) do cmd");
        assert_eq!(t(&tr, b"cat /etc/passwd"), b"cat/etc/passwd");
        // Nothing to change: borrowed, not reallocated.
        assert!(matches!(tr.transform(b"already normal"), Cow::Borrowed(_)));
    }

    #[test]
    fn normalize_path_win_keeps_forward_slashes() {
        let tr = NormalizePathWin;
        assert_eq!(t(&tr, br"\etc\\passwd"), b"/etc/passwd");
        assert_eq!(t(&tr, b"/.claude/settings.json"), b"/.claude/settings.json");
    }

    #[test]
    fn escape_seq_decode_writes_bytes() {
        assert_eq!(
            t(&EscapeSeqDecode, br"\xac\xED\0\5\377"),
            b"\xac\xed\x00\x05\xff"
        );
    }

    #[test]
    fn comments() {
        assert_eq!(t(&RemoveComments, b"a/*x*/b<!--y-->c-- d"), b"abc");
        assert_eq!(t(&RemoveComments, b"a/*open"), b"a ");
        assert_eq!(t(&ReplaceComments, b"a/*x*/b/*open"), b"a b ");
        assert_eq!(t(&RemoveCommentsChar, b"a/*b*/c<!--d-->e--f#g"), b"abcdefg");
    }

    #[test]
    fn sql_hex_decode() {
        assert_eq!(t(&SqlHexDecode, b"0x414243 0x4 0X61"), b"ABC 0x4 a");
    }
}
