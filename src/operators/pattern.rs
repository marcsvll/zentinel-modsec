//! Pattern matching operators (@rx, @pm).
//!
//! Optimized with lazy regex compilation for fast rule parsing.

use super::traits::{Operator, OperatorResult};
use crate::error::{Error, Result};
use aho_corasick::AhoCorasick;
use once_cell::sync::OnceCell;

/// How a pattern is compiled.
///
/// ModSecurity hands patterns to PCRE without its UTF mode: the subject is a
/// sequence of bytes, `\xHH` and `\x{HH}` are bytes, `.` and a negated class
/// take one byte, and `\w`, `\s`, `\b` and `(?i)` are ASCII. The CRS is
/// written for that (942430 spells U+2019 as `\x{e2}\x80\x99`), so that is how
/// a pattern is read here. A pattern that only makes sense with Unicode
/// (`\p{L}`, a non-ASCII character in a class, an escape above `\x{FF}`) does
/// not parse that way and is compiled over characters instead.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Bytes,
    Characters,
}

/// Both modes run over bytes; in [`Mode::Characters`] the pattern's classes
/// and `.` are Unicode-aware and match UTF-8 sequences (bytes that are not
/// UTF-8 match no character).
type Compiled = regex::bytes::Regex;

/// The pattern as the `regex` crate needs it to mean bytes. With Unicode off,
/// `\xHH` is a byte there, but `\x{HH}` stays a code point (`\x{e2}` would
/// match the two bytes of U+00E2), while PCRE without UTF reads both as the
/// byte. Braced escapes up to `FF` are rewritten to the two-digit form; a
/// larger one is left alone and sends the pattern to [`Mode::Characters`].
fn as_bytes_pattern(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut rest = pattern;
    while let Some(at) = rest.find('\\') {
        out.push_str(&rest[..at]);
        let escape = &rest[at..];
        let braced = escape.strip_prefix("\\x{").and_then(|tail| {
            let end = tail.find('}')?;
            let byte = u8::from_str_radix(&tail[..end], 16).ok()?;
            Some((byte, 4 + end))
        });
        match braced {
            Some((byte, len)) => {
                out.push_str(&format!("\\x{byte:02x}"));
                rest = &escape[len..];
            }
            None => {
                // Any other escape, its character included, so that the `x`
                // of `\\x{41}` (a literal backslash) is not read as one.
                let len = 1 + escape[1..].chars().next().map_or(0, char::len_utf8);
                out.push_str(&escape[..len]);
                rest = &escape[len..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn syntax_error(mode: Mode, pattern: &str) -> Option<String> {
    let mut parser = regex_syntax::ParserBuilder::new();
    if mode == Mode::Bytes {
        parser.unicode(false).utf8(false);
    }
    parser.build().parse(pattern).err().map(|e| e.to_string())
}

/// Regex operator (@rx) with lazy compilation.
///
/// The pattern's *syntax* is validated when the rule is loaded, but the
/// automaton is only built on first use — CRS defines hundreds of regex rules
/// and most requests exercise few of them.
///
/// The distinction matters: an invalid pattern must be a load error. If it
/// were discovered at match time there would be nothing useful to do about it,
/// and the rule would silently never match — a dead rule that looks alive.
pub struct RxOperator {
    pattern_str: String,
    mode: Mode,
    /// `None` once compilation has been attempted and failed, so a pattern
    /// that passes syntax validation but cannot be built (an oversized
    /// program, say) is reported once rather than retried per request.
    compiled: OnceCell<Option<Compiled>>,
}

impl RxOperator {
    /// Create a new regex operator, validating the pattern's syntax.
    ///
    /// Parsing with `regex-syntax` catches every syntax error the full
    /// compiler would, without building the automaton, so loading stays fast
    /// while a malformed pattern fails loudly at load instead of turning into
    /// a rule that can never match.
    #[inline]
    pub fn new(pattern: &str) -> Result<Self> {
        if pattern.is_empty() {
            return Err(Error::RegexCompile {
                pattern: pattern.to_string(),
                source: regex::Error::Syntax("empty pattern".to_string()),
            });
        }

        let as_bytes = as_bytes_pattern(pattern);
        let (mode, pattern) = if syntax_error(Mode::Bytes, &as_bytes).is_none() {
            (Mode::Bytes, as_bytes.as_str())
        } else if let Some(error) = syntax_error(Mode::Characters, pattern) {
            return Err(Error::RegexCompile {
                pattern: pattern.to_string(),
                source: regex::Error::Syntax(error),
            });
        } else {
            (Mode::Characters, pattern)
        };

        Ok(Self {
            pattern_str: pattern.to_string(),
            mode,
            compiled: OnceCell::new(),
        })
    }

    /// Get or compile the regex pattern.
    ///
    /// Returns `None` if compilation failed. Syntax was already validated in
    /// [`RxOperator::new`], so reaching this is rare — a program too large to
    /// build, for instance. It is reported once, because a rule that cannot
    /// match must not do so silently.
    #[inline]
    fn get_regex(&self) -> Option<&Compiled> {
        self.compiled
            .get_or_init(|| {
                let compiled = regex::bytes::RegexBuilder::new(&self.pattern_str)
                    .unicode(self.mode == Mode::Characters)
                    .build();
                match compiled {
                    Ok(regex) => Some(regex),
                    Err(e) => {
                        tracing::error!(
                            pattern = %self.pattern_str,
                            error = %e,
                            "regex could not be compiled at first use; this rule can never match"
                        );
                        None
                    }
                }
            })
            .as_ref()
    }
}

impl Operator for RxOperator {
    fn execute(&self, value: &[u8]) -> OperatorResult {
        let Some(regex) = self.get_regex() else {
            return OperatorResult::no_match();
        };

        // Nearly every value matches nothing. Asking for the groups reserves
        // room for all of them before searching -- several hundred bytes for
        // the larger CRS patterns, on every value of every rule -- so ask
        // first whether there is a match at all, which reserves nothing.
        if !regex.is_match(value) {
            return OperatorResult::no_match();
        }
        let Some(captures) = regex.captures(value) else {
            return OperatorResult::no_match();
        };
        OperatorResult {
            matched: true,
            matched_value: captures.get(0).map(|m| m.as_bytes().to_vec()),
            // A group that did not take part keeps its slot, empty, so TX:2 is
            // always the second group.
            captures: captures
                .iter()
                .skip(1)
                .map(|c| c.map(|m| m.as_bytes().to_vec()).unwrap_or_default())
                .collect(),
        }
    }

    fn name(&self) -> &'static str {
        "rx"
    }

    fn supports_capture(&self) -> bool {
        true
    }
}

/// Phrase match operator (@pm).
pub struct PmOperator {
    automaton: AhoCorasick,
    patterns: Vec<String>,
}

impl PmOperator {
    /// Create a new phrase match operator from space-separated patterns.
    pub fn new(patterns_str: &str) -> Result<Self> {
        let patterns: Vec<String> = patterns_str
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        if patterns.is_empty() {
            return Err(Error::PatternSet {
                message: "empty pattern list".to_string(),
            });
        }

        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .map_err(|e| Error::PatternSet {
                message: e.to_string(),
            })?;

        Ok(Self {
            automaton,
            patterns,
        })
    }

    /// Create a phrase match operator from a file.
    pub fn from_file(path: &str) -> Result<Self> {
        // Try the path as-is first, then common CRS locations
        let possible_paths = [
            path.to_string(),
            format!("test-rules/crs/rules/{}", path),
            format!("rules/{}", path),
        ];

        let mut content = None;
        let mut last_error = None;

        for p in &possible_paths {
            match std::fs::read_to_string(p) {
                Ok(c) => {
                    content = Some(c);
                    break;
                }
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        let content = content.ok_or_else(|| Error::RuleFileLoad {
            path: path.into(),
            source: last_error.unwrap(),
        })?;

        let patterns: Vec<String> = content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|s| s.to_string())
            .collect();

        if patterns.is_empty() {
            return Err(Error::PatternSet {
                message: "empty pattern file".to_string(),
            });
        }

        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .map_err(|e| Error::PatternSet {
                message: e.to_string(),
            })?;

        Ok(Self {
            automaton,
            patterns,
        })
    }
}

impl Operator for PmOperator {
    fn execute(&self, value: &[u8]) -> OperatorResult {
        if let Some(mat) = self.automaton.find(value) {
            let matched = &self.patterns[mat.pattern().as_usize()];
            OperatorResult::matched(matched.as_bytes())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "pm"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rx_simple() {
        let op = RxOperator::new("^admin").unwrap();
        assert!(op.execute(b"admin").matched);
        assert!(!op.execute(b"user").matched);
    }

    #[test]
    fn test_rx_captures() {
        let op = RxOperator::new(r"user=(\w+)").unwrap();
        let result = op.execute(b"user=john");
        assert!(result.matched);
        assert_eq!(result.captures, vec![b"john".to_vec()]);
    }

    #[test]
    fn test_pm_simple() {
        let op = PmOperator::new("admin root user").unwrap();
        assert!(op.execute(b"the admin user").matched);
        assert!(!op.execute(b"guest").matched);
    }

    #[test]
    fn test_pm_case_insensitive() {
        let op = PmOperator::new("ADMIN").unwrap();
        assert!(op.execute(b"admin").matched);
        assert!(op.execute(b"Admin").matched);
    }
}
