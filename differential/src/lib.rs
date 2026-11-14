//! The two detectors side by side: the engine's `@detectSQLi` and `@detectXSS`
//! (the `libinjectionrs` port) and the C libinjection the port was translated
//! from. Development only; see `README.md`.

use std::ffi::{c_char, c_int};

use zentinel_modsec::operators::{DetectSqliOperator, DetectXssOperator, Operator};

extern "C" {
    fn libinjection_sqli(s: *const c_char, slen: usize, fingerprint: *mut c_char) -> c_int;
    fn libinjection_xss(s: *const c_char, slen: usize) -> c_int;
}

/// What a detector says about one value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The fingerprint when the value is SQL injection.
    pub sqli: Option<String>,
    /// Whether the value is XSS.
    pub xss: bool,
}

/// Zero bytes kept after the value handed to the C library. Its XSS check
/// compares an attribute name with each event-handler name over the length of
/// the handler name, so a short attribute at the end of the input is read past
/// its end (`is_black_attr`, found by the fuzz target here under
/// AddressSanitizer). The padding makes that read land on zeros, the same
/// every time.
const PADDING: usize = 64;

/// The C library's verdict.
pub fn c(value: &str) -> Verdict {
    let mut input = Vec::with_capacity(value.len() + PADDING);
    input.extend_from_slice(value.as_bytes());
    input.resize(value.len() + PADDING, 0);
    // libinjection writes at most 8 bytes, NUL included; the buffer is larger
    // and zeroed.
    let mut fingerprint = [0 as c_char; 16];
    // SAFETY: the pointer and length describe the start of `input`, which
    // outlives the call and is only read, and which holds PADDING readable
    // bytes past the length; `fingerprint` is writable and larger than the
    // library ever writes.
    let is_sqli =
        unsafe { libinjection_sqli(input.as_ptr().cast(), value.len(), fingerprint.as_mut_ptr()) }
            != 0;
    // SAFETY: as above; the call only reads `input`.
    let xss = unsafe { libinjection_xss(input.as_ptr().cast(), value.len()) } != 0;
    let sqli = is_sqli.then(|| {
        fingerprint
            .iter()
            .take_while(|b| **b != 0)
            .map(|b| *b as u8 as char)
            .collect()
    });
    Verdict { sqli, xss }
}

/// The engine's verdict, through the operators the rules call.
pub fn engine(value: &str) -> Verdict {
    let sqli = DetectSqliOperator.execute(value);
    Verdict {
        sqli: sqli.matched.then(|| sqli.matched_value.unwrap_or_default()),
        xss: DetectXssOperator.execute(value).matched,
    }
}

/// A disagreement that is understood: the name of its cause in `README.md`,
/// when the value has what triggers one. A disagreement with no cause is a
/// finding.
pub fn known_cause(value: &str, ours: &Verdict, theirs: &Verdict) -> Option<&'static str> {
    if ours.sqli != theirs.sqli {
        let lower = value.to_ascii_lowercase();
        let sp_password_not_lower = lower
            .match_indices("sp_password")
            .any(|(at, word)| value[at..at + word.len()] != *word);
        if sp_password_not_lower {
            return Some("sp_password compared without its case");
        }
    } else if theirs.xss && !ours.xss {
        // An attribute name that starts with "on" and is long enough for the
        // C library's event-handler check, which compares a prefix.
        let on_attribute = value
            .split(|c: char| c.is_ascii_whitespace() || "\u{b}<>/='\"`".contains(c))
            .any(|name| name.len() >= 5 && name.as_bytes()[..2].eq_ignore_ascii_case(b"on"));
        if on_attribute {
            return Some("event handler names compared as a prefix");
        }
    }
    // Last, so that it takes only what nothing above explains.
    value.contains('\0').then_some("a NUL inside the value")
}
