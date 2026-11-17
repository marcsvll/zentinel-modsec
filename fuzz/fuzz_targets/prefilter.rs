//! The prefilter against the regular expression it stands for. The input is a pattern
//! and a value, split at the first NUL. If the pattern compiles over bytes, as `@rx`
//! compiles it, and matches the value, the value must satisfy what the prefilter says a
//! match needs: its classes of bytes (`Need`) and, compared without regard to ASCII case,
//! one of its literals. A value that matches and does not satisfy them is a value the
//! engine would skip and ModSecurity would catch: a bypass.
#![no_main]
use libfuzzer_sys::fuzz_target;
use zentinel_modsec::prefilter::{classes, contains_any, regex_literals, Need};

fuzz_target!(|data: &[u8]| {
    let Some(split) = data.iter().position(|&b| b == 0) else {
        return;
    };
    let (pattern, value) = (&data[..split], &data[split + 1..]);
    let Ok(pattern) = std::str::from_utf8(pattern) else {
        return;
    };
    if pattern.len() > 256 || value.len() > 4096 {
        return;
    }
    let Ok(hir) = regex_syntax::ParserBuilder::new()
        .unicode(false)
        .utf8(false)
        .nest_limit(32)
        .build()
        .parse(pattern)
    else {
        return;
    };
    let Ok(regex) = regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .size_limit(1 << 20)
        .build()
    else {
        return;
    };
    if !regex.is_match(value) {
        return;
    }
    if let Some(need) = Need::of_regex(&hir) {
        assert!(
            need.allows(classes(value)),
            "{pattern:?} matches {value:?}, which lacks a class the prefilter needs"
        );
    }
    if let Some(literals) = regex_literals(&hir) {
        assert!(
            contains_any(value, &literals),
            "{pattern:?} matches {value:?}, which holds none of {literals:?}"
        );
    }
});
