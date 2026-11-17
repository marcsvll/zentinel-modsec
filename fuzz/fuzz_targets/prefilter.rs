//! The prefilter against the regular expression it stands for. The input is a pattern
//! and a value, split at the first NUL. If the pattern compiles over bytes, as `@rx`
//! compiles it, and matches the value, the value must satisfy what the prefilter says a
//! match needs: its classes of bytes (`Need`) and, compared without regard to ASCII case,
//! one of its literals. A value that matches and does not satisfy them is a value the
//! engine would skip and ModSecurity would catch: a bypass.
#![no_main]
use libfuzzer_sys::fuzz_target;
use zentinel_modsec::operators::{Operator, RxOperator};
use zentinel_modsec::prefilter::{classes, contains_any};

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
    // As a rule's @rx: the same rewriting of `\x{HH}`, the same fallback to
    // characters (where the operator claims nothing).
    let Ok(op) = RxOperator::new(pattern) else {
        return;
    };
    if !op.execute(value).matched {
        return;
    }
    if let Some(need) = op.need() {
        assert!(
            need.allows(classes(value)),
            "{pattern:?} matches {value:?}, which lacks a class the prefilter needs"
        );
    }
    if let Some(literals) = op.literals() {
        assert!(
            contains_any(value, &literals),
            "{pattern:?} matches {value:?}, which holds none of {literals:?}"
        );
    }
});
