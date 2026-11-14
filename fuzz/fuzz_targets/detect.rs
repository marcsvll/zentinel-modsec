//! `@detectSQLi` and `@detectXSS` over arbitrary text, with no rule set in between: the
//! operators hand the value to the `libinjectionrs` port. Nothing may panic; a slow
//! input is caught by the run's `-timeout`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use zentinel_modsec::operators::{DetectSqliOperator, DetectXssOperator, Operator};

fuzz_target!(|data: &[u8]| {
    let value = String::from_utf8_lossy(data);
    let _ = DetectSqliOperator.execute(&value);
    let _ = DetectXssOperator.execute(&value);
});
