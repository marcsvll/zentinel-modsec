//! `@detectSQLi` and `@detectXSS` over arbitrary bytes, with no rule set in between: the
//! operators hand the value to the `libinjectionrs` port. Nothing may panic; a slow
//! input is caught by the run's `-timeout`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use zentinel_modsec::operators::{DetectSqliOperator, DetectXssOperator, Operator};

fuzz_target!(|data: &[u8]| {
    let _ = DetectSqliOperator.execute(data);
    let _ = DetectXssOperator.execute(data);
});
