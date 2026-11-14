//! The engine's `@detectSQLi` and `@detectXSS` against the C libinjection over
//! arbitrary text: a different verdict or fingerprint is a crash, unless it
//! has one of the known causes (`README.md`).
//!
//! With `DIFFERENTIAL_COLLECT=<directory>` a disagreement is written there, one
//! file per value, and the run goes on: a survey instead of a first finding.
//! `DIFFERENTIAL_RAW_DIRS=<directory> cargo test` then lists them by cause.
#![no_main]
use std::hash::{DefaultHasher, Hash, Hasher};

use libfuzzer_sys::fuzz_target;
use zentinel_modsec_differential::{c, engine, known_cause};

fuzz_target!(|data: &[u8]| {
    let value = String::from_utf8_lossy(data);
    let (ours, theirs) = (engine(&value), c(&value));
    if ours == theirs || known_cause(&value, &ours, &theirs).is_some() {
        return;
    }
    match std::env::var_os("DIFFERENTIAL_COLLECT") {
        Some(dir) => {
            let mut hasher = DefaultHasher::new();
            value.hash(&mut hasher);
            let file = std::path::Path::new(&dir).join(format!("{:016x}", hasher.finish()));
            let _ = std::fs::write(file, value.as_bytes());
        }
        None => panic!("engine {ours:?} and C {theirs:?} disagree on {value:?}"),
    }
});
