//! The SecLang parser and rule compiler: any text either loads or returns an error.
#![no_main]
use libfuzzer_sys::fuzz_target;
use zentinel_modsec::ModSecurity;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Rule files are bounded in practice; a fuzzer-grown input past this size only slows
    // the run without reaching new code.
    if text.len() > 64 * 1024 {
        return;
    }
    // `Include` and the `FromFile` operators read files: the parser is the subject here,
    // not the filesystem of the machine running the fuzzer.
    let lower = text.to_ascii_lowercase();
    if lower.contains("include") || lower.contains("fromfile") {
        return;
    }
    let _ = ModSecurity::from_string(text);
});
