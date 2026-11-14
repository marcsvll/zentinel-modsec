//! Compiles the C libinjection fetched by `fetch.sh` (or found at
//! `LIBINJECTION_C_DIR`) into this crate.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=LIBINJECTION_C_DIR");
    let dir = std::env::var_os("LIBINJECTION_C_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("libinjection-c"));
    let src = dir.join("src");
    assert!(
        src.join("libinjection_sqli.c").is_file(),
        "the C libinjection is not at {}: run differential/fetch.sh",
        dir.display()
    );
    println!("cargo:rerun-if-changed={}", src.display());
    cc::Build::new()
        .file(src.join("libinjection_sqli.c"))
        .file(src.join("libinjection_xss.c"))
        .file(src.join("libinjection_html5.c"))
        .include(&src)
        // Its build system writes the version; nothing here reads it.
        .define("LIBINJECTION_VERSION", "\"differential\"")
        .warnings(false)
        .compile("injection");
}
