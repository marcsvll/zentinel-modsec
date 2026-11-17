//! Transformations and operators against ModSecurity's own vectors.
//!
//! `owasp-modsecurity/secrules-language-tests` is the set libmodsecurity's unit
//! tests run: for each transformation an input and the output ModSecurity
//! produces, for each operator an input, a parameter and whether it matches
//! (and, with `capture`, what `TX:0` holds). They are read the way
//! libmodsecurity's runner reads them (`test/unit/unit_test.cc`): the JSON
//! string as UTF-8, then every `\xHH` and `\uHHHH` written in it replaced by the
//! byte it names (the low byte, for the four-digit form), in both the input and
//! the expected output.
//!
//! The vectors are not in this repository (they carry no licence file):
//! `vectors/fetch.sh` downloads them by commit. Without the checkout the test
//! says so and passes; the gate fetches them first.
//!
//! Where this engine differs from ModSecurity on purpose, or has not caught up
//! yet, the vector is listed in `vectors/known-differences.txt` with the reason.
//! A vector that fails and is not listed fails the test; so does a listed one
//! that has started to pass, so the list cannot go stale.

use regex::bytes::Regex;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use zentinel_modsec::operators::create_operator;
use zentinel_modsec::parser::OperatorName;
use zentinel_modsec::transformations::create_transformation;

#[derive(Deserialize)]
struct Vector {
    name: String,
    #[serde(default)]
    input: String,
    #[serde(default)]
    output: Option<String>,
    #[serde(default)]
    param: Option<String>,
    #[serde(default)]
    ret: Option<i64>,
    #[serde(default)]
    capture: Option<i64>,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/secrules-language-tests")
}

/// libmodsecurity's `json2bin`: the first `\xHH` (then `\uHHHH`) written in the
/// text, and every other occurrence of the same six or four characters, becomes
/// the byte it names; repeated until none is left.
fn json2bin(text: &str) -> Vec<u8> {
    let mut bytes = text.as_bytes().to_vec();
    for (pattern, digits) in [(r"\\x([a-zA-Z0-9]{2})", 2), (r"\\u([a-zA-Z0-9]{4})", 4)] {
        let re = Regex::new(pattern).unwrap();
        while let Some(found) = re.find(&bytes) {
            let escape = found.as_bytes().to_vec();
            let hex = std::str::from_utf8(&escape[2..2 + digits]).unwrap();
            // sscanf("%x") reads the leading hexadecimal digits; none reads 0.
            let end = hex
                .find(|c: char| !c.is_ascii_hexdigit())
                .unwrap_or(hex.len());
            let value = u32::from_str_radix(&hex[..end], 16).unwrap_or(0) as u8;
            bytes = replace_all(&bytes, &escape, value);
        }
    }
    bytes
}

fn replace_all(haystack: &[u8], needle: &[u8], with: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(needle) {
            out.push(with);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

/// `kind name index` for each listed difference; `*` as the index stands for
/// every vector of that name.
fn known_differences() -> BTreeSet<(String, String, String)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/known-differences.txt");
    let text = std::fs::read_to_string(&path).expect("vectors/known-differences.txt");
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut fields = l.split_whitespace();
            let mut next = || fields.next().expect("kind name index reason").to_string();
            (next(), next(), next())
        })
        .collect()
}

fn shown(bytes: &[u8]) -> String {
    bytes.escape_ascii().to_string().chars().take(160).collect()
}

fn load(dir: &str) -> Vec<(String, usize, Vector)> {
    let mut all = Vec::new();
    let mut files: Vec<_> = std::fs::read_dir(root().join(dir))
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        let vectors: Vec<Vector> =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        for (i, v) in vectors.into_iter().enumerate() {
            let name = v.name.clone();
            all.push((name, i, v));
        }
    }
    all
}

/// What failed, as `kind name index` with a description.
fn failures() -> BTreeMap<(String, String, String), String> {
    let mut failed = BTreeMap::new();
    for (name, i, v) in load("transformations") {
        let key = ("tfn".to_string(), name.clone(), i.to_string());
        let Ok(t) = create_transformation(&name) else {
            failed.insert(key, "not implemented".to_string());
            continue;
        };
        let input = json2bin(&v.input);
        let expected = json2bin(v.output.as_deref().unwrap_or_default());
        let got = t.transform(&input);
        if got.as_ref() != expected.as_slice() {
            failed.insert(
                key,
                format!(
                    "input {} gives {}, ModSecurity {}",
                    shown(&input),
                    shown(&got),
                    shown(&expected)
                ),
            );
        }
    }
    for (name, i, v) in load("operators") {
        let key = ("op".to_string(), name.clone(), i.to_string());
        let param = v.param.clone().unwrap_or_default();
        // File parameters are written relative to libmodsecurity's test directory.
        let param = match param.strip_prefix("test-cases/secrules-language-tests/") {
            Some(rest) => root().join(rest).display().to_string(),
            None => param,
        };
        let Some(op_name) = OperatorName::from_str(&name) else {
            failed.insert(key, "not implemented".to_string());
            continue;
        };
        let op = match create_operator(op_name, &param) {
            Ok(op) => op,
            Err(e) => {
                failed.insert(key, format!("parameter {param:?} refused: {e}"));
                continue;
            }
        };
        let input = json2bin(&v.input);
        let result = op.execute(&input);
        let expected = v.ret.unwrap_or(0) != 0;
        if result.matched != expected {
            failed.insert(
                key,
                format!(
                    "{} with {param:?} on {}: ModSecurity says {}",
                    name,
                    shown(&input),
                    if expected { "match" } else { "no match" }
                ),
            );
            continue;
        }
        let output = v.output.as_deref().unwrap_or_default();
        if v.capture.unwrap_or(0) != 0 || !output.is_empty() {
            let expected = json2bin(output);
            let got = result.matched_value.clone().unwrap_or_default();
            if got != expected {
                failed.insert(
                    key,
                    format!(
                        "{name} on {}: TX:0 is {}, ModSecurity {}",
                        shown(&input),
                        shown(&got),
                        shown(&expected)
                    ),
                );
            }
        }
    }
    failed
}

#[test]
fn modsecurity_vectors() {
    if !root().join(".commit").is_file() {
        eprintln!(
            "modsecurity_vectors: no vectors at {} (vectors/fetch.sh); skipped",
            root().display()
        );
        return;
    }
    let known = known_differences();
    let failed = failures();
    let listed = |k: &(String, String, String)| {
        known.contains(k) || known.contains(&(k.0.clone(), k.1.clone(), "*".to_string()))
    };
    let unexpected: Vec<_> = failed.iter().filter(|(k, _)| !listed(k)).collect();
    let stale: Vec<_> = known
        .iter()
        .filter(|k| k.2 != "*" && !failed.contains_key(*k))
        .collect();
    for ((kind, name, i), why) in &unexpected {
        eprintln!("NEW DIFFERENCE {kind} {name} {i}: {why}");
    }
    for (kind, name, i) in &stale {
        eprintln!("NOW PASSES {kind} {name} {i}: remove it from vectors/known-differences.txt");
    }
    eprintln!(
        "modsecurity_vectors: {} vectors differ ({} listed)",
        failed.len(),
        failed.len() - unexpected.len()
    );
    assert!(
        unexpected.is_empty() && stale.is_empty(),
        "{} new differences, {} stale entries",
        unexpected.len(),
        stale.len()
    );
}
