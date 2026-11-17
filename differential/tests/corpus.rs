//! Every value of the corpora below goes through both detectors; they must
//! agree on the SQL-injection verdict, the fingerprint and the XSS verdict,
//! except for the causes `known_cause` names (`README.md`).
//!
//! Corpora: the C library's own samples (`libinjection-c/data`), always; every
//! string of every YAML file under the directories named in
//! `DIFFERENTIAL_YAML_DIRS` (colon-separated: the OWASP CRS regression tests,
//! GoTestWAF's test cases), when set. Each string is tried as written,
//! URL-decoded, and cut at `?`, `&` and `=`. `DIFFERENTIAL_RAW_DIRS` names
//! directories whose files are one value each (a fuzz corpus).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use percent_encoding::percent_decode;
use zentinel_modsec_differential::{c, engine, known_cause};

fn url_decoded(text: &str) -> String {
    let plus = text.replace('+', " ");
    String::from_utf8_lossy(&percent_decode(plus.as_bytes()).collect::<Vec<u8>>()).into_owned()
}

fn add(values: &mut BTreeSet<String>, text: &str) {
    for form in [text.to_string(), url_decoded(text)] {
        for piece in form.split(['?', '&', '=']) {
            if !piece.is_empty() {
                values.insert(piece.to_string());
            }
        }
        if !form.is_empty() {
            values.insert(form);
        }
    }
}

fn strings(value: &serde_yaml::Value, values: &mut BTreeSet<String>) {
    match value {
        serde_yaml::Value::String(s) => add(values, s),
        serde_yaml::Value::Sequence(items) => items.iter().for_each(|v| strings(v, values)),
        serde_yaml::Value::Mapping(map) => map.values().for_each(|v| strings(v, values)),
        _ => {}
    }
}

fn files(dir: &Path, extensions: &[&str]) -> Vec<PathBuf> {
    walkdir::WalkDir::new(dir)
        .sort_by_file_name()
        .into_iter()
        .filter_map(Result::ok)
        .map(|e| e.into_path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| extensions.contains(&e))
        })
        .collect()
}

fn corpus() -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    let c_dir = std::env::var_os("LIBINJECTION_C_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("libinjection-c"));
    let samples = files(&c_dir.join("data"), &["txt"]);
    assert!(!samples.is_empty(), "no samples under {}", c_dir.display());
    for file in samples {
        let text =
            String::from_utf8_lossy(&std::fs::read(&file).expect("sample file")).into_owned();
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            add(&mut values, line);
        }
    }
    println!("C library samples: {} values", values.len());
    for dir in std::env::var("DIFFERENTIAL_YAML_DIRS")
        .unwrap_or_default()
        .split(':')
        .filter(|d| !d.is_empty())
    {
        let before = values.len();
        let yaml = files(Path::new(dir), &["yaml", "yml"]);
        assert!(!yaml.is_empty(), "no YAML under {dir}");
        for file in yaml {
            let text =
                String::from_utf8_lossy(&std::fs::read(&file).expect("yaml file")).into_owned();
            for document in serde_yaml::Deserializer::from_str(&text) {
                // A document that does not parse ends the file: the iterator
                // does not move past it.
                let Ok(value) = serde::Deserialize::deserialize(document) else {
                    break;
                };
                strings(&value, &mut values);
            }
        }
        println!("{dir}: {} more values", values.len() - before);
    }
    // Directories whose files are one value each, as a fuzz corpus is.
    for dir in std::env::var("DIFFERENTIAL_RAW_DIRS")
        .unwrap_or_default()
        .split(':')
        .filter(|d| !d.is_empty())
    {
        let before = values.len();
        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(Result::ok)
        {
            if entry.file_type().is_file() {
                let bytes = std::fs::read(entry.path()).expect("raw file");
                values.insert(String::from_utf8_lossy(&bytes).into_owned());
            }
        }
        println!("{dir}: {} more values", values.len() - before);
    }
    values
}

#[test]
fn the_engine_and_the_c_library_agree() {
    let values = corpus();
    let (mut sqli, mut xss) = (0, 0);
    let mut known: BTreeMap<&str, (usize, &String)> = BTreeMap::new();
    let mut findings: BTreeMap<String, (usize, &String)> = BTreeMap::new();
    for value in &values {
        let (ours, theirs) = (engine(value), c(value));
        sqli += usize::from(theirs.sqli.is_some());
        xss += usize::from(theirs.xss);
        if ours == theirs {
            continue;
        }
        match known_cause(value, &ours, &theirs) {
            Some(cause) => {
                let entry = known.entry(cause).or_insert((0, value));
                entry.0 += 1;
                if value.len() < entry.1.len() {
                    entry.1 = value;
                }
            }
            None => {
                let kind = format!(
                    "SQLi engine {:?} C {:?}; XSS engine {} C {}",
                    ours.sqli, theirs.sqli, ours.xss, theirs.xss
                );
                let entry = findings.entry(kind).or_insert((0, value));
                entry.0 += 1;
                if value.len() < entry.1.len() {
                    entry.1 = value;
                }
            }
        }
    }
    println!(
        "{} values compared; the C library calls {sqli} SQL injection and {xss} XSS",
        values.len()
    );
    for (cause, (count, shortest)) in &known {
        println!("known, {cause}: {count} values, e.g. {shortest:?}");
    }
    // One line per kind of finding, the most frequent first, with its
    // shortest value.
    let total: usize = findings.values().map(|(count, _)| count).sum();
    let mut kinds: Vec<_> = findings.into_iter().collect();
    kinds.sort_by_key(|(_, (count, _))| std::cmp::Reverse(*count));
    for (kind, (count, shortest)) in kinds.iter().take(60) {
        println!("{count:>6}  {kind}  e.g. {shortest:?}");
    }
    assert!(
        total == 0,
        "{total} values on which the engine and the C library disagree for no known cause ({} kinds, above)",
        kinds.len()
    );
}

/// What the misses cost behind the OWASP CRS: each value the C library calls
/// SQL injection or XSS and the engine does not is sent as a query argument
/// to the CRS at its default paranoia level, in blocking mode. Informational:
/// it prints how many are still refused by other rules and lists the ones
/// that pass. Runs when `CRS_DIR` names a CRS checkout.
#[test]
fn what_the_crs_still_refuses_of_the_misses() {
    let Ok(dir) = std::env::var("CRS_DIR") else {
        println!("CRS_DIR is not set: skipped");
        return;
    };
    let dir = std::fs::canonicalize(dir).expect("CRS_DIR");
    let d = dir.display();
    let rules =
        format!("SecRuleEngine On\nInclude \"{d}/crs-setup.conf\"\nInclude \"{d}/rules/*.conf\"\n");
    let crs = zentinel_modsec::ModSecurity::from_string(&rules).expect("the CRS loads");
    let values = corpus();
    let (mut missed, mut passed) = (0, Vec::new());
    for value in &values {
        if value.contains('\0') {
            continue; // the CRS removes NULs before these operators
        }
        let (ours, theirs) = (engine(value), c(value));
        let miss = (theirs.sqli.is_some() && ours.sqli.is_none()) || (theirs.xss && !ours.xss);
        if !miss {
            continue;
        }
        missed += 1;
        let query: String =
            percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC)
                .to_string();
        let mut tx = crs.new_transaction();
        tx.process_uri(format!("/?q={query}"), "GET", "HTTP/1.1")
            .unwrap();
        for (name, header) in [
            ("Host", "example.com"),
            (
                "User-Agent",
                "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0",
            ),
            ("Accept", "*/*"),
        ] {
            tx.add_request_header(name, header).unwrap();
        }
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        if !tx.has_intervention() {
            passed.push(value);
        }
    }
    println!(
        "{missed} values the C library reports and the engine does not; the CRS lets {} of them through",
        passed.len()
    );
    passed.sort_by_key(|v| v.len());
    for value in passed.iter().take(40) {
        println!("    {value:?}");
    }
}

/// The engine answers "no" for a value of ASCII letters, digits and
/// underscores without calling libinjection (`is_one_plain_token` there). The
/// C library must never report such a value: every one in the corpora, every
/// single-word entry of its keyword table, and number spellings.
#[test]
fn the_c_library_never_reports_a_single_word_or_number() {
    let plain = |v: &str| v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    let mut values: BTreeSet<String> = corpus().into_iter().filter(|v| plain(v)).collect();
    let c_dir = std::env::var_os("LIBINJECTION_C_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("libinjection-c"));
    let table =
        std::fs::read_to_string(c_dir.join("src/sqlparse_data.json")).expect("the keyword table");
    // Every quoted string of the table that is one plain word: keywords,
    // functions, types, and fingerprints, in both cases.
    for word in table.split('"').filter(|w| !w.is_empty() && plain(w)) {
        values.insert(word.to_string());
        values.insert(word.to_ascii_lowercase());
    }
    for number in [
        "0", "007", "1e5", "1E5", "0x", "0x41", "0X41", "0b", "0b1", "0B101", "1_000", "x41", "n1",
        "b1", "e1", "u0041", "_", "__a",
    ] {
        values.insert(number.to_string());
    }
    assert!(values.len() > 1000, "only {} plain values", values.len());
    for value in &values {
        assert_eq!(c(value).sqli, None, "the C library reports {value:?}");
        assert_eq!(engine(value).sqli, None, "the engine reports {value:?}");
    }
    println!("{} single words and numbers, none reported", values.len());
}
