//! `FILES_SIZES` and `FILES_COMBINED_SIZE` from the multipart body processor;
//! CRS 920410 compares the combined size with `tx.combined_file_sizes`.

use zentinel_modsec::ModSecurity;

fn blocked(rules: &str, body: &str) -> bool {
    let m = ModSecurity::from_string(rules).expect("rules load");
    let mut tx = m.new_transaction();
    tx.process_uri("/upload", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "multipart/form-data; boundary=b")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(body.as_bytes()).unwrap();
    tx.process_request_body().unwrap();
    tx.has_intervention()
}

fn multipart(files: &[(&str, usize)]) -> String {
    let mut body = String::new();
    for (name, size) in files {
        body.push_str(&format!(
            "--b\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{name}.txt\"\r\nContent-Type: text/plain\r\n\r\n{}\r\n",
            "1".repeat(*size)
        ));
    }
    body.push_str("--b--\r\n");
    body
}

#[test]
fn the_combined_size_is_the_sum_of_the_uploaded_files() {
    let rules = "SecRuleEngine On\n\
        SecAction \"id:900000,phase:1,pass,nolog,setvar:tx.combined_file_sizes=100\"\n\
        SecRule &TX:COMBINED_FILE_SIZES \"@eq 1\" \"id:920410,phase:2,deny,t:none,chain\"\n\
        SecRule FILES_COMBINED_SIZE \"@gt %{tx.combined_file_sizes}\" \"t:none\"";
    assert!(blocked(rules, &multipart(&[("a", 60), ("b", 60)])));
    assert!(!blocked(rules, &multipart(&[("a", 60), ("b", 30)])));
}

#[test]
fn each_file_has_its_size() {
    let rules = "SecRuleEngine On\nSecRule FILES_SIZES:big \"@gt 50\" \"id:1,phase:2,deny,t:none\"";
    assert!(blocked(rules, &multipart(&[("small", 10), ("big", 70)])));
    assert!(!blocked(rules, &multipart(&[("small", 10), ("big", 20)])));
}
