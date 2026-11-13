//! The engine's request path: a fixed rule set with the operators, transformation
//! chains and variables the CRS uses, evaluated over an arbitrary request. The input is
//! HTTP/1.1 wire format: request line, header lines, a blank line, then the body (`\r\n`
//! or `\n`). Content-Type comes from the input, so every body processor (urlencoded,
//! multipart, JSON, XML) is reached. Nothing may panic; a slow input is caught by the
//! run's `-timeout`.
#![no_main]
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use zentinel_modsec::ModSecurity;

const RULES: &str = r#"
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 1048576
SecRequestBodyNoFilesLimit 131072
SecAction "id:900000,phase:1,pass,nolog,setvar:tx.anomaly_score=0,setvar:tx.inbound_anomaly_score_threshold=5"
SecRule REQUEST_HEADERS:Content-Type "@rx ^(?i)application/x-www-form-urlencoded" "id:900001,phase:1,pass,nolog,ctl:requestBodyProcessor=URLENCODED"
SecRule REQUEST_HEADERS:Content-Type "@rx ^(?i)multipart/form-data" "id:900002,phase:1,pass,nolog,ctl:requestBodyProcessor=MULTIPART"
SecRule REQUEST_HEADERS:Content-Type "@rx ^(?i)application/(?:[a-z0-9.-]+\+)?json" "id:900003,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQUEST_HEADERS:Content-Type "@rx ^(?i)(?:text|application)/(?:[a-z0-9.-]+\+)?xml" "id:900004,phase:1,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_URI|REQUEST_HEADERS_NAMES|REQUEST_HEADERS|ARGS_NAMES|ARGS|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|XML:/* "@validateUtf8Encoding" "id:920250,phase:2,pass,log,t:none,setvar:tx.anomaly_score=+2"
SecRule REQUEST_URI|REQUEST_HEADERS|ARGS|ARGS_NAMES "@validateByteRange 1-255" "id:920270,phase:2,pass,log,t:none,t:urlDecodeUni,setvar:tx.anomaly_score=+5"
SecRule REQUEST_FILENAME "@rx (?i)(?:\.{2,}|%2e%2e)[/\\]" "id:930100,phase:1,pass,log,t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,t:cmdLine,setvar:tx.anomaly_score=+5"
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)(?:;|\{|\||\|\||&|&&|\n|\r|\$\(|\$\(\(|`|\${|<\(|>\(|\(\s*\))\s*(?:[\w'\"./]+/)?[\"'\s]*(?:nc|ping|wget|curl)" "id:932230,phase:2,pass,log,capture,t:none,t:urlDecodeUni,t:cmdLine,t:normalizePath,t:compressWhitespace,setvar:tx.anomaly_score=+5,setvar:tx.cmd=%{TX.0}"
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|ARGS_NAMES|ARGS|XML:/* "@detectSQLi" "id:942100,phase:2,pass,log,t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,setvar:tx.anomaly_score=+5"
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|ARGS_NAMES|ARGS|XML:/* "@detectXSS" "id:941100,phase:2,pass,log,t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,setvar:tx.anomaly_score=+5"
SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,t:none,log,pass,setvar:tx.anomaly_score=+5"
SecRule MULTIPART_STRICT_ERROR "!@eq 0" "id:200003,phase:2,t:none,log,pass,setvar:tx.anomaly_score=+5"
SecRule MULTIPART_UNMATCHED_BOUNDARY "@eq 1" "id:200004,phase:2,t:none,log,pass,setvar:tx.anomaly_score=+5"
SecRule FILES|FILES_NAMES|MULTIPART_PART_HEADERS "@rx (?i)\.php" "id:933110,phase:2,pass,log,t:none,setvar:tx.anomaly_score=+5"
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)(?:^|[^\w])(?:select|union|insert|update|delete)\b" "id:942190,phase:2,pass,log,multiMatch,t:none,t:urlDecodeUni,t:lowercase,t:base64Decode,t:replaceComments,t:compressWhitespace,setvar:tx.anomaly_score=+3"
SecRule ARGS "@rx (?i)<\s*script" "id:941110,phase:2,pass,log,capture,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:lowercase,t:removeWhitespace,setvar:tx.xss=%{MATCHED_VAR_NAME},setvar:tx.anomaly_score=+5"
SecRule ARGS:q|ARGS:/^search$/ "@pm sleep benchmark waitfor" "id:942200,phase:2,pass,log,t:none,t:urlDecodeUni,t:lowercase,t:removeWhitespace,t:hexDecode,setvar:tx.anomaly_score=+1"
SecRule FILES|FILES_NAMES "@rx (?i)\.(?:php|phtml|jsp)$" "id:933110,phase:2,pass,log,t:none,t:lowercase,t:normalizePathWin,setvar:tx.anomaly_score=+5"
SecRule FILES_COMBINED_SIZE "@gt 1000" "id:933111,phase:2,pass,log,t:none,setvar:tx.anomaly_score=+1"
SecRule REQUEST_BODY "@rx (?i)union.{1,100}?select" "id:942300,phase:2,pass,log,t:none,t:urlDecodeUni,t:replaceNulls,t:length,setvar:tx.anomaly_score=+2"
SecRule REQUEST_HEADERS:Host "@rx ^[\d.:]+$" "id:920350,phase:1,pass,log,t:none,setvar:tx.anomaly_score=+2"
SecRule REQUEST_METHOD "!@within GET HEAD POST OPTIONS" "id:911100,phase:1,pass,log,t:none,setvar:tx.anomaly_score=+5"
SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,pass,log,t:none,setvar:tx.anomaly_score=+5"
SecRule MULTIPART_STRICT_ERROR "!@eq 0" "id:200003,phase:2,pass,log,t:none,setvar:tx.anomaly_score=+5"
SecRule ARGS "@rx ^(?:a|b)$" "id:950000,phase:2,pass,log,chain,t:none,t:trim,t:lowercase"
  SecRule ARGS_NAMES "@rx ^x" "t:none,t:sha1,t:hexEncode,setvar:tx.anomaly_score=+1"
SecRule ARGS:ctl "@unconditionalMatch" "id:950001,phase:2,pass,nolog,ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:ctl,ctl:ruleRemoveById=942200"
SecRule TX:ANOMALY_SCORE "@ge %{tx.inbound_anomaly_score_threshold}" "id:949110,phase:2,deny,status:403,log,t:none"
"#;

fn rules() -> &'static ModSecurity {
    static ENGINE: OnceLock<ModSecurity> = OnceLock::new();
    ENGINE.get_or_init(|| ModSecurity::from_string(RULES).expect("the fixed rule set loads"))
}

fuzz_target!(|data: &[u8]| {
    // A request this large only slows the run; the body limit above is 1 MiB anyway.
    if data.len() > 256 * 1024 {
        return;
    }
    let head_end = data.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2));
    let crlf_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, 4));
    let (end, sep) = match (head_end, crlf_end) {
        (Some(a), Some(b)) => std::cmp::min_by_key(a, b, |x| x.0),
        (a, b) => a.or(b).unwrap_or((data.len(), 0)),
    };
    let (head, body) = (&data[..end], data.get(end + sep..).unwrap_or(&[]));
    let mut lines = head
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let Some(line) = lines.next() else { return };
    let mut parts = line.splitn(3, |&b| b == b' ');
    let method = String::from_utf8_lossy(parts.next().unwrap_or(b"GET"));
    let uri = String::from_utf8_lossy(parts.next().unwrap_or(b"/"));

    // Errors are results here, never panics: every step runs whatever the one before said.
    let mut tx = rules().new_transaction();
    let _ = tx.process_uri(&uri, &method, "HTTP/1.1");
    for l in lines {
        let Some(colon) = l.iter().position(|&b| b == b':') else {
            continue;
        };
        let value = l.get(colon + 1..).unwrap_or(&[]);
        let value = value.strip_prefix(b" ").unwrap_or(value);
        let _ = tx.add_request_header(
            &String::from_utf8_lossy(&l[..colon]),
            &String::from_utf8_lossy(value),
        );
    }
    let _ = tx.process_request_headers();
    if !body.is_empty() {
        let _ = tx.append_request_body(body);
    }
    let _ = tx.process_request_body();
    let _ = tx.process_logging();
    let _ = (tx.has_intervention(), tx.matched_rules().len());
});
