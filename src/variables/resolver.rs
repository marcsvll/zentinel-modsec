//! Variable resolution engine.

use super::{RequestData, ResponseData, TxCollection};
use crate::parser::{Selection, VariableName, VariableSpec, XmlTarget};
use once_cell::sync::Lazy;
use regex::bytes::Regex;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Compile a regex written in rule text (an `ARGS:/.../` selection or a
/// `!ARGS:/.../` exclusion), once per pattern.
///
/// These used to be compiled on every evaluation, once per resolved key for an
/// exclusion. Compiling costs orders of magnitude more than matching: CRS
/// 942431's two `!ARGS_NAMES:/.../` exclusions took ~5.5ms per request on
/// clean traffic, for patterns that never change.
///
/// Patterns come only from loaded rules, so the cache is bounded by the rule
/// set. A pattern that does not compile is cached as `None` and never matches,
/// as before.
///
/// The compiled regex is handed out behind an `Arc`, not as a clone: a cloned
/// `Regex` shares the program but starts with an empty pool of matcher state,
/// so the first match on every clone builds that state again. With one clone
/// per resolved key, a `!ARGS_NAMES:/.../` exclusion over a JSON body with two
/// thousand keys cost 10 ms, nearly all of it building state to match one key.
fn cached_regex(pattern: &str) -> Option<Arc<Regex>> {
    static CACHE: Lazy<RwLock<HashMap<String, Option<Arc<Regex>>>>> = Lazy::new(Default::default);
    if let Some(hit) = CACHE.read().unwrap_or_else(|e| e.into_inner()).get(pattern) {
        return hit.clone();
    }
    // Over bytes, as `@rx` reads them (a key need not be UTF-8); a pattern
    // that only makes sense over characters is compiled that way.
    let compiled = regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .or_else(|_| Regex::new(pattern))
        .ok()
        .map(Arc::new);
    CACHE
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .entry(pattern.to_string())
        .or_insert(compiled)
        .clone()
}

/// Resolved variables: the name each value is known by (`ARGS:q`) and the
/// value, both as bytes.
pub type Vals = Vec<(Vec<u8>, Vec<u8>)>;

/// One resolved variable that is not a collection member.
fn named(name: &str, value: impl Into<Vec<u8>>) -> Vals {
    vec![(name.as_bytes().to_vec(), value.into())]
}

/// `PREFIX:key`.
fn qualified(prefix: &str, key: &[u8]) -> Vec<u8> {
    let mut name = Vec::with_capacity(prefix.len() + 1 + key.len());
    name.extend_from_slice(prefix.as_bytes());
    name.push(b':');
    name.extend_from_slice(key);
    name
}

/// Variable resolver for transaction context.
pub struct VariableResolver<'a> {
    request: &'a RequestData,
    response: &'a ResponseData,
    tx: &'a TxCollection,
    matched_var: Option<&'a [u8]>,
    matched_vars: &'a [(Vec<u8>, Vec<u8>)],
    /// Carried alongside the other resolver inputs for symmetry; no variable
    /// reads it yet (`TX:0`..`TX:9` are served from the TX collection).
    #[allow(dead_code)]
    captures: &'a [Vec<u8>],
}

impl<'a> VariableResolver<'a> {
    /// Create a new resolver.
    pub fn new(
        request: &'a RequestData,
        response: &'a ResponseData,
        tx: &'a TxCollection,
        matched_var: Option<&'a [u8]>,
        matched_vars: &'a [(Vec<u8>, Vec<u8>)],
        captures: &'a [Vec<u8>],
    ) -> Self {
        Self {
            request,
            response,
            tx,
            matched_var,
            matched_vars,
            captures,
        }
    }

    /// Resolve a variable specification to values.
    pub fn resolve(&self, spec: &VariableSpec) -> Vals {
        let values = self.resolve_unfiltered(spec);

        // Apply exclusions
        if spec.exclusions.is_empty() {
            values
        } else {
            values
                .into_iter()
                .filter(|(k, _)| !is_excluded(spec, k))
                .collect()
        }
    }

    /// The values a specification selects, before its exclusions
    /// (`!ARGS:x`): what rules naming the same variable have in common.
    pub(crate) fn resolve_unfiltered(&self, spec: &VariableSpec) -> Vals {
        self.resolve_variable(spec.name, &spec.selection)
    }

    /// Resolve a variable by name.
    fn resolve_variable(&self, name: VariableName, selection: &Option<Selection>) -> Vals {
        match name {
            // Request variables
            VariableName::RequestUri => named("REQUEST_URI", self.request.uri.clone()),
            VariableName::RequestUriRaw => named("REQUEST_URI_RAW", self.request.uri_raw.clone()),
            VariableName::RequestMethod => named("REQUEST_METHOD", self.request.method.clone()),
            VariableName::RequestProtocol => {
                named("REQUEST_PROTOCOL", self.request.protocol.clone())
            }
            VariableName::QueryString => named("QUERY_STRING", self.request.query_string.clone()),
            VariableName::RequestFilename => named("REQUEST_FILENAME", self.request.path.clone()),
            VariableName::RequestLine => {
                // The request line as it arrived. CRS 920100 tests this with a
                // negated regex, so leaving it unresolved made that rule match
                // every request rather than none.
                let uri = if self.request.uri_raw.is_empty() {
                    &self.request.uri
                } else {
                    &self.request.uri_raw
                };
                let mut line = Vec::with_capacity(uri.len() + 16);
                line.extend_from_slice(self.request.method.as_bytes());
                line.push(b' ');
                line.extend_from_slice(uri);
                line.push(b' ');
                line.extend_from_slice(self.request.protocol.as_bytes());
                named("REQUEST_LINE", line)
            }
            VariableName::RequestBasename => {
                // Final path segment. ModSecurity splits on both separators, so
                // a Windows-style path does not hide the basename.
                let basename = self
                    .request
                    .path
                    .rsplit(|&b| b == b'/' || b == b'\\')
                    .next()
                    .unwrap_or_default()
                    .to_vec();
                named("REQUEST_BASENAME", basename)
            }
            VariableName::ArgsCombinedSize => {
                use super::collection::Collection;
                let size: usize = [&self.request.args_get, &self.request.args_post]
                    .iter()
                    .flat_map(|c| c.all())
                    .map(|(name, value)| name.len() + value.len())
                    .sum();
                named("ARGS_COMBINED_SIZE", size.to_string())
            }
            VariableName::RequestBody => {
                // ModSecurity v2 fills REQUEST_BODY only when the URLENCODED
                // processor handled the body; with the XML processor the body is
                // reached through XML:/* and XML://@* instead. The CRS regression
                // suite expects that: 944100-11 sends
                // `<java.lang.Runtime>value</java.lang.Runtime>` and must not
                // match `java\.lang\.runtime` over REQUEST_BODY (libmodsecurity
                // v3 does fill it and fails those tests, CRS nginx-overrides.yaml).
                if self.request.body_processor == "XML" {
                    vec![]
                } else {
                    named("REQUEST_BODY", self.request.body.clone())
                }
            }
            VariableName::RequestBodyLength => named(
                "REQUEST_BODY_LENGTH",
                self.request.body_length().to_string(),
            ),

            // Collections
            VariableName::Args => self.resolve_collection_from_all_args(selection),
            VariableName::ArgsGet => {
                self.resolve_collection(&self.request.args_get, "ARGS_GET", selection)
            }
            VariableName::ArgsPost => {
                self.resolve_collection(&self.request.args_post, "ARGS_POST", selection)
            }
            VariableName::ArgsNames => self.resolve_collection_names(
                &[&self.request.args_get, &self.request.args_post],
                "ARGS_NAMES",
                selection,
            ),
            VariableName::ArgsGetNames => self.resolve_collection_names(
                &[&self.request.args_get],
                "ARGS_GET_NAMES",
                selection,
            ),
            VariableName::ArgsPostNames => self.resolve_collection_names(
                &[&self.request.args_post],
                "ARGS_POST_NAMES",
                selection,
            ),
            VariableName::RequestHeaders => {
                self.resolve_collection_ci(&self.request.headers, "REQUEST_HEADERS", selection)
            }
            VariableName::RequestHeadersNames => self.resolve_collection_names(
                &[&self.request.headers],
                "REQUEST_HEADERS_NAMES",
                selection,
            ),
            VariableName::RequestCookies => {
                self.resolve_collection(&self.request.cookies, "REQUEST_COOKIES", selection)
            }
            VariableName::RequestCookiesNames => self.resolve_collection_names(
                &[&self.request.cookies],
                "REQUEST_COOKIES_NAMES",
                selection,
            ),

            // Multipart body processor results
            VariableName::MultipartPartHeaders => self.resolve_collection(
                &self.request.multipart_part_headers,
                "MULTIPART_PART_HEADERS",
                selection,
            ),
            VariableName::Files => self.resolve_collection(&self.request.files, "FILES", selection),
            VariableName::FilesSizes => {
                self.resolve_collection(&self.request.files_sizes, "FILES_SIZES", selection)
            }
            VariableName::FilesCombinedSize => {
                use super::collection::Collection;
                let total: u64 = self
                    .request
                    .files_sizes
                    .all()
                    .into_iter()
                    .filter_map(|(_, v)| std::str::from_utf8(v).ok()?.parse::<u64>().ok())
                    .sum();
                named("FILES_COMBINED_SIZE", total.to_string())
            }
            VariableName::FilesNames => {
                self.resolve_collection_names(&[&self.request.files], "FILES_NAMES", selection)
            }
            // What the multipart processor noticed about the framing
            // (`modsecurity.conf-recommended` rules 200003 and 200004). Absent
            // unless the multipart processor ran, as in libmodsecurity.
            VariableName::MultipartStrictCheck
            | VariableName::MultipartStrictError
            | VariableName::MultipartBoundaryQuoted
            | VariableName::MultipartBoundaryWhitespace
            | VariableName::MultipartDataAfter
            | VariableName::MultipartDataBefore
            | VariableName::MultipartFileLimitExceeded
            | VariableName::MultipartHeaderFolding
            | VariableName::MultipartInvalidHeaderFolding
            | VariableName::MultipartInvalidPart
            | VariableName::MultipartInvalidQuoting
            | VariableName::MultipartLfLine
            | VariableName::MultipartMissingSemicolon
            | VariableName::MultipartUnmatchedBoundary => {
                if self.request.body_processor != "MULTIPART" {
                    return vec![];
                }
                let m = &self.request.multipart;
                let (label, value): (&str, u8) = match name {
                    VariableName::MultipartBoundaryQuoted => {
                        ("MULTIPART_BOUNDARY_QUOTED", u8::from(m.boundary_quoted))
                    }
                    VariableName::MultipartBoundaryWhitespace => (
                        "MULTIPART_BOUNDARY_WHITESPACE",
                        u8::from(m.boundary_whitespace),
                    ),
                    VariableName::MultipartDataAfter => {
                        ("MULTIPART_DATA_AFTER", u8::from(m.data_after))
                    }
                    VariableName::MultipartDataBefore => {
                        ("MULTIPART_DATA_BEFORE", u8::from(m.data_before))
                    }
                    VariableName::MultipartFileLimitExceeded => (
                        "MULTIPART_FILE_LIMIT_EXCEEDED",
                        u8::from(m.file_limit_exceeded),
                    ),
                    VariableName::MultipartHeaderFolding => {
                        ("MULTIPART_HEADER_FOLDING", u8::from(m.header_folding))
                    }
                    VariableName::MultipartInvalidHeaderFolding => (
                        "MULTIPART_INVALID_HEADER_FOLDING",
                        u8::from(m.invalid_header_folding),
                    ),
                    VariableName::MultipartInvalidPart => {
                        ("MULTIPART_INVALID_PART", u8::from(m.invalid_part))
                    }
                    VariableName::MultipartInvalidQuoting => {
                        ("MULTIPART_INVALID_QUOTING", u8::from(m.invalid_quoting))
                    }
                    VariableName::MultipartLfLine => ("MULTIPART_LF_LINE", u8::from(m.lf_line)),
                    VariableName::MultipartMissingSemicolon => {
                        ("MULTIPART_MISSING_SEMICOLON", u8::from(m.missing_semicolon))
                    }
                    VariableName::MultipartUnmatchedBoundary => {
                        ("MULTIPART_UNMATCHED_BOUNDARY", m.unmatched_boundary)
                    }
                    _ => ("MULTIPART_STRICT_ERROR", u8::from(m.strict_error())),
                };
                named(label, value.to_string())
            }
            VariableName::ReqBodyProcessor => {
                if self.request.body_processor.is_empty() {
                    vec![]
                } else {
                    named("REQBODY_PROCESSOR", self.request.body_processor.clone())
                }
            }

            // A body the processor could not handle. These resolved to nothing
            // before, so CRS rule 200002 (`SecRule REQBODY_ERROR "!@eq 0"`)
            // could never fire and a rejected body passed unexamined and
            // unreported.
            //
            // REQBODY_ERROR always has a value -- "0" when the body processed
            // cleanly -- because a rule comparing it against 0 must be able to
            // find it. REQBODY_ERROR_MSG is absent unless there is a message,
            // matching ModSecurity.
            VariableName::ReqBodyError | VariableName::ReqBodyProcessorError => {
                let flag = if self.request.body_error.is_some() {
                    "1"
                } else {
                    "0"
                };
                named("REQBODY_ERROR", flag.to_string())
            }
            VariableName::ReqBodyErrorMsg | VariableName::ReqBodyProcessorErrorMsg => {
                match &self.request.body_error {
                    Some(msg) => named("REQBODY_ERROR_MSG", msg.clone()),
                    None => vec![],
                }
            }

            // Response variables
            VariableName::ResponseStatus => {
                named("RESPONSE_STATUS", self.response.status.to_string())
            }
            VariableName::ResponseBody => named("RESPONSE_BODY", self.response.body.clone()),
            VariableName::ResponseContentType => {
                named("RESPONSE_CONTENT_TYPE", self.response.content_type.clone())
            }
            VariableName::ResponseHeaders => {
                self.resolve_collection_ci(&self.response.headers, "RESPONSE_HEADERS", selection)
            }

            // TX collection
            VariableName::Xml => self.resolve_xml(selection),

            VariableName::Tx => self.resolve_tx_collection(selection),

            // Client/Server info
            VariableName::RemoteAddr => named("REMOTE_ADDR", self.request.client_ip.clone()),
            VariableName::RemotePort => named("REMOTE_PORT", self.request.client_port.to_string()),
            VariableName::ServerName => named("SERVER_NAME", self.request.server_name.clone()),
            VariableName::ServerAddr => named("SERVER_ADDR", self.request.server_addr.clone()),
            VariableName::ServerPort => named("SERVER_PORT", self.request.server_port.to_string()),

            // Matched variables
            VariableName::MatchedVar => {
                if let Some(v) = self.matched_var {
                    named("MATCHED_VAR", v)
                } else {
                    vec![]
                }
            }
            VariableName::MatchedVars => self
                .matched_vars
                .iter()
                .map(|(k, v)| (qualified("MATCHED_VARS", k), v.clone()))
                .collect(),
            VariableName::MatchedVarName => match self.matched_vars.last() {
                Some((name, _)) => named("MATCHED_VAR_NAME", name.clone()),
                None => vec![],
            },
            VariableName::MatchedVarsNames => self
                .matched_vars
                .iter()
                .map(|(k, _)| (qualified("MATCHED_VARS_NAMES", k), k.clone()))
                .collect(),

            // Default - empty
            _ => vec![],
        }
    }

    /// Resolve a collection with optional selection.
    fn resolve_collection(
        &self,
        collection: &super::collection::HashMapCollection,
        prefix: &str,
        selection: &Option<Selection>,
    ) -> Vals {
        self.resolve_collection_inner(collection, prefix, selection, false)
    }

    /// Resolve a collection where keys are matched case-insensitively (HTTP headers).
    fn resolve_collection_ci(
        &self,
        collection: &super::collection::HashMapCollection,
        prefix: &str,
        selection: &Option<Selection>,
    ) -> Vals {
        self.resolve_collection_inner(collection, prefix, selection, true)
    }

    fn resolve_collection_inner(
        &self,
        collection: &super::collection::HashMapCollection,
        prefix: &str,
        selection: &Option<Selection>,
        lowercase_key: bool,
    ) -> Vals {
        use super::collection::Collection;

        match selection {
            Some(Selection::Key(key)) => {
                let lookup = if lowercase_key {
                    key.to_ascii_lowercase()
                } else {
                    key.clone()
                };
                if let Some(values) = collection.get(&lookup) {
                    values
                        .into_iter()
                        .map(|v| (qualified(prefix, key.as_bytes()), v.to_vec()))
                        .collect()
                } else {
                    vec![]
                }
            }
            Some(Selection::Regex(pattern)) => {
                if let Some(re) = cached_regex(pattern) {
                    collection
                        .get_regex(&re)
                        .into_iter()
                        .map(|(k, v)| (qualified(prefix, k), v.to_vec()))
                        .collect()
                } else {
                    vec![]
                }
            }
            None => collection
                .all()
                .into_iter()
                .map(|(k, v)| (qualified(prefix, k), v.to_vec()))
                .collect(),
        }
    }

    /// Resolve ARGS collection (GET + POST combined).
    /// Resolve an `XML:` target.
    ///
    /// ModSecurity answers `XML:/*` with the content of the document element
    /// (the document's text as one value) and `XML://@*` with every attribute
    /// value; the XML body processor collects exactly those two sets, so no
    /// XPath is evaluated. Values are reported under the selector that
    /// addressed them, so `%{MATCHED_VAR_NAME}` reads `XML:/*` or `XML://@*`.
    fn resolve_xml(&self, selection: &Option<Selection>) -> Vals {
        let Some(target) = XmlTarget::from_selection(selection.as_ref()) else {
            // An XPath expression this engine cannot express. Reported when the
            // rules load, so there is nothing to say per request.
            return vec![];
        };
        let text = self
            .request
            .xml_text
            .iter()
            .map(|v| (b"XML:/*".to_vec(), v.clone()));
        let attributes = self
            .request
            .xml_attributes
            .iter()
            .map(|v| (b"XML://@*".to_vec(), v.clone()));
        match target {
            XmlTarget::Elements => text.collect(),
            XmlTarget::Attributes => attributes.collect(),
            XmlTarget::All => text.chain(attributes).collect(),
        }
    }

    fn resolve_collection_from_all_args(&self, selection: &Option<Selection>) -> Vals {
        let mut result = self.resolve_collection(&self.request.args_get, "ARGS", selection);
        result.extend(self.resolve_collection(&self.request.args_post, "ARGS", selection));
        result
    }

    /// Resolve a `*_NAMES` collection: the values are the keys of the backing
    /// collection(s), one entry per stored value (duplicates preserved,
    /// matching ModSecurity).
    fn resolve_collection_names(
        &self,
        collections: &[&super::collection::HashMapCollection],
        prefix: &str,
        selection: &Option<Selection>,
    ) -> Vals {
        use super::collection::Collection;

        let mut result = Vec::new();
        for collection in collections {
            for (key, _) in collection.all() {
                let selected = match selection {
                    Some(Selection::Key(sel)) => key.eq_ignore_ascii_case(sel.as_bytes()),
                    Some(Selection::Regex(pattern)) => cached_regex(pattern)
                        .map(|re| re.is_match(key))
                        .unwrap_or(false),
                    None => true,
                };
                if selected {
                    result.push((qualified(prefix, key), key.to_vec()));
                }
            }
        }
        result
    }

    /// Resolve TX collection.
    fn resolve_tx_collection(&self, selection: &Option<Selection>) -> Vals {
        use super::collection::Collection;

        match selection {
            Some(Selection::Key(key)) => {
                if let Some(values) = self.tx.get(key) {
                    values
                        .into_iter()
                        .map(|v| (qualified("TX", key.as_bytes()), v.to_vec()))
                        .collect()
                } else {
                    vec![]
                }
            }
            Some(Selection::Regex(pattern)) => {
                // TX keys are case-insensitive (stored lowercased), so the
                // selection pattern must be too: CRS writes
                // `TX:/MULTIPART_HEADERS_CONTENT_TYPES_*/`.
                if let Some(re) = cached_regex(&format!("(?i){pattern}")) {
                    self.tx
                        .get_regex(&re)
                        .into_iter()
                        .map(|(k, v)| (qualified("TX", k), v.to_vec()))
                        .collect()
                } else {
                    vec![]
                }
            }
            None => self
                .tx
                .all()
                .into_iter()
                .map(|(k, v)| (qualified("TX", k), v.to_vec()))
                .collect(),
        }
    }
}

/// Whether a resolved variable key (e.g. `ARGS:password`) is left out by one of
/// the specification's own exclusions.
pub(crate) fn is_excluded(spec: &VariableSpec, key: &[u8]) -> bool {
    spec.exclusions.iter().any(|e| exclusion_matches(key, e))
}

/// Check whether a resolved variable key (e.g. `ARGS:password`) is excluded by
/// a target exclusion (`!TARGET` in a rule's variable list or in
/// `SecRuleUpdateTargetById`).
///
/// Supported exclusion forms, per ModSecurity:
/// - `COLLECTION:key` — excludes that member (key compared case-insensitively);
/// - `COLLECTION:/regex/` — excludes members whose key matches the regex;
/// - `COLLECTION` — excludes the entire collection.
fn exclusion_matches(key: &[u8], exclusion: &str) -> bool {
    let (key_coll, key_member) = match key.iter().position(|&b| b == b':') {
        Some(colon) => (&key[..colon], Some(&key[colon + 1..])),
        None => (key, None),
    };
    match exclusion.split_once(':') {
        Some((excl_coll, excl_sel)) => {
            let Some(key_member) = key_member else {
                return false;
            };
            if !key_coll.eq_ignore_ascii_case(excl_coll.as_bytes()) {
                return false;
            }
            if excl_sel.len() > 2 && excl_sel.starts_with('/') && excl_sel.ends_with('/') {
                cached_regex(&excl_sel[1..excl_sel.len() - 1])
                    .map(|re| re.is_match(key_member))
                    .unwrap_or(false)
            } else {
                key_member.eq_ignore_ascii_case(excl_sel.as_bytes())
            }
        }
        None => key_coll.eq_ignore_ascii_case(exclusion.as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::{cached_regex, exclusion_matches};

    #[test]
    fn test_cached_regex_compiles_once_and_keeps_invalid_patterns_dead() {
        let a = cached_regex(r"^user_\d+$").expect("valid pattern");
        let b = cached_regex(r"^user_\d+$").expect("valid pattern");
        assert!(a.is_match(b"user_42") && b.is_match(b"user_42"));
        // An invalid pattern stays a never-matching selection, cached or not.
        assert!(cached_regex("(unclosed").is_none());
        assert!(cached_regex("(unclosed").is_none());
        assert!(!exclusion_matches(b"ARGS:x", "ARGS:/(unclosed/"));
    }

    #[test]
    fn test_exclusion_exact_key() {
        assert!(exclusion_matches(b"ARGS:password", "ARGS:password"));
        assert!(exclusion_matches(b"ARGS:Password", "ARGS:password"));
        // Must NOT be a prefix/substring match.
        assert!(!exclusion_matches(b"ARGS:password2", "ARGS:password"));
        assert!(!exclusion_matches(b"ARGS:xpassword", "ARGS:password"));
        // Different collection.
        assert!(!exclusion_matches(
            b"REQUEST_COOKIES:password",
            "ARGS:password"
        ));
    }

    #[test]
    fn test_exclusion_regex_key() {
        // CRS pattern: SecRuleUpdateTargetById 941100 "!REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
        assert!(exclusion_matches(
            b"REQUEST_COOKIES:_ga_ABC123",
            r"REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
        ));
        assert!(exclusion_matches(
            b"REQUEST_COOKIES:_ga",
            r"REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
        ));
        assert!(!exclusion_matches(
            b"REQUEST_COOKIES:session",
            r"REQUEST_COOKIES:/^_ga(?:_\w+)?$/"
        ));
    }

    #[test]
    fn test_exclusion_whole_collection() {
        assert!(exclusion_matches(b"ARGS:anything", "ARGS"));
        assert!(!exclusion_matches(b"ARGS_NAMES:anything", "ARGS"));
    }
}
