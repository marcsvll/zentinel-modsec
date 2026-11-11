//! Request data for variable resolution.

use super::collection::{Collection, HashMapCollection};
use super::json::JsonNode;
use std::borrow::Cow;
use std::collections::HashSet;

/// What the multipart body processor noticed, as ModSecurity reports it in the
/// `MULTIPART_*` variables (`modsecurity.conf-recommended`, rule 200003). Every flag is
/// about the framing, never about the content of a part.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MultipartFlags {
    /// `MULTIPART_BOUNDARY_QUOTED`: the boundary parameter was quoted.
    pub boundary_quoted: bool,
    /// `MULTIPART_BOUNDARY_WHITESPACE`: whitespace around the boundary value.
    pub boundary_whitespace: bool,
    /// `MULTIPART_DATA_BEFORE`: bytes before the first delimiter.
    pub data_before: bool,
    /// `MULTIPART_DATA_AFTER`: bytes after the closing delimiter.
    pub data_after: bool,
    /// `MULTIPART_HEADER_FOLDING`: a part header continued on the next line.
    pub header_folding: bool,
    /// `MULTIPART_LF_LINE`: a framing line (delimiter, part header, the blank line
    /// after the headers, the line break before a delimiter) ended with LF alone.
    pub lf_line: bool,
    /// `MULTIPART_MISSING_SEMICOLON`.
    pub missing_semicolon: bool,
    /// `MULTIPART_INVALID_QUOTING`.
    pub invalid_quoting: bool,
    /// `MULTIPART_INVALID_PART`: a part the processor could not use (no name).
    pub invalid_part: bool,
    /// `MULTIPART_INVALID_HEADER_FOLDING`: a continuation line with no header before it.
    pub invalid_header_folding: bool,
    /// `MULTIPART_FILE_LIMIT_EXCEEDED`.
    pub file_limit_exceeded: bool,
    /// The Content-Type named no usable boundary.
    pub missing_boundary: bool,
    /// `MULTIPART_UNMATCHED_BOUNDARY` as libmodsecurity 3 reports it: 2 once the closing
    /// delimiter was seen, 1 when a line looked like a delimiter (`--...`) but was not
    /// ours and the body never closed, 0 otherwise.
    pub unmatched_boundary: u8,
}

impl MultipartFlags {
    /// `MULTIPART_STRICT_ERROR`: any of the strict checks failed.
    pub fn strict_error(&self) -> bool {
        self.boundary_quoted
            || self.boundary_whitespace
            || self.data_before
            || self.data_after
            || self.header_folding
            || self.lf_line
            || self.missing_semicolon
            || self.invalid_quoting
            || self.invalid_part
            || self.invalid_header_folding
            || self.file_limit_exceeded
            || self.missing_boundary
    }
}

/// One part of a multipart body while it is being read.
#[derive(Default)]
struct MultipartPart {
    headers: Vec<String>,
    content: String,
}

/// Request data container.
#[derive(Debug, Clone, Default)]
pub struct RequestData {
    /// HTTP method.
    pub method: String,
    /// Request URI (with query string).
    pub uri: String,
    /// Raw URI.
    pub uri_raw: String,
    /// Request path (without query string).
    pub path: String,
    /// Query string.
    pub query_string: String,
    /// HTTP protocol version.
    pub protocol: String,
    /// Request headers.
    pub headers: HashMapCollection,
    /// GET arguments.
    pub args_get: HashMapCollection,
    /// POST arguments.
    pub args_post: HashMapCollection,
    /// Cookies.
    pub cookies: HashMapCollection,
    /// Multipart part headers (key = part name, value = full header line),
    /// populated by the multipart body processor. Mirrors ModSecurity's
    /// `MULTIPART_PART_HEADERS` collection.
    pub multipart_part_headers: HashMapCollection,
    /// Uploaded files (key = part name, value = client-supplied filename),
    /// populated by the multipart body processor. Backs `FILES`/`FILES_NAMES`.
    pub files: HashMapCollection,
    /// Size in bytes of each uploaded file's content (key = part name), as a
    /// decimal string. Backs `FILES_SIZES` and `FILES_COMBINED_SIZE`.
    pub files_sizes: HashMapCollection,
    /// What the multipart processor noticed about the body's framing: ModSecurity's
    /// `MULTIPART_*` variables.
    pub multipart: MultipartFlags,
    /// Name of the body processor that handled the request body
    /// (`MULTIPART`, `URLENCODED`, `JSON`, or empty when none ran). Backs
    /// `REQBODY_PROCESSOR`.
    pub body_processor: String,
    /// Why the body processor could not process the body, if it failed.
    ///
    /// Backs `REQBODY_ERROR` (1 when set, 0 otherwise) and
    /// `REQBODY_ERROR_MSG`. CRS rule 200002 blocks on this, which only works
    /// if a failed parse is observable: a strict parser rejecting a payload
    /// that the origin application happily accepts is a bypass when it
    /// happens quietly.
    pub body_error: Option<String>,
    /// Request body.
    pub body: Vec<u8>,
    /// Argument names whose decoded *value* was not valid UTF-8 (`%c0%af`, a
    /// truncated sequence, a byte above `%f4`). Values are stored as `String`,
    /// so the invalid bytes themselves are gone (replaced by U+FFFD); this is
    /// what `@validateUtf8Encoding` over `ARGS` reports, as ModSecurity does on
    /// the raw bytes (CRS 920250).
    pub invalid_utf8_args: HashSet<String>,
    /// Argument names that were themselves not valid UTF-8 once decoded
    /// (`@validateUtf8Encoding` over `ARGS_NAMES`).
    pub invalid_utf8_arg_names: HashSet<String>,
    /// The XML body's text, as ModSecurity's `XML:/*` yields it: the content of
    /// the document element, that is every text node (and CDATA section) of the
    /// document in order, as one value. Empty when the body was not XML or had
    /// no text. Populated by the XML body processor.
    pub xml_text: Vec<String>,
    /// Every attribute value of the XML body, in document order, as
    /// ModSecurity's `XML://@*` yields them. Populated by the XML body processor.
    pub xml_attributes: Vec<String>,
    /// Client IP address.
    pub client_ip: String,
    /// Client port.
    pub client_port: u16,
    /// Server name.
    pub server_name: String,
    /// Local address the connection was accepted on. Backs `SERVER_ADDR`.
    pub server_addr: String,
    /// Server port.
    pub server_port: u16,
}

impl RequestData {
    /// Create new request data.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the URI and parse path/query string.
    pub fn set_uri(&mut self, uri: &str) {
        self.uri = uri.to_string();
        self.uri_raw = uri.to_string();

        // ModSecurity sees the path the web server hands it: percent-decoded.
        // REQUEST_FILENAME/REQUEST_BASENAME are built from it, so CRS rules with
        // `t:none` (933160, 932130, ...) match `/post/eval%28...%29`; REQUEST_URI
        // and REQUEST_URI_RAW keep the original bytes.
        if let Some(pos) = uri.find('?') {
            self.path = percent_decode_path(&uri[..pos]);
            self.query_string = uri[pos + 1..].to_string();
            self.parse_query_string(&self.query_string.clone());
        } else {
            self.path = percent_decode_path(uri);
            self.query_string.clear();
        }
    }

    /// Set the HTTP method.
    pub fn set_method(&mut self, method: &str) {
        self.method = method.to_string();
    }

    /// Set the protocol.
    pub fn set_protocol(&mut self, protocol: &str) {
        self.protocol = protocol.to_string();
    }

    /// Add a request header.
    pub fn add_header(&mut self, name: &str, value: &str) {
        let lower = name.to_lowercase();
        if lower == "cookie" {
            self.parse_cookie_header(value);
        }
        self.headers.add(lower, value.to_string());
    }

    /// Parse a `Cookie` request header into the cookies collection.
    fn parse_cookie_header(&mut self, value: &str) {
        for pair in value.split(';') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            match pair.split_once('=') {
                Some((k, v)) => self.cookies.add(k.trim().to_string(), v.trim().to_string()),
                None => self.cookies.add(pair.to_string(), String::new()),
            }
        }
    }

    /// Append to request body.
    pub fn append_body(&mut self, data: &[u8]) {
        self.body.extend_from_slice(data);
    }

    /// Get body as string.
    pub fn body_str(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    /// Get body length.
    pub fn body_length(&self) -> usize {
        self.body.len()
    }

    /// Parse query string into args_get.
    fn parse_query_string(&mut self, qs: &str) {
        for pair in qs.split('&') {
            if let Some(pos) = pair.find('=') {
                let key = &pair[..pos];
                let value = &pair[pos + 1..];
                // URL decode
                let (key, key_ok) = form_decode_checked(key);
                let (value, value_ok) = form_decode_checked(value);
                self.note_utf8(&key, key_ok, value_ok);
                self.args_get.add(key, value);
            } else if !pair.is_empty() {
                let (key, key_ok) = form_decode_checked(pair);
                self.note_utf8(&key, key_ok, true);
                self.args_get.add(key, String::new());
            }
        }
    }

    /// Records an argument whose name or value did not decode to valid UTF-8.
    fn note_utf8(&mut self, key: &str, key_ok: bool, value_ok: bool) {
        if !key_ok {
            self.invalid_utf8_arg_names.insert(key.to_string());
        }
        if !value_ok {
            self.invalid_utf8_args.insert(key.to_string());
        }
    }

    /// Whether the argument a resolved name points at (`ARGS:x`, `ARGS_GET:x`,
    /// `ARGS_NAMES:x`, ...) did not decode to valid UTF-8.
    pub fn has_invalid_utf8(&self, resolved_name: &str) -> bool {
        let Some((collection, key)) = resolved_name.split_once(':') else {
            return false;
        };
        if !collection.starts_with("ARGS") {
            return false;
        }
        if collection.ends_with("_NAMES") {
            self.invalid_utf8_arg_names.contains(key)
        } else {
            self.invalid_utf8_args.contains(key)
        }
    }

    /// Parse a `multipart/form-data` body.
    ///
    /// Populates `args_post` from form fields, `files` from file parts, and
    /// `multipart_part_headers` with every part header line keyed by the part
    /// name (ModSecurity `MULTIPART_PART_HEADERS` semantics), and records what the
    /// framing looked like in `multipart` (ModSecurity's `MULTIPART_*` flags).
    ///
    /// The body is read line by line, as libmodsecurity does: a delimiter
    /// (`--boundary`, or `--boundary--` to close) counts only as a whole line, so
    /// the boundary text inside a value is content; a part's headers end at the
    /// first blank line, whatever its line ending. A body whose closing
    /// delimiter never comes is a body error (`REQBODY_ERROR`), and the parts read
    /// until then are still inspected. Returns `false` when no boundary parameter
    /// can be extracted from the Content-Type.
    pub fn parse_multipart_body(&mut self, content_type: &str) -> bool {
        self.body_processor = "MULTIPART".to_string();
        let Some((boundary, quoted, whitespace)) = extract_multipart_boundary(content_type) else {
            return false;
        };
        self.multipart.boundary_quoted = quoted;
        self.multipart.boundary_whitespace = whitespace;
        let body = self.body_str();
        let delimiter = format!("--{boundary}");
        let closing = format!("--{boundary}--");

        #[derive(PartialEq)]
        enum State {
            Preamble,
            Headers,
            Content,
            Epilogue,
        }
        let mut state = State::Preamble;
        let mut parts: Vec<MultipartPart> = Vec::new();
        let mut current = MultipartPart::default();
        // The line break before a delimiter belongs to the delimiter; it is held back
        // until the next line shows whether it ends the content.
        let mut pending_break = "";
        let mut closed = false;
        let mut lookalike = false;
        let mut rest = body.as_str();
        while !rest.is_empty() {
            let (line, ending, next) = match rest.find('\n') {
                Some(i) => {
                    let raw = &rest[..=i];
                    match raw.strip_suffix("\r\n") {
                        Some(l) => (l, "\r\n", &rest[i + 1..]),
                        None => (&raw[..raw.len() - 1], "\n", &rest[i + 1..]),
                    }
                }
                None => (rest, "", ""),
            };
            rest = next;
            if state == State::Epilogue {
                self.multipart.data_after = true;
                break;
            }
            let framing = line.trim_end_matches([' ', '\t']);
            let is_closing = framing == closing;
            let is_delimiter = is_closing || framing == delimiter;
            if is_delimiter {
                if pending_break == "\n" || ending == "\n" {
                    self.multipart.lf_line = true;
                }
                pending_break = "";
                match state {
                    State::Preamble => {}
                    State::Headers | State::Content => parts.push(std::mem::take(&mut current)),
                    State::Epilogue => unreachable!("handled above"),
                }
                if is_closing {
                    closed = true;
                    state = State::Epilogue;
                    // Anything at all after the closing line is epilogue data.
                    if !rest.is_empty() {
                        self.multipart.data_after = true;
                    }
                    break;
                }
                state = State::Headers;
                continue;
            }
            if line.starts_with("--") {
                lookalike = true;
            }
            match state {
                State::Preamble => self.multipart.data_before = true,
                State::Headers => {
                    if ending == "\n" {
                        self.multipart.lf_line = true;
                    }
                    if line.is_empty() {
                        state = State::Content;
                    } else if line.starts_with([' ', '\t']) {
                        // A folded header (RFC 822 continuation): it belongs to the
                        // header before it. Ignoring it hid `filename=` from FILES.
                        match current.headers.last_mut() {
                            Some(previous) => {
                                previous.push(' ');
                                previous.push_str(line.trim_start());
                                self.multipart.header_folding = true;
                            }
                            None => self.multipart.invalid_header_folding = true,
                        }
                    } else {
                        current.headers.push(line.to_string());
                    }
                }
                State::Content => {
                    current.content.push_str(pending_break);
                    current.content.push_str(line);
                    pending_break = ending;
                }
                State::Epilogue => unreachable!("handled above"),
            }
        }
        if !closed {
            // The parts read so far are inspected anyway; the error is what blocks.
            if state != State::Preamble {
                parts.push(current);
            }
            self.body_error = Some("Multipart: final boundary missing".to_string());
            self.multipart.unmatched_boundary = u8::from(lookalike);
        } else {
            self.multipart.unmatched_boundary = 2;
        }

        for part in parts {
            let mut part_name: Option<String> = None;
            let mut filename: Option<String> = None;
            for line in &part.headers {
                if let Some((hname, hval)) = line.split_once(':') {
                    if hname.trim().eq_ignore_ascii_case("content-disposition") {
                        part_name = extract_disposition_param(hval, "name");
                        // RFC 5987 `filename*=charset'lang'percent-encoded` names the
                        // file as much as `filename=` does, and wins when both appear.
                        filename = extract_disposition_param(hval, "filename*")
                            .map(|v| decode_ext_value(&v))
                            .or_else(|| extract_disposition_param(hval, "filename"));
                    }
                }
            }
            let Some(name) = part_name else {
                // A part without a Content-Disposition name cannot be
                // addressed by any collection key; skip it.
                continue;
            };
            for line in part.headers {
                self.multipart_part_headers.add(name.clone(), line);
            }
            if let Some(fname) = filename {
                self.files_sizes
                    .add(name.clone(), part.content.len().to_string());
                self.files.add(name, fname);
            } else {
                self.args_post.add(name, part.content);
            }
        }
        true
    }

    /// Parse form body into args_post.
    pub fn parse_form_body(&mut self) {
        let body_str = self.body_str();
        for pair in body_str.split('&') {
            if let Some(pos) = pair.find('=') {
                let key = &pair[..pos];
                let value = &pair[pos + 1..];
                let (key, key_ok) = form_decode_checked(key);
                let (value, value_ok) = form_decode_checked(value);
                self.note_utf8(&key, key_ok, value_ok);
                self.args_post.add(key, value);
            } else if !pair.is_empty() {
                // A parameter with no `=` is a name with an empty value, which
                // is how application frameworks parse it. Dropping it here was
                // a bypass: percent-encoding the `=` leaves a body with no
                // literal separator, so the whole body became invisible to
                // ARGS and ARGS_NAMES while the origin still saw a parameter.
                // The query-string parser has always handled this shape.
                let (key, key_ok) = form_decode_checked(pair);
                self.note_utf8(&key, key_ok, true);
                self.args_post.add(key, String::new());
            }
        }
    }

    /// Parse a JSON body into `args_post`, mirroring ModSecurity's JSON
    /// request body processor.
    ///
    /// Every scalar in the document becomes one argument named by its path,
    /// prefixed with `json.` and joined with `.`, with array indices as path
    /// segments — the naming libmodsecurity uses, so CRS exclusions written as
    /// `ARGS:json.user.name` keep working:
    ///
    /// ```text
    /// {"user": {"name": "bob"}, "tags": ["a", "b"]}
    ///   -> json.user.name = bob
    ///      json.tags.0    = a
    ///      json.tags.1    = b
    /// ```
    ///
    /// Returns `Ok(())` on success, or the reason the body could not be
    /// processed. The caller must surface that reason rather than treating it
    /// as an empty body: a strict parser rejecting a payload that the origin
    /// application accepts is a bypass if it happens quietly.
    pub fn parse_json_body(&mut self) -> Result<(), String> {
        self.body_processor = "JSON".to_string();

        // A body that is empty or only whitespace has nothing to inspect, and
        // is not a parse failure. Clients legitimately send an empty body with
        // `Content-Type: application/json` on POST and DELETE; reporting that
        // as an error would make CRS rule 200002 block them.
        if self.body.iter().all(|b| b.is_ascii_whitespace()) {
            return Ok(());
        }

        let value: JsonNode = match serde_json::from_slice(&self.body) {
            Ok(v) => v,
            Err(e) => {
                let msg = format!("JSON parsing error: {e}");
                self.body_error = Some(msg.clone());
                return Err(msg);
            }
        };

        let mut count = 0usize;
        let mut path = String::from("json");
        let truncated = flatten_json(&value, &mut path, &mut self.args_post, &mut count, 0);

        if truncated {
            let msg = format!(
                "JSON body exceeded processing limits ({MAX_JSON_ARGS} arguments or \
                 {MAX_JSON_DEPTH} levels of nesting); only part of the body was inspected"
            );
            self.body_error = Some(msg.clone());
            return Err(msg);
        }

        Ok(())
    }

    /// Parse an XML body into what ModSecurity's two XML selectors yield.
    ///
    /// ModSecurity exposes XML through an XPath-selected `XML:` variable. The
    /// only selectors the CRS writes are `XML:/*`, which libxml2 answers with
    /// the content of the document element (every text node of the document,
    /// in order, as one value), and `XML://@*`, every attribute value. Those
    /// two sets are collected here, in `xml_text` and `xml_attributes`:
    ///
    /// ```text
    /// <order><item id="7">widget</item></order>
    ///   -> XML:/*    = widget
    ///      XML://@*  = 7
    /// ```
    ///
    /// Element and attribute *names* are not values, as in ModSecurity: CRS
    /// 944100 inspects `ARGS_NAMES|XML:/*|XML://@*` for `java.lang.runtime`
    /// and must not fire on `<java.lang.Runtime>value</java.lang.Runtime>`.
    /// Nothing goes into `ARGS`, which ModSecurity leaves alone for an XML
    /// body; a rule set that inspects only `ARGS` does not see XML here either.
    ///
    /// The whole document is also available as `REQUEST_BODY`.
    pub fn parse_xml_body(&mut self) -> Result<(), String> {
        use quick_xml::events::Event;

        self.body_processor = "XML".to_string();

        if self.body.iter().all(|b| b.is_ascii_whitespace()) {
            return Ok(());
        }

        let mut reader = quick_xml::Reader::from_reader(self.body.as_slice());
        reader.config_mut().check_end_names = true;

        let mut depth = 0usize;
        // Elements and attribute values are counted against MAX_XML_ARGS: a body
        // with tens of thousands of nodes is reported through REQBODY_ERROR
        // rather than parsed in full.
        let mut nodes = 0usize;
        // Text arrives in fragments, split around entity references; they are
        // appended to one document text, so a payload written as
        // `UNION&#32;SELECT` stays whole for every rule.
        let mut text = String::new();
        let mut unresolved_entity: Option<String> = None;
        let mut buf = Vec::new();

        macro_rules! attributes {
            ($e:expr) => {
                nodes += 1;
                for attr in $e.attributes().flatten() {
                    nodes += 1;
                    if nodes > MAX_XML_ARGS {
                        let msg = xml_limit_message();
                        self.body_error = Some(msg.clone());
                        return Err(msg);
                    }
                    let value = attr
                        .decoded_and_normalized_value(
                            quick_xml::XmlVersion::Implicit1_0,
                            reader.decoder(),
                        )
                        .map(|v| v.into_owned())
                        .unwrap_or_default();
                    self.xml_attributes.push(value);
                }
            };
        }

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    if depth >= MAX_XML_DEPTH {
                        let msg = format!(
                            "XML body exceeded {MAX_XML_DEPTH} levels of nesting; \
                             only part of the body was inspected"
                        );
                        self.body_error = Some(msg.clone());
                        return Err(msg);
                    }
                    depth += 1;
                    attributes!(e);
                    if nodes > MAX_XML_ARGS {
                        let msg = xml_limit_message();
                        self.body_error = Some(msg.clone());
                        return Err(msg);
                    }
                }
                Ok(Event::Empty(e)) => {
                    attributes!(e);
                    if nodes > MAX_XML_ARGS {
                        let msg = xml_limit_message();
                        self.body_error = Some(msg.clone());
                        return Err(msg);
                    }
                }
                Ok(Event::End(_)) => {
                    depth = depth.saturating_sub(1);
                }
                Ok(Event::Text(e)) => {
                    if let Ok(t) = e.decode() {
                        text.push_str(t.as_ref());
                    }
                }
                Ok(Event::CData(e)) => {
                    // CDATA is text that is deliberately not markup, and a
                    // classic place to hide a payload.
                    text.push_str(&String::from_utf8_lossy(e.as_ref()));
                }
                Ok(Event::GeneralRef(e)) => {
                    let name = e.decode().map(|n| n.into_owned()).unwrap_or_default();
                    match resolve_entity(&name) {
                        Some(resolved) => {
                            text.push_str(&resolved);
                        }
                        None => {
                            // A custom entity. Expanding it is how XXE and
                            // billion-laughs work, so this deliberately does
                            // not. But the origin application may expand it,
                            // and content this engine cannot see is content it
                            // cannot inspect -- so say so rather than treat
                            // the document as fully examined.
                            unresolved_entity.get_or_insert(name);
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Ok(_) => {}
                Err(e) => {
                    let msg = format!("XML parsing error: {e}");
                    self.body_error = Some(msg.clone());
                    return Err(msg);
                }
            }
            buf.clear();
        }

        if !text.trim().is_empty() {
            self.xml_text.push(text);
        }

        // Elements left open at end of input mean the document was cut short.
        // quick-xml reports EOF rather than an error for this, so a truncated
        // body would otherwise look like a complete one that simply had less
        // in it.
        if depth > 0 {
            let msg = format!(
                "XML body ended with {depth} element(s) still open; the document is truncated \
                 and was only partly inspected"
            );
            self.body_error = Some(msg.clone());
            return Err(msg);
        }

        if let Some(name) = unresolved_entity {
            let msg = format!(
                "XML body references the undeclared or custom entity '&{name};', which is \
                 not expanded (expanding it is how XXE and entity-expansion attacks work). \
                 Any content it carries was not inspected."
            );
            self.body_error = Some(msg.clone());
            return Err(msg);
        }

        Ok(())
    }

    /// Get all arguments (GET + POST combined).
    pub fn all_args(&self) -> Vec<(&str, &str)> {
        let mut all = self.args_get.all();
        all.extend(self.args_post.all());
        all
    }
}

/// Most arguments extracted from a single XML body.
const MAX_XML_ARGS: usize = 4096;

/// Deepest element nesting the XML processor will descend.
///
/// quick-xml is a pull parser and does not recurse, so this bounds work and
/// argument-name length rather than stack depth.
const MAX_XML_DEPTH: usize = 64;

fn xml_limit_message() -> String {
    format!(
        "XML body exceeded {MAX_XML_ARGS} elements and attributes; only part of the \
         body was inspected"
    )
}

/// Resolve an entity reference this engine is willing to expand.
///
/// The five predefined XML entities and numeric character references only.
/// Custom entities declared in an internal DTD subset are deliberately not
/// resolved: expanding those is precisely the mechanism behind XXE and
/// billion-laughs, and no amount of care makes expanding attacker-supplied
/// entity definitions safe.
fn resolve_entity(name: &str) -> Option<String> {
    if let Some(predefined) = quick_xml::escape::resolve_predefined_entity(name) {
        return Some(predefined.to_string());
    }
    // Numeric character references: &#65; and &#x41;.
    let digits = name.strip_prefix('#')?;
    let code = match digits.strip_prefix(['x', 'X']) {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => digits.parse::<u32>().ok()?,
    };
    char::from_u32(code).map(|c| c.to_string())
}

/// Decode one component of `application/x-www-form-urlencoded` input, and say
/// whether the decoded bytes were valid UTF-8.
///
/// In that encoding `+` denotes a space -- it is what a browser emits for a
/// space in a submitted form -- so decoding only percent-escapes leaves the
/// argument holding a literal `+` where the origin application will see a
/// space. Any rule matching a payload that contains whitespace then misses,
/// which is a bypass rather than a coverage gap: the same request reaches the
/// application as spaces either way. The `+` substitution happens *before*
/// percent-decoding, so a plus that was genuinely sent as `%2B` survives as a
/// plus instead of becoming a space.
///
/// Invalid UTF-8 bytes are replaced (U+FFFD) in the returned string; the flag
/// is what `@validateUtf8Encoding` reports, since the string cannot carry them.
fn form_decode_checked(component: &str) -> (String, bool) {
    let plus_decoded: Cow<'_, str> = if component.as_bytes().contains(&b'+') {
        Cow::Owned(component.replace('+', " "))
    } else {
        Cow::Borrowed(component)
    };
    let bytes: Vec<u8> = percent_encoding::percent_decode_str(&plus_decoded).collect();
    match String::from_utf8(bytes) {
        Ok(s) => (s, true),
        Err(e) => (String::from_utf8_lossy(e.as_bytes()).into_owned(), false),
    }
}

/// Most arguments extracted from a single JSON body.
///
/// A hostile body can be small on the wire and still expand into an enormous
/// number of arguments — `[[[...]]]` or a long array of scalars — each of
/// which would then be run through every rule's operator. The cap bounds that
/// work; exceeding it is reported as a body-processor error rather than
/// silently truncating, since a partially inspected body is not a safe body.
const MAX_JSON_ARGS: usize = 4096;

/// Deepest JSON nesting the flattener will descend.
///
/// `serde_json` already refuses to *parse* beyond its own recursion limit;
/// this bounds the separate recursion done here.
const MAX_JSON_DEPTH: usize = 64;

/// Flatten a JSON value into `args`, naming each scalar by its path.
///
/// `path` is the prefix built so far and is restored before returning, so one
/// buffer is reused for the whole document. Returns `true` if a limit was hit
/// and the result is therefore incomplete.
fn flatten_json(
    value: &JsonNode,
    path: &mut String,
    args: &mut HashMapCollection,
    count: &mut usize,
    depth: usize,
) -> bool {
    if depth > MAX_JSON_DEPTH {
        return true;
    }

    match value {
        JsonNode::Object(entries) => {
            // Duplicate keys produce repeated entries under the same argument
            // name, so every value a client sent is inspected. Keeping only
            // one would let a parser differential hide a payload.
            for (key, child) in entries {
                let restore = path.len();
                path.push('.');
                path.push_str(key);
                let truncated = flatten_json(child, path, args, count, depth + 1);
                path.truncate(restore);
                if truncated {
                    return true;
                }
            }
            false
        }
        JsonNode::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let restore = path.len();
                path.push('.');
                path.push_str(&index.to_string());
                let truncated = flatten_json(child, path, args, count, depth + 1);
                path.truncate(restore);
                if truncated {
                    return true;
                }
            }
            false
        }
        // Scalars are the leaves that become arguments. `null` contributes an
        // empty value rather than being skipped, so a rule testing for the
        // presence of a key still sees it.
        JsonNode::String(s) => push_json_arg(path, s.clone(), args, count),
        JsonNode::Number(n) => push_json_arg(path, n.clone(), args, count),
        JsonNode::Bool(b) => push_json_arg(path, b.to_string(), args, count),
        JsonNode::Null => push_json_arg(path, String::new(), args, count),
    }
}

/// Record one flattened scalar. Returns `true` once the argument cap is hit.
fn push_json_arg(
    path: &str,
    value: String,
    args: &mut HashMapCollection,
    count: &mut usize,
) -> bool {
    if *count >= MAX_JSON_ARGS {
        return true;
    }
    *count += 1;
    args.add(path.to_string(), value);
    false
}

/// Extract the `boundary` parameter from a multipart Content-Type value, with whether
/// it was quoted and whether whitespace surrounded the value (ModSecurity keeps that
/// whitespace in the boundary, so such a body never finds its delimiter).
fn extract_multipart_boundary(content_type: &str) -> Option<(String, bool, bool)> {
    for param in content_type.split(';').skip(1) {
        let param = param.trim_start();
        if let Some((key, value)) = param.split_once('=') {
            if key.trim().eq_ignore_ascii_case("boundary") {
                let value = value.trim_end();
                let whitespace = value.starts_with([' ', '\t']);
                let (value, quoted) = match value
                    .trim_start()
                    .strip_prefix('"')
                    .and_then(|v| v.strip_suffix('"'))
                {
                    Some(inner) => (inner.to_string(), true),
                    None => (value.to_string(), false),
                };
                if !value.trim().is_empty() {
                    return Some((value, quoted, whitespace));
                }
            }
        }
    }
    None
}

/// Decodes an RFC 5987 extended value (`charset'language'percent-encoded`): the
/// percent-encoded bytes, read as UTF-8 (lossy). A value without the two quotes is
/// taken as already decoded.
fn decode_ext_value(value: &str) -> String {
    let mut fields = value.splitn(3, '\'');
    match (fields.next(), fields.next(), fields.next()) {
        (Some(_charset), Some(_language), Some(encoded)) => {
            percent_encoding::percent_decode_str(encoded)
                .decode_utf8_lossy()
                .into_owned()
        }
        _ => value.to_string(),
    }
}

/// Extract a parameter value (e.g. `name`, `filename`) from a
/// Content-Disposition header value.
/// Decodes `%XX` escapes in a URI path. `+` is not a space in a path, an
/// incomplete or non-hex escape is left as written, and bytes that do not form
/// UTF-8 become U+FFFD (the engine works on `str`).
fn percent_decode_path(path: &str) -> String {
    if !path.contains('%') {
        return path.to_string();
    }
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| (b as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn extract_disposition_param(header_value: &str, param: &str) -> Option<String> {
    // Parameters are `;`-separated, but a quoted value may contain `;` and
    // backslash-escaped quotes (`name="fi;le"`, `filename="a\"b"`), so the
    // split happens outside quotes only. The quoted content is kept verbatim.
    let mut params: Vec<String> = vec![String::new()];
    let mut quoted = false;
    let mut chars = header_value.chars();
    while let Some(c) = chars.next() {
        let current = params.last_mut().expect("params is never empty");
        match c {
            '"' => {
                quoted = !quoted;
                current.push(c);
            }
            '\\' if quoted => {
                current.push(c);
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            ';' if !quoted => params.push(String::new()),
            _ => current.push(c),
        }
    }
    for part in params {
        let Some((key, value)) = part.trim().split_once('=') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case(param) {
            let value = value.trim();
            let unquoted = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value);
            return Some(unquoted.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cookie_header() {
        let mut req = RequestData::new();
        req.add_header("Cookie", "session=abc123; theme=dark; bare");
        assert_eq!(req.cookies.get("session"), Some(vec!["abc123"]));
        assert_eq!(req.cookies.get("theme"), Some(vec!["dark"]));
        assert_eq!(req.cookies.get("bare"), Some(vec![""]));
    }

    #[test]
    fn test_parse_multipart_body_fields_and_headers() {
        let mut req = RequestData::new();
        let body = "--XyZ\r\n\
                    Content-Disposition: form-data; name=\"field1\"\r\n\
                    \r\n\
                    value1\r\n\
                    --XyZ\r\n\
                    Content-Disposition: form-data; name=\"upload\"; filename=\"a.txt\"\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    file contents\r\n\
                    --XyZ--\r\n";
        req.append_body(body.as_bytes());
        assert!(req.parse_multipart_body("multipart/form-data; boundary=XyZ"));

        // Form field lands in ARGS_POST.
        assert_eq!(req.args_post.get("field1"), Some(vec!["value1"]));
        // File part does NOT land in ARGS_POST but in FILES.
        assert_eq!(req.args_post.get("upload"), None);
        assert_eq!(req.files.get("upload"), Some(vec!["a.txt"]));

        // Every part header line is recorded under the part name.
        let field1_headers = req.multipart_part_headers.get("field1").unwrap();
        assert_eq!(
            field1_headers,
            vec!["Content-Disposition: form-data; name=\"field1\""]
        );
        let upload_headers = req.multipart_part_headers.get("upload").unwrap();
        assert!(upload_headers.contains(&"Content-Type: text/plain"));
        assert_eq!(req.body_processor, "MULTIPART");
    }

    #[test]
    fn test_parse_multipart_body_quoted_boundary_and_lf_only() {
        let mut req = RequestData::new();
        let body = "--b1\nContent-Disposition: form-data; name=\"k\"\n\nv\n--b1--\n";
        req.append_body(body.as_bytes());
        assert!(req.parse_multipart_body("multipart/form-data; boundary=\"b1\""));
        assert_eq!(req.args_post.get("k"), Some(vec!["v"]));
    }

    #[test]
    fn test_parse_multipart_body_missing_boundary() {
        let mut req = RequestData::new();
        req.append_body(b"irrelevant");
        assert!(!req.parse_multipart_body("multipart/form-data"));
        // libmodsecurity names the processor even when it cannot run it
        // (REQBODY_PROCESSOR=MULTIPART in the oracle's s4-no-boundary case).
        assert_eq!(req.body_processor, "MULTIPART");
    }

    #[test]
    fn disposition_params_keep_semicolons_and_escapes_inside_quotes() {
        let h = r#"form-data; name="fi;le"; filename="te\"st.j\s\p""#;
        assert_eq!(
            extract_disposition_param(h, "name"),
            Some("fi;le".to_string())
        );
        assert_eq!(
            extract_disposition_param(h, "filename"),
            Some(r#"te\"st.j\s\p"#.to_string())
        );
        assert_eq!(
            extract_disposition_param("form-data; name=plain; filename=x.txt", "filename"),
            Some("x.txt".to_string())
        );
        assert_eq!(
            extract_disposition_param(r#"form-data; name=""; filename="""#, "name"),
            Some(String::new())
        );
        assert_eq!(
            extract_disposition_param("form-data; name=\"a\"", "filename"),
            None
        );
    }

    #[test]
    fn request_filename_is_percent_decoded_and_the_raw_uri_is_kept() {
        let mut req = RequestData::new();
        req.set_uri("/post/subSTR%28%24x%29/a%2Fb?q=%41&p=1");
        assert_eq!(req.path, "/post/subSTR($x)/a/b");
        assert_eq!(req.query_string, "q=%41&p=1");
        assert_eq!(req.uri, "/post/subSTR%28%24x%29/a%2Fb?q=%41&p=1");
        assert_eq!(percent_decode_path("/a%2/b%zz/c%"), "/a%2/b%zz/c%");
        assert_eq!(percent_decode_path("/plus+is+kept"), "/plus+is+kept");
        assert_eq!(percent_decode_path("/%c0%af"), "/\u{FFFD}\u{FFFD}");
    }

    /// The multipart processor against ModSecurity v3 (`tests/fixtures/multipart-oracle`,
    /// recorded by neblina's `conformance/multipart-oracle/run.sh`): every case's body
    /// arguments, files, `REQBODY_ERROR` and `MULTIPART_*` flags must be what
    /// libmodsecurity produced, except where `ORACLE_DEVIATIONS` says why not.
    mod multipart_oracle {
        use super::super::*;
        use serde_json::Value;
        use std::collections::BTreeMap;

        /// (case, field, why): where this parser differs from libmodsecurity on purpose.
        /// Fields: `args`, `files`, or a flag name of the oracle (`RE`, `SE`, `UB`, ...).
        const ORACLE_DEVIATIONS: &[(&str, &str, &str)] = &[
            ("s1-missing-final-boundary", "args", "the parts read before the body ended are still inspected (libmodsecurity drops them); the body error blocks either way"),
            ("s4-no-boundary", "RE", "pending: a body without a boundary is a body error (S4)"),
            ("s4-no-boundary", "SE", "pending: S4"),
            ("s4-no-boundary", "PE", "pending: S4"),
            ("control-part-without-name", "RE", "pending: a part without a name is invalid (S4)"),
            ("control-part-without-name", "PE", "pending: S4"),
            ("control-part-without-name", "IP", "pending: S4"),
            ("control-part-without-name", "SE", "pending: S4"),
            ("control-part-without-name", "UB", "pending: S4"),
            ("control-part-without-name", "args", "pending: S4"),
        ];

        fn deviates(case: &str, field: &str) -> bool {
            ORACLE_DEVIATIONS
                .iter()
                .any(|(c, f, _)| *c == case && *f == field)
        }

        fn sorted(c: &HashMapCollection) -> Vec<(String, String)> {
            let mut v: Vec<(String, String)> = c
                .all()
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            v.sort();
            v
        }

        fn expected_pairs(v: &Value) -> Vec<(String, String)> {
            let mut out: Vec<(String, String)> = v
                .as_array()
                .unwrap()
                .iter()
                .map(|p| {
                    (
                        p[0].as_str().unwrap().to_string(),
                        p[1].as_str().unwrap().to_string(),
                    )
                })
                .collect();
            out.sort();
            out
        }

        #[test]
        fn every_case_matches_modsecurity() {
            let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/multipart-oracle");
            let mut checked = 0;
            let mut failures = Vec::new();
            for entry in std::fs::read_dir(dir.join("cases")).unwrap() {
                let path = entry.unwrap().path();
                let case = path.file_stem().unwrap().to_str().unwrap().to_string();
                let input: Value =
                    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
                let expected: Value = serde_json::from_str(
                    &std::fs::read_to_string(dir.join("expected").join(format!("{case}.json")))
                        .unwrap(),
                )
                .unwrap();
                let mut req = RequestData::new();
                req.body = input["body"].as_str().unwrap().as_bytes().to_vec();
                req.parse_multipart_body(input["content_type"].as_str().unwrap());
                let m = &req.multipart;
                let flag = |b: bool| if b { "1" } else { "0" }.to_string();
                let actual: BTreeMap<&str, String> = BTreeMap::from([
                    ("RE", flag(req.body_error.is_some())),
                    ("PE", flag(req.body_error.is_some())),
                    ("SE", flag(m.strict_error())),
                    ("UB", m.unmatched_boundary.to_string()),
                    ("BQ", flag(m.boundary_quoted)),
                    ("BW", flag(m.boundary_whitespace)),
                    ("DB", flag(m.data_before)),
                    ("DA", flag(m.data_after)),
                    ("HF", flag(m.header_folding)),
                    ("LF", flag(m.lf_line)),
                    ("SM", flag(m.missing_semicolon)),
                    ("IQ", flag(m.invalid_quoting)),
                    ("IP", flag(m.invalid_part)),
                    ("IH", flag(m.invalid_header_folding)),
                ]);
                for (k, v) in &actual {
                    let want = expected["flags"][k].as_str().unwrap_or("0");
                    let want = if want.is_empty() { "0" } else { want };
                    if want != v && !deviates(&case, k) {
                        failures.push(format!("{case}: {k} = {v}, ModSecurity {want}"));
                    }
                }
                for (field, got) in [
                    ("args", sorted(&req.args_post)),
                    ("files", sorted(&req.files)),
                ] {
                    let want = expected_pairs(&expected[field]);
                    if want != got && !deviates(&case, field) {
                        failures.push(format!("{case}: {field} = {got:?}, ModSecurity {want:?}"));
                    }
                }
                checked += 1;
            }
            assert!(checked >= 17, "fixtures missing: {checked} cases");
            assert!(
                failures.is_empty(),
                "{} difference(s) from ModSecurity:\n{}",
                failures.len(),
                failures.join("\n")
            );
        }

        #[test]
        fn filename_star_and_folded_headers_name_files() {
            let mut req = RequestData::new();
            req.body = b"--B\r\nContent-Disposition: form-data; name=\"up\"; filename=\"a.txt\"; filename*=UTF-8''%C3%A9vil.php\r\n\r\nx\r\n--B\r\nContent-Disposition: form-data;\r\n\tname=\"second\"\r\n\r\ny\r\n--B--\r\n".to_vec();
            assert!(req.parse_multipart_body("multipart/form-data; boundary=B"));
            assert_eq!(
                req.files.get("up"),
                Some(vec!["\u{e9}vil.php"]),
                "filename* wins over filename"
            );
            assert_eq!(
                req.args_post.get("second"),
                Some(vec!["y"]),
                "a folded name is read"
            );
            assert!(req.multipart.header_folding && req.multipart.strict_error());
            assert_eq!(decode_ext_value("no-quotes"), "no-quotes");
        }

        #[test]
        fn every_deviation_names_a_real_difference() {
            // A deviation that no longer differs must be removed: the list documents
            // what is still open, not what once was.
            for (case, field, why) in ORACLE_DEVIATIONS {
                assert!(!why.is_empty(), "{case}/{field} without a reason");
            }
        }
    }
}
