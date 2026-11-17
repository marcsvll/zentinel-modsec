//! Request data for variable resolution.

use super::collection::{Collection, HashMapCollection};
use super::json::JsonNode;

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
    headers: Vec<Vec<u8>>,
    content: Vec<u8>,
}

/// Request data container.
#[derive(Debug, Clone, Default)]
pub struct RequestData {
    /// HTTP method.
    pub method: String,
    /// Request URI (with query string).
    pub uri: Vec<u8>,
    /// Raw URI.
    pub uri_raw: Vec<u8>,
    /// Request path (without query string), percent-decoded.
    pub path: Vec<u8>,
    /// Query string.
    pub query_string: Vec<u8>,
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
    /// The XML body's text, as ModSecurity's `XML:/*` yields it: the content of
    /// the document element, that is every text node (and CDATA section) of the
    /// document in order, as one value. Empty when the body was not XML or had
    /// no text. Populated by the XML body processor.
    pub xml_text: Vec<Vec<u8>>,
    /// Every attribute value of the XML body, in document order, as
    /// ModSecurity's `XML://@*` yields them. Populated by the XML body processor.
    pub xml_attributes: Vec<Vec<u8>>,
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
    pub fn set_uri(&mut self, uri: &[u8]) {
        self.uri = uri.to_vec();
        self.uri_raw = uri.to_vec();

        // ModSecurity sees the path the web server hands it: percent-decoded.
        // REQUEST_FILENAME/REQUEST_BASENAME are built from it, so CRS rules with
        // `t:none` (933160, 932130, ...) match `/post/eval%28...%29`; REQUEST_URI
        // and REQUEST_URI_RAW keep the original bytes.
        match uri.iter().position(|&b| b == b'?') {
            Some(pos) => {
                self.path = percent_decode_path(&uri[..pos]);
                self.query_string = uri[pos + 1..].to_vec();
                self.parse_query_string(&uri[pos + 1..]);
            }
            None => {
                self.path = percent_decode_path(uri);
                self.query_string.clear();
            }
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

    /// Add a request header. The name is stored in lower case (ASCII).
    pub fn add_header(&mut self, name: &[u8], value: &[u8]) {
        let lower = name.to_ascii_lowercase();
        if lower == b"cookie" {
            self.parse_cookie_header(value);
        }
        self.headers.add(lower, value);
    }

    /// Parse a `Cookie` request header into the cookies collection.
    fn parse_cookie_header(&mut self, value: &[u8]) {
        let mut cookies = self.cookies.count();
        for pair in value.split(|&b| b == b';') {
            let pair = pair.trim_ascii();
            if pair.is_empty() {
                continue;
            }
            if cookies >= MAX_ARGS {
                self.note_too_many("cookies");
                break;
            }
            cookies += 1;
            match pair.iter().position(|&b| b == b'=') {
                Some(eq) => self
                    .cookies
                    .add(pair[..eq].trim_ascii(), pair[eq + 1..].trim_ascii()),
                None => self.cookies.add(pair, Vec::new()),
            }
        }
    }

    /// Append to request body.
    pub fn append_body(&mut self, data: &[u8]) {
        self.body.extend_from_slice(data);
    }

    /// Get body length.
    pub fn body_length(&self) -> usize {
        self.body.len()
    }

    /// Parse query string into args_get.
    fn parse_query_string(&mut self, qs: &[u8]) {
        let mut arguments = self.argument_count();
        for pair in qs.split(|&b| b == b'&') {
            if pair.is_empty() {
                continue;
            }
            if arguments >= MAX_ARGS {
                self.note_too_many("arguments");
                break;
            }
            arguments += 1;
            let (key, value) = split_pair(pair);
            self.args_get.add(form_decode(key), form_decode(value));
        }
    }

    /// Arguments collected so far, from the query string and the body.
    fn argument_count(&self) -> usize {
        self.args_get.count() + self.args_post.count()
    }

    /// The request has more fields of one kind than [`MAX_ARGS`]: the rest was
    /// not collected, so it was not inspected, and that is reported the way
    /// every partially inspected body is, through `REQBODY_ERROR`.
    fn note_too_many(&mut self, what: &str) {
        if self.body_error.is_none() {
            self.body_error = Some(format!(
                "request has more than {MAX_ARGS} {what}; only the first {MAX_ARGS} were inspected"
            ));
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
    pub fn parse_multipart_body(&mut self, content_type: impl AsRef<[u8]>) -> bool {
        self.body_processor = "MULTIPART".to_string();
        let Some((boundary, quoted, whitespace)) =
            extract_multipart_boundary(content_type.as_ref())
        else {
            // Without a boundary nothing can be parsed: that is a body error, not an
            // empty body (it used to leave ARGS_POST empty and REQBODY_ERROR at 0, so
            // rule 200002 could not stop it). An empty `boundary=` is treated the same,
            // where libmodsecurity reports nothing.
            self.body_error = Some("Multipart: no usable boundary in Content-Type".to_string());
            self.multipart.missing_boundary = true;
            return false;
        };
        self.multipart.boundary_quoted = quoted;
        self.multipart.boundary_whitespace = whitespace;
        let body = std::mem::take(&mut self.body);
        let delimiter = [b"--".as_slice(), &boundary].concat();
        let closing = [b"--".as_slice(), &boundary, b"--"].concat();

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
        let mut pending_break: &[u8] = b"";
        let mut closed = false;
        let mut lookalike = false;
        let mut rest: &[u8] = &body;
        while !rest.is_empty() {
            let (line, ending, next): (&[u8], &[u8], &[u8]) =
                match rest.iter().position(|&b| b == b'\n') {
                    Some(i) => {
                        let raw = &rest[..=i];
                        match raw.strip_suffix(b"\r\n") {
                            Some(l) => (l, b"\r\n", &rest[i + 1..]),
                            None => (&raw[..raw.len() - 1], b"\n", &rest[i + 1..]),
                        }
                    }
                    None => (rest, b"", b""),
                };
            rest = next;
            if state == State::Epilogue {
                self.multipart.data_after = true;
                break;
            }
            let framing = trim_end_blanks(line);
            let is_closing = framing == closing.as_slice();
            let is_delimiter = is_closing || framing == delimiter.as_slice();
            if is_delimiter {
                if pending_break == b"\n" || ending == b"\n" {
                    self.multipart.lf_line = true;
                }
                pending_break = b"";
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
            if line.starts_with(b"--") {
                lookalike = true;
            }
            match state {
                State::Preamble => self.multipart.data_before = true,
                State::Headers => {
                    if ending == b"\n" {
                        self.multipart.lf_line = true;
                    }
                    if line.is_empty() {
                        state = State::Content;
                    } else if line.starts_with(b" ") || line.starts_with(b"\t") {
                        // A folded header (RFC 822 continuation): it belongs to the
                        // header before it. Ignoring it hid `filename=` from FILES.
                        match current.headers.last_mut() {
                            Some(previous) => {
                                previous.push(b' ');
                                previous.extend_from_slice(trim_start_blanks(line));
                                self.multipart.header_folding = true;
                            }
                            None => self.multipart.invalid_header_folding = true,
                        }
                    } else {
                        current.headers.push(line.to_vec());
                    }
                }
                State::Content => {
                    current.content.extend_from_slice(pending_break);
                    current.content.extend_from_slice(line);
                    pending_break = ending;
                }
                State::Epilogue => unreachable!("handled above"),
            }
        }
        self.body = body;
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

        // Fields and files count alike: each part is one thing to inspect.
        let room = MAX_ARGS.saturating_sub(self.argument_count() + self.files.count());
        if parts.len() > room {
            self.note_too_many("arguments");
        }
        for part in parts.into_iter().take(room) {
            let mut part_name: Option<Vec<u8>> = None;
            let mut filename: Option<Vec<u8>> = None;
            for line in &part.headers {
                if let Some(colon) = line.iter().position(|&b| b == b':') {
                    let (hname, hval) = (&line[..colon], &line[colon + 1..]);
                    if hname
                        .trim_ascii()
                        .eq_ignore_ascii_case(b"content-disposition")
                    {
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
                // A part without a Content-Disposition name cannot be addressed by
                // any collection key: an invalid part, and a body error, as in
                // libmodsecurity (which stops there; the named parts are still
                // inspected here).
                self.multipart.invalid_part = true;
                self.multipart.unmatched_boundary = 0;
                if self.body_error.is_none() {
                    self.body_error = Some("Multipart: part without a name".to_string());
                }
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
        let body = std::mem::take(&mut self.body);
        let mut arguments = self.argument_count();
        for pair in body.split(|&b| b == b'&') {
            if pair.is_empty() {
                continue;
            }
            if arguments >= MAX_ARGS {
                self.note_too_many("arguments");
                break;
            }
            arguments += 1;
            // A parameter with no `=` is a name with an empty value, which is how
            // application frameworks parse it. Dropping it here was a bypass:
            // percent-encoding the `=` leaves a body with no literal separator,
            // so the whole body became invisible to ARGS and ARGS_NAMES while
            // the origin still saw a parameter.
            let (key, value) = split_pair(pair);
            self.args_post.add(form_decode(key), form_decode(value));
        }
        self.body = body;
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
        self.body_processor = "XML".to_string();

        if self.body.iter().all(|b| b.is_ascii_whitespace()) {
            return Ok(());
        }

        // Whatever was read before an error stays available to the rules:
        // under the XML processor REQUEST_BODY is empty, so text thrown away
        // here would be content no rule could see. The error is reported as
        // well, and rule 200002 refuses the request on it.
        let mut text = Vec::new();
        let outcome = read_xml(&self.body, &mut self.xml_attributes, &mut text);
        if !text.trim_ascii().is_empty() {
            self.xml_text.push(text);
        }
        if let Err(msg) = &outcome {
            self.body_error = Some(msg.clone());
        }
        outcome
    }

    /// Get all arguments (GET + POST combined).
    pub fn all_args(&self) -> Vec<(&[u8], &[u8])> {
        let mut all = self.args_get.all();
        all.extend(self.args_post.all());
        all
    }
}

/// Read an XML document: attribute values go to `attributes` as they are
/// found, text accumulates in `text`. On an error both hold what was read up
/// to it.
///
/// Nothing the document carries is dropped quietly. A value that does not
/// decode (bytes that are not UTF-8, a reference that does not resolve) is
/// kept as its raw bytes, read leniently, so the rules still test it, and the
/// document is reported as not fully understood; a malformed attribute is a
/// parse error.
fn read_xml(body: &[u8], attributes: &mut Vec<Vec<u8>>, text: &mut Vec<u8>) -> Result<(), String> {
    use quick_xml::events::Event;

    let mut reader = quick_xml::Reader::from_reader(body);
    reader.config_mut().check_end_names = true;

    let mut depth = 0usize;
    // Elements and attribute values are counted against MAX_XML_ARGS: a body
    // with tens of thousands of nodes is reported through REQBODY_ERROR
    // rather than parsed in full.
    let mut nodes = 0usize;
    // The first thing that could not be decoded or resolved, reported once the
    // whole document has been read.
    let mut not_understood: Option<String> = None;
    let mut buf = Vec::new();

    macro_rules! element {
        ($e:expr) => {
            nodes += 1;
            for attr in $e.attributes() {
                let attr = attr.map_err(|e| format!("XML parsing error: malformed attribute: {e}"))?;
                nodes += 1;
                if nodes > MAX_XML_ARGS {
                    return Err(xml_limit_message());
                }
                let value = match attr.decoded_and_normalized_value(
                    quick_xml::XmlVersion::Implicit1_0,
                    reader.decoder(),
                ) {
                    Ok(value) => value.into_owned().into_bytes(),
                    Err(e) => {
                        not_understood.get_or_insert_with(|| {
                            format!(
                                "XML body has an attribute value that could not be decoded \
                                 ({e}); it was inspected as written"
                            )
                        });
                        attr.value.into_owned()
                    }
                };
                attributes.push(value);
            }
            if nodes > MAX_XML_ARGS {
                return Err(xml_limit_message());
            }
        };
    }

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                if depth >= MAX_XML_DEPTH {
                    return Err(format!(
                        "XML body exceeded {MAX_XML_DEPTH} levels of nesting; \
                         only part of the body was inspected"
                    ));
                }
                depth += 1;
                element!(e);
            }
            Ok(Event::Empty(e)) => {
                element!(e);
            }
            Ok(Event::End(_)) => {
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Text(e)) => {
                // Text arrives in fragments, split around entity references;
                // they are appended to one document text, so a payload written
                // as `UNION&#32;SELECT` stays whole for every rule.
                match e.decode() {
                    Ok(t) => text.extend_from_slice(t.as_bytes()),
                    Err(err) => {
                        not_understood.get_or_insert_with(|| {
                            format!(
                                "XML body has text that could not be decoded ({err}); \
                                 it was inspected as written"
                            )
                        });
                        text.extend_from_slice(e.as_ref());
                    }
                }
            }
            Ok(Event::CData(e)) => {
                // CDATA is text that is deliberately not markup, and a
                // classic place to hide a payload.
                text.extend_from_slice(e.as_ref());
            }
            Ok(Event::GeneralRef(e)) => {
                let name = e
                    .decode()
                    .map(|n| n.into_owned())
                    .unwrap_or_else(|_| String::from_utf8_lossy(e.as_ref()).into_owned());
                match resolve_entity(&name) {
                    Some(resolved) => {
                        text.extend_from_slice(resolved.as_bytes());
                    }
                    None => {
                        // A custom entity. Expanding it is how XXE and
                        // billion-laughs work, so this deliberately does
                        // not. But the origin application may expand it,
                        // and content this engine cannot see is content it
                        // cannot inspect -- so say so rather than treat
                        // the document as fully examined.
                        not_understood.get_or_insert_with(|| {
                            format!(
                                "XML body references the undeclared or custom entity \
                                 '&{name};', which is not expanded (expanding it is how XXE \
                                 and entity-expansion attacks work). Any content it carries \
                                 was not inspected."
                            )
                        });
                    }
                }
            }
            Ok(Event::Decl(e)) => {
                // The text is read as UTF-8. A document that declares another
                // encoding may mean something else to a parser that honours
                // the declaration (`+ADw-script+AD4-` is `<script>` in UTF-7).
                if let Some(Ok(encoding)) = e.encoding() {
                    let name = String::from_utf8_lossy(&encoding).to_ascii_lowercase();
                    if !matches!(name.as_str(), "utf-8" | "utf8" | "us-ascii" | "ascii") {
                        not_understood.get_or_insert_with(|| {
                            format!(
                                "XML body declares the encoding '{name}', which is not \
                                 decoded; it was inspected as UTF-8"
                            )
                        });
                    }
                }
            }
            Ok(Event::DocType(e)) => {
                // An internal subset can give attributes default values and
                // declare entities: content the application's parser sees and
                // this one does not build.
                if e.as_ref().contains(&b'[') {
                    not_understood.get_or_insert_with(|| {
                        "XML body has a DOCTYPE with an internal subset, which is not \
                         processed; what it declares was not inspected"
                            .to_string()
                    });
                }
            }
            Ok(Event::Eof) => break,
            // Comments and processing instructions carry no value to inspect.
            Ok(_) => {}
            Err(e) => return Err(format!("XML parsing error: {e}")),
        }
        buf.clear();
    }

    // Elements left open at end of input mean the document was cut short.
    // quick-xml reports EOF rather than an error for this, so a truncated
    // body would otherwise look like a complete one that simply had less
    // in it.
    if depth > 0 {
        return Err(format!(
            "XML body ended with {depth} element(s) still open; the document is truncated \
             and was only partly inspected"
        ));
    }

    match not_understood {
        Some(msg) => Err(msg),
        None => Ok(()),
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

/// A `name=value` pair split at its first `=`; a pair without one is a name
/// with an empty value.
fn split_pair(pair: &[u8]) -> (&[u8], &[u8]) {
    match pair.iter().position(|&b| b == b'=') {
        Some(eq) => (&pair[..eq], &pair[eq + 1..]),
        None => (pair, b""),
    }
}

/// Decode one component of `application/x-www-form-urlencoded` input: `+` is a
/// space and `%XX` the byte it names, whether or not the result is UTF-8 (CRS
/// 944200 looks for the Java serialization magic `AC ED 00 05`).
///
/// In that encoding `+` denotes a space -- it is what a browser emits for a
/// space in a submitted form -- so decoding only percent-escapes leaves the
/// argument holding a literal `+` where the origin application will see a
/// space. Any rule matching a payload that contains whitespace then misses,
/// which is a bypass rather than a coverage gap. The `+` substitution happens
/// *before* percent-decoding, so a plus that was genuinely sent as `%2B`
/// survives as a plus instead of becoming a space.
fn form_decode(component: &[u8]) -> Vec<u8> {
    let spaced: Vec<u8> = component
        .iter()
        .map(|&b| if b == b'+' { b' ' } else { b })
        .collect();
    percent_encoding::percent_decode(&spaced).collect()
}

/// Most fields of one kind collected from a request: arguments (query string,
/// urlencoded body and multipart parts together) and cookies. The JSON and XML
/// processors count their own values against their own caps, on top of the
/// query string's.
///
/// `a&a&a...` is two bytes per argument, and every argument is tested by every
/// rule over `ARGS`: without a bound, a body of a few hundred kilobytes buys
/// hundreds of thousands of operator calls per rule. The JSON and XML
/// processors already had theirs. As there, going over is reported as a
/// body-processor error (`REQBODY_ERROR`), not silently truncated: a partially
/// inspected request is not a safe one. ModSecurity's `SecArgumentsLimit`
/// defaults to 1000; this is the engine's own, higher, fixed bound.
const MAX_ARGS: usize = 4096;

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
        JsonNode::String(s) => push_json_arg(path, s.as_bytes(), args, count),
        JsonNode::Number(n) => push_json_arg(path, n.as_bytes(), args, count),
        JsonNode::Bool(b) => push_json_arg(path, b.to_string().as_bytes(), args, count),
        JsonNode::Null => push_json_arg(path, b"", args, count),
    }
}

/// Record one flattened scalar. Returns `true` once the argument cap is hit.
fn push_json_arg(
    path: &str,
    value: &[u8],
    args: &mut HashMapCollection,
    count: &mut usize,
) -> bool {
    if *count >= MAX_JSON_ARGS {
        return true;
    }
    *count += 1;
    args.add(path, value);
    false
}

/// Extract the `boundary` parameter from a multipart Content-Type value, with whether
/// it was quoted and whether whitespace surrounded the value (ModSecurity keeps that
/// whitespace in the boundary, so such a body never finds its delimiter).
fn extract_multipart_boundary(content_type: &[u8]) -> Option<(Vec<u8>, bool, bool)> {
    for param in content_type.split(|&b| b == b';').skip(1) {
        let param = param.trim_ascii_start();
        let Some(eq) = param.iter().position(|&b| b == b'=') else {
            continue;
        };
        let (key, value) = (&param[..eq], &param[eq + 1..]);
        if key.trim_ascii().eq_ignore_ascii_case(b"boundary") {
            let value = value.trim_ascii_end();
            let whitespace = value.starts_with(b" ") || value.starts_with(b"\t");
            let (value, quoted) = match value
                .trim_ascii_start()
                .strip_prefix(b"\"")
                .and_then(|v| v.strip_suffix(b"\""))
            {
                Some(inner) => (inner.to_vec(), true),
                None => (value.to_vec(), false),
            };
            if !value.trim_ascii().is_empty() {
                return Some((value, quoted, whitespace));
            }
        }
    }
    None
}

/// Decodes an RFC 5987 extended value (`charset'language'percent-encoded`): the
/// percent-encoded bytes. A value without the two quotes is taken as already
/// decoded.
fn decode_ext_value(value: &[u8]) -> Vec<u8> {
    let mut fields = value.splitn(3, |&b| b == b'\'');
    match (fields.next(), fields.next(), fields.next()) {
        (Some(_charset), Some(_language), Some(encoded)) => {
            percent_encoding::percent_decode(encoded).collect()
        }
        _ => value.to_vec(),
    }
}

/// Decodes `%XX` escapes in a URI path. `+` is not a space in a path, and an
/// incomplete or non-hex escape is left as written.
fn percent_decode_path(path: &[u8]) -> Vec<u8> {
    if !path.contains(&b'%') {
        return path.to_vec();
    }
    let mut out = Vec::with_capacity(path.len());
    let mut i = 0;
    while i < path.len() {
        if path[i] == b'%' && i + 2 < path.len() {
            let hex = |b: u8| (b as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hex(path[i + 1]), hex(path[i + 2])) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(path[i]);
        i += 1;
    }
    out
}

/// Spaces and tabs at the start of `line`.
fn trim_start_blanks(line: &[u8]) -> &[u8] {
    let start = line
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(line.len());
    &line[start..]
}

/// Spaces and tabs at the end of `line`.
fn trim_end_blanks(line: &[u8]) -> &[u8] {
    let end = line
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map_or(0, |at| at + 1);
    &line[..end]
}

/// Extract a parameter value (e.g. `name`, `filename`) from a
/// Content-Disposition header value.
fn extract_disposition_param(header_value: &[u8], param: &str) -> Option<Vec<u8>> {
    // Parameters are `;`-separated, but a quoted value may contain `;` and
    // backslash-escaped quotes (`name="fi;le"`, `filename="a\"b"`), so the
    // split happens outside quotes only. The quoted content is kept verbatim.
    let mut params: Vec<Vec<u8>> = vec![Vec::new()];
    let mut quoted = false;
    let mut bytes = header_value.iter().copied();
    while let Some(b) = bytes.next() {
        let current = params.last_mut().expect("params is never empty");
        match b {
            b'"' => {
                quoted = !quoted;
                current.push(b);
            }
            b'\\' if quoted => {
                current.push(b);
                if let Some(next) = bytes.next() {
                    current.push(next);
                }
            }
            b';' if !quoted => params.push(Vec::new()),
            _ => current.push(b),
        }
    }
    for part in params {
        let part = part.trim_ascii();
        let Some(eq) = part.iter().position(|&b| b == b'=') else {
            continue;
        };
        if part[..eq]
            .trim_ascii()
            .eq_ignore_ascii_case(param.as_bytes())
        {
            let value = part[eq + 1..].trim_ascii();
            let unquoted = value
                .strip_prefix(b"\"")
                .and_then(|v| v.strip_suffix(b"\""))
                .unwrap_or(value);
            return Some(unquoted.to_vec());
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
        req.add_header(b"Cookie", b"session=abc123; theme=dark; bare");
        assert_eq!(req.cookies.get("session"), Some(vec![&b"abc123"[..]]));
        assert_eq!(req.cookies.get("theme"), Some(vec![&b"dark"[..]]));
        assert_eq!(req.cookies.get("bare"), Some(vec![&b""[..]]));
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
        assert_eq!(req.args_post.get("field1"), Some(vec![&b"value1"[..]]));
        // File part does NOT land in ARGS_POST but in FILES.
        assert_eq!(req.args_post.get("upload"), None);
        assert_eq!(req.files.get("upload"), Some(vec![&b"a.txt"[..]]));

        // Every part header line is recorded under the part name.
        let field1_headers = req.multipart_part_headers.get("field1").unwrap();
        assert_eq!(
            field1_headers,
            vec![&b"Content-Disposition: form-data; name=\"field1\""[..]]
        );
        let upload_headers = req.multipart_part_headers.get("upload").unwrap();
        assert!(upload_headers.contains(&&b"Content-Type: text/plain"[..]));
        assert_eq!(req.body_processor, "MULTIPART");
    }

    #[test]
    fn test_parse_multipart_body_quoted_boundary_and_lf_only() {
        let mut req = RequestData::new();
        let body = "--b1\nContent-Disposition: form-data; name=\"k\"\n\nv\n--b1--\n";
        req.append_body(body.as_bytes());
        assert!(req.parse_multipart_body("multipart/form-data; boundary=\"b1\""));
        assert_eq!(req.args_post.get("k"), Some(vec![&b"v"[..]]));
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
        let h = br#"form-data; name="fi;le"; filename="te\"st.j\s\p""#;
        assert_eq!(
            extract_disposition_param(h, "name"),
            Some(b"fi;le".to_vec())
        );
        assert_eq!(
            extract_disposition_param(h, "filename"),
            Some(br#"te\"st.j\s\p"#.to_vec())
        );
        assert_eq!(
            extract_disposition_param(b"form-data; name=plain; filename=x.txt", "filename"),
            Some(b"x.txt".to_vec())
        );
        assert_eq!(
            extract_disposition_param(br#"form-data; name=""; filename="""#, "name"),
            Some(Vec::new())
        );
        assert_eq!(
            extract_disposition_param(b"form-data; name=\"a\"", "filename"),
            None
        );
    }

    #[test]
    fn request_filename_is_percent_decoded_and_the_raw_uri_is_kept() {
        let mut req = RequestData::new();
        req.set_uri(b"/post/subSTR%28%24x%29/a%2Fb?q=%41&p=1");
        assert_eq!(req.path, b"/post/subSTR($x)/a/b");
        assert_eq!(req.query_string, b"q=%41&p=1");
        assert_eq!(req.uri, b"/post/subSTR%28%24x%29/a%2Fb?q=%41&p=1");
        assert_eq!(percent_decode_path(b"/a%2/b%zz/c%"), b"/a%2/b%zz/c%");
        assert_eq!(percent_decode_path(b"/plus+is+kept"), b"/plus+is+kept");
        // The bytes an escape names, UTF-8 or not.
        assert_eq!(percent_decode_path(b"/%c0%af"), b"/\xc0\xaf");
    }

    #[test]
    fn arguments_keep_the_bytes_they_were_sent_as() {
        let mut req = RequestData::new();
        req.set_uri(b"/?n%ff=%ac%ed%00%05&e=%C3%A9");
        assert_eq!(
            req.args_get.get(b"n\xff"),
            Some(vec![&b"\xac\xed\x00\x05"[..]])
        );
        assert_eq!(req.args_get.get("e"), Some(vec!["\u{e9}".as_bytes()]));
        req.append_body(b"test=\xac\xed\x00\x05&p=%FE");
        req.parse_form_body();
        assert_eq!(
            req.args_post.get("test"),
            Some(vec![&b"\xac\xed\x00\x05"[..]])
        );
        assert_eq!(req.args_post.get("p"), Some(vec![&b"\xfe"[..]]));
        req.add_header(b"Cookie", b"c=\xff\x00; d=%41");
        assert_eq!(req.cookies.get("c"), Some(vec![&b"\xff\x00"[..]]));
        // Cookies are not decoded, as in ModSecurity.
        assert_eq!(req.cookies.get("d"), Some(vec![&b"%41"[..]]));
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
            ("control-part-without-name", "args", "the named parts are still inspected (libmodsecurity stops at the invalid part); the body error blocks either way"),
            ("s4-empty-boundary", "RE", "an empty boundary is a body error here; libmodsecurity reports nothing, which leaves the body unparsed and unflagged (S4)"),
            ("s4-empty-boundary", "PE", "as RE"),
            ("s4-empty-boundary", "SE", "as RE: the missing boundary is a strict error, as for an absent one"),
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
                .map(|(k, v)| {
                    (
                        String::from_utf8_lossy(k).into_owned(),
                        String::from_utf8_lossy(v).into_owned(),
                    )
                })
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
            let mut used: Vec<(String, String)> = Vec::new();
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
                    if want != v {
                        if deviates(&case, k) {
                            used.push((case.clone(), k.to_string()));
                        } else {
                            failures.push(format!("{case}: {k} = {v}, ModSecurity {want}"));
                        }
                    }
                }
                for (field, got) in [
                    ("args", sorted(&req.args_post)),
                    ("files", sorted(&req.files)),
                ] {
                    let want = expected_pairs(&expected[field]);
                    if want != got {
                        if deviates(&case, field) {
                            used.push((case.clone(), field.to_string()));
                        } else {
                            failures
                                .push(format!("{case}: {field} = {got:?}, ModSecurity {want:?}"));
                        }
                    }
                }
                checked += 1;
            }
            assert!(checked >= 17, "fixtures missing: {checked} cases");
            // A deviation that no longer differs must go: the list documents what is
            // still different, not what once was.
            for (case, field, _) in ORACLE_DEVIATIONS {
                if !used.iter().any(|(c, f)| c == case && f == field) {
                    failures.push(format!(
                        "{case}/{field}: listed as a deviation but matches ModSecurity"
                    ));
                }
            }
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
                Some(vec!["\u{e9}vil.php".as_bytes()]),
                "filename* wins over filename"
            );
            assert_eq!(
                req.args_post.get("second"),
                Some(vec![&b"y"[..]]),
                "a folded name is read"
            );
            assert!(req.multipart.header_folding && req.multipart.strict_error());
            assert_eq!(decode_ext_value(b"no-quotes"), b"no-quotes");
        }
    }
}
