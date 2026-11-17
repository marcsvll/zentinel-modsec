//! Response data for variable resolution.

use super::collection::HashMapCollection;

/// Response data container.
#[derive(Debug, Clone, Default)]
pub struct ResponseData {
    /// HTTP status code.
    pub status: u16,
    /// Response protocol.
    pub protocol: String,
    /// Response headers.
    pub headers: HashMapCollection,
    /// Response body.
    pub body: Vec<u8>,
    /// Content type.
    pub content_type: Vec<u8>,
}

impl ResponseData {
    /// Create new response data.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the status code.
    pub fn set_status(&mut self, status: u16) {
        self.status = status;
    }

    /// Set the protocol.
    pub fn set_protocol(&mut self, protocol: &str) {
        self.protocol = protocol.to_string();
    }

    /// Add a response header.
    pub fn add_header(&mut self, name: &[u8], value: &[u8]) {
        self.headers.add(name.to_ascii_lowercase(), value);

        // Track content-type
        if name.eq_ignore_ascii_case(b"content-type") {
            self.content_type = value.to_vec();
        }
    }

    /// Append to response body.
    pub fn append_body(&mut self, data: &[u8]) {
        self.body.extend_from_slice(data);
    }

    /// Get body length.
    pub fn body_length(&self) -> usize {
        self.body.len()
    }
}
