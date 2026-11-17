//! Operator trait definition.

/// Result of operator execution.
#[derive(Debug, Clone, Default)]
pub struct OperatorResult {
    /// Whether the operator matched.
    pub matched: bool,
    /// Captured groups from regex.
    pub captures: Vec<Vec<u8>>,
    /// The matched value.
    pub matched_value: Option<Vec<u8>>,
}

impl OperatorResult {
    /// Create a result indicating no match.
    pub fn no_match() -> Self {
        Self {
            matched: false,
            captures: Vec::new(),
            matched_value: None,
        }
    }

    /// Create a result indicating a match.
    pub fn matched(value: impl Into<Vec<u8>>) -> Self {
        Self {
            matched: true,
            captures: Vec::new(),
            matched_value: Some(value.into()),
        }
    }

    /// Create a result with captures.
    pub fn matched_with_captures(value: impl Into<Vec<u8>>, captures: Vec<Vec<u8>>) -> Self {
        Self {
            matched: true,
            captures,
            matched_value: Some(value.into()),
        }
    }
}

/// Trait for all operators.
///
/// An operator reads bytes: request data is whatever the client sent, and a
/// rule may be looking for bytes that are not text (CRS 944200 and the Java
/// serialization magic `AC ED 00 05`).
pub trait Operator: Send + Sync {
    /// Execute the operator against a value.
    fn execute(&self, value: &[u8]) -> OperatorResult;

    /// Get the operator name.
    fn name(&self) -> &'static str;

    /// Whether this operator supports capture groups.
    fn supports_capture(&self) -> bool {
        false
    }
}
