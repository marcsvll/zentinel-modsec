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

    /// What a value must hold for this operator to match it, when that is
    /// known (see [`crate::prefilter`]). A value that does not satisfy it is
    /// not run through `execute`; `None` (the default) runs every value.
    fn need(&self) -> Option<crate::prefilter::Need> {
        None
    }

    /// Literals of which a value must contain at least one, compared without
    /// regard to ASCII case and given in lower case, for this operator to
    /// match it (see [`crate::prefilter::regex_literals`]). `None` (the
    /// default) when no such set is known.
    fn literals(&self) -> Option<Vec<Vec<u8>>> {
        None
    }

    /// Whether this operator supports capture groups.
    fn supports_capture(&self) -> bool {
        false
    }
}
