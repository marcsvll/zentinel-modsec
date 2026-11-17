//! Comparison operators (@contains, @eq, @gt, etc.).
//!
//! The string comparisons are over bytes. Their argument can come from the
//! request through a macro (`@streq %{request_headers.host}`), so it is taken
//! as bytes too.

use super::traits::{Operator, OperatorResult};

/// Contains operator (@contains).
pub struct ContainsOperator {
    needle: Vec<u8>,
    /// A searcher built once, linear in the value: the needle can be request
    /// data (`@contains %{request_headers.x}`) and the value a whole body.
    finder: aho_corasick::AhoCorasick,
}

impl ContainsOperator {
    /// Create the operator from its SecLang argument.
    pub fn new(needle: impl AsRef<[u8]>) -> Self {
        let needle = needle.as_ref().to_vec();
        let finder = aho_corasick::AhoCorasick::new([&needle])
            .expect("one needle of any length always builds");
        Self { needle, finder }
    }
}

impl Operator for ContainsOperator {
    fn execute(&self, value: &[u8]) -> OperatorResult {
        if self.needle.is_empty() || self.finder.is_match(value) {
            OperatorResult::matched(self.needle.clone())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "contains"
    }

    fn need(&self) -> Option<crate::prefilter::Need> {
        crate::prefilter::Need::of_literal(&self.needle, false)
    }
}

/// Begins with operator (@beginsWith).
pub struct BeginsWithOperator {
    prefix: Vec<u8>,
}

impl BeginsWithOperator {
    /// Create the operator from its SecLang argument.
    pub fn new(prefix: impl AsRef<[u8]>) -> Self {
        Self {
            prefix: prefix.as_ref().to_vec(),
        }
    }
}

impl Operator for BeginsWithOperator {
    fn execute(&self, value: &[u8]) -> OperatorResult {
        if value.starts_with(&self.prefix) {
            OperatorResult::matched(self.prefix.clone())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "beginsWith"
    }

    fn need(&self) -> Option<crate::prefilter::Need> {
        crate::prefilter::Need::of_literal(&self.prefix, false)
    }
}

/// Ends with operator (@endsWith).
pub struct EndsWithOperator {
    suffix: Vec<u8>,
}

impl EndsWithOperator {
    /// Create the operator from its SecLang argument.
    pub fn new(suffix: impl AsRef<[u8]>) -> Self {
        Self {
            suffix: suffix.as_ref().to_vec(),
        }
    }
}

impl Operator for EndsWithOperator {
    fn execute(&self, value: &[u8]) -> OperatorResult {
        if value.ends_with(&self.suffix) {
            OperatorResult::matched(self.suffix.clone())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "endsWith"
    }

    fn need(&self) -> Option<crate::prefilter::Need> {
        crate::prefilter::Need::of_literal(&self.suffix, false)
    }
}

/// String equality operator (@streq).
pub struct StreqOperator {
    expected: Vec<u8>,
}

impl StreqOperator {
    /// Create the operator from its SecLang argument.
    pub fn new(expected: impl AsRef<[u8]>) -> Self {
        Self {
            expected: expected.as_ref().to_vec(),
        }
    }
}

impl Operator for StreqOperator {
    fn execute(&self, value: &[u8]) -> OperatorResult {
        if value == self.expected.as_slice() {
            OperatorResult::matched(value)
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "streq"
    }

    fn need(&self) -> Option<crate::prefilter::Need> {
        crate::prefilter::Need::of_literal(&self.expected, false)
    }
}

/// A value read as a decimal integer, or `None` when it is not one.
pub(crate) fn integer(value: &[u8]) -> Option<i64> {
    std::str::from_utf8(value).ok()?.parse().ok()
}

/// The integer an argument names, unless it still holds a macro (which the
/// transaction expands before the operator runs).
fn target(arg: &[u8]) -> Option<i64> {
    if arg.windows(2).any(|w| w == b"%{") {
        return None;
    }
    integer(arg)
}

/// A numeric comparison: `@eq`, `@gt`, `@lt`, `@ge`, `@le`. A value or an
/// argument that is not an integer does not match.
macro_rules! numeric_operator {
    ($(#[$doc:meta])* $name:ident, $label:literal, $cmp:expr) => {
        $(#[$doc])*
        pub struct $name {
            target: Option<i64>,
        }

        impl $name {
            /// Create the operator from its SecLang argument.
            pub fn new(value: impl AsRef<[u8]>) -> Self {
                Self {
                    target: target(value.as_ref()),
                }
            }
        }

        impl Operator for $name {
            fn execute(&self, value: &[u8]) -> OperatorResult {
                let compare: fn(i64, i64) -> bool = $cmp;
                match (integer(value), self.target) {
                    (Some(n), Some(target)) if compare(n, target) => OperatorResult::matched(value),
                    _ => OperatorResult::no_match(),
                }
            }

            fn name(&self) -> &'static str {
                $label
            }
        }
    };
}

numeric_operator!(
    /// Numeric equality operator (@eq).
    EqOperator,
    "eq",
    |n, t| n == t
);
numeric_operator!(
    /// Greater than operator (@gt).
    GtOperator,
    "gt",
    |n, t| n > t
);
numeric_operator!(
    /// Less than operator (@lt).
    LtOperator,
    "lt",
    |n, t| n < t
);
numeric_operator!(
    /// Greater than or equal operator (@ge).
    GeOperator,
    "ge",
    |n, t| n >= t
);
numeric_operator!(
    /// Less than or equal operator (@le).
    LeOperator,
    "le",
    |n, t| n <= t
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains() {
        let op = ContainsOperator::new("admin");
        assert!(op.execute(b"/admin/users").matched);
        assert!(!op.execute(b"/users").matched);
        assert!(
            ContainsOperator::new(b"\xac\xed")
                .execute(b"x\xac\xed\x00")
                .matched
        );
    }

    #[test]
    fn test_begins_with() {
        let op = BeginsWithOperator::new("/admin");
        assert!(op.execute(b"/admin/users").matched);
        assert!(!op.execute(b"/users/admin").matched);
    }

    #[test]
    fn test_ends_with() {
        let op = EndsWithOperator::new(".php");
        assert!(op.execute(b"index.php").matched);
        assert!(!op.execute(b"index.html").matched);
    }

    #[test]
    fn test_streq() {
        let op = StreqOperator::new("admin");
        assert!(op.execute(b"admin").matched);
        assert!(!op.execute(b"Admin").matched);
    }

    #[test]
    fn test_numeric_operators() {
        let eq = EqOperator::new("10");
        assert!(eq.execute(b"10").matched);
        assert!(!eq.execute(b"11").matched);

        let gt = GtOperator::new("10");
        assert!(gt.execute(b"11").matched);
        assert!(!gt.execute(b"10").matched);

        let lt = LtOperator::new("10");
        assert!(lt.execute(b"9").matched);
        assert!(!lt.execute(b"10").matched);

        assert!(!EqOperator::new("0").execute(b"\xff").matched);
    }
}
