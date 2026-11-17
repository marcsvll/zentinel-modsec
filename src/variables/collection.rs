//! Collection trait and implementations.

use indexmap::IndexMap;
use regex::bytes::Regex;

/// A collection of key-value pairs.
///
/// Keys and values are bytes: they come from the request (argument names and
/// values, header values, cookies) or from `setvar`s that copy request data,
/// and none of them is text until proven so. A key or value given as text is
/// taken as its UTF-8 bytes.
pub trait Collection: Send + Sync {
    /// Get all key-value pairs.
    fn all(&self) -> Vec<(&[u8], &[u8])>;

    /// Get values by key.
    fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<&[u8]>>;

    /// Get values matching a regex pattern.
    fn get_regex(&self, pattern: &Regex) -> Vec<(&[u8], &[u8])>;

    /// Count items.
    fn count(&self) -> usize;

    /// Count items with specific key.
    fn count_key(&self, key: impl AsRef<[u8]>) -> usize;
}

/// A mutable collection (TX, SESSION, etc.).
pub trait MutableCollection: Collection {
    /// Set a value.
    fn set(&mut self, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>);

    /// Delete a key.
    fn delete(&mut self, key: impl AsRef<[u8]>);

    /// Increment a numeric value.
    fn increment(&mut self, key: impl AsRef<[u8]>, amount: i64);

    /// Decrement a numeric value.
    fn decrement(&mut self, key: impl AsRef<[u8]>, amount: i64);
}

/// The first value a lookup found, as a number: what `setvar` arithmetic and
/// the anomaly scores read. A value that is not a decimal integer is 0, as in
/// libmodsecurity.
pub fn first_number(values: Option<Vec<&[u8]>>) -> i64 {
    values
        .and_then(|v| v.first().copied())
        .and_then(|v| std::str::from_utf8(v).ok()?.parse().ok())
        .unwrap_or(0)
}

/// A keyed collection that iterates in insertion order.
///
/// Order is part of the result, not an implementation detail: a rule over a
/// collection reports the first variable that matched, which becomes
/// `MATCHED_VAR`, the captures and the audit log's matched data. A
/// `std::collections::HashMap` iterates in an order seeded per map, so the
/// same rules and the same request gave different answers from run to run
/// (zentinelproxy/zentinel-modsec#53). Insertion order is the order the
/// request carried its headers and arguments in, and the order `setvar`
/// created TX variables in.
///
/// The name is kept for API compatibility.
#[derive(Debug, Clone, Default)]
pub struct HashMapCollection {
    data: IndexMap<Vec<u8>, Vec<Vec<u8>>>,
}

impl HashMapCollection {
    /// Create a new empty collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a value to a key.
    pub fn add(&mut self, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) {
        self.data.entry(key.into()).or_default().push(value.into());
    }

    /// Clear all data.
    pub fn clear(&mut self) {
        self.data.clear();
    }
}

impl Collection for HashMapCollection {
    fn all(&self) -> Vec<(&[u8], &[u8])> {
        self.data
            .iter()
            .flat_map(|(k, vs)| vs.iter().map(move |v| (k.as_slice(), v.as_slice())))
            .collect()
    }

    fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<&[u8]>> {
        self.data
            .get(key.as_ref())
            .map(|vs| vs.iter().map(Vec::as_slice).collect())
    }

    fn get_regex(&self, pattern: &Regex) -> Vec<(&[u8], &[u8])> {
        self.data
            .iter()
            .filter(|(k, _)| pattern.is_match(k))
            .flat_map(|(k, vs)| vs.iter().map(move |v| (k.as_slice(), v.as_slice())))
            .collect()
    }

    fn count(&self) -> usize {
        self.data.values().map(|v| v.len()).sum()
    }

    fn count_key(&self, key: impl AsRef<[u8]>) -> usize {
        self.data.get(key.as_ref()).map(|v| v.len()).unwrap_or(0)
    }
}

impl MutableCollection for HashMapCollection {
    fn set(&mut self, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) {
        self.data.insert(key.into(), vec![value.into()]);
    }

    fn delete(&mut self, key: impl AsRef<[u8]>) {
        // `shift_remove`, not `swap_remove`: the latter moves the last key
        // into the gap and so reorders what is left.
        self.data.shift_remove(key.as_ref());
    }

    fn increment(&mut self, key: impl AsRef<[u8]>, amount: i64) {
        let key = key.as_ref();
        let current = first_number(self.get(key));
        self.set(key, current.saturating_add(amount).to_string());
    }

    fn decrement(&mut self, key: impl AsRef<[u8]>, amount: i64) {
        let key = key.as_ref();
        let current = first_number(self.get(key));
        self.set(key, current.saturating_sub(amount).to_string());
    }
}
