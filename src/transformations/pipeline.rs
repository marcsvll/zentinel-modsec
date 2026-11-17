//! Transformation pipeline.

use super::{create_transformation_with, Transformation, UnicodeMap};
use crate::error::Result;
use once_cell::sync::Lazy;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A number for a chain of transformations: the same transformations in the
/// same order get the same number, whichever rule they were written in.
///
/// It lets a result be kept under "this value, through this chain" without
/// comparing chains. The table grows only when rules are loaded, by one entry
/// per distinct chain.
fn chain_key(transformations: &[Arc<dyn Transformation>]) -> u32 {
    static KEYS: Lazy<Mutex<HashMap<Vec<&'static str>, u32>>> = Lazy::new(Default::default);
    let names: Vec<&'static str> = transformations.iter().map(|t| t.name()).collect();
    let mut keys = KEYS.lock().unwrap_or_else(|e| e.into_inner());
    let next = keys.len() as u32;
    *keys.entry(names).or_insert(next)
}

/// A pipeline of transformations to apply in sequence.
#[derive(Clone)]
pub struct TransformationPipeline {
    transformations: Vec<Arc<dyn Transformation>>,
    /// See [`chain_key`].
    key: u32,
    /// See [`TransformationPipeline::touches`].
    touches: Option<u64>,
}

/// The union of what each transformation touches, when all of them say.
fn chain_touches(transformations: &[Arc<dyn Transformation>]) -> Option<u64> {
    transformations
        .iter()
        .try_fold(0, |all, t| Some(all | t.touches()?))
}

impl TransformationPipeline {
    /// Create an empty pipeline.
    pub fn new() -> Self {
        Self {
            transformations: Vec::new(),
            key: chain_key(&[]),
            touches: Some(0),
        }
    }

    /// Create a pipeline from transformation names.
    pub fn from_names(names: &[String]) -> Result<Self> {
        Self::from_names_with(names, None)
    }

    /// Create a pipeline from transformation names, with the best-fit table
    /// of a `SecUnicodeMapFile` directive (`None`: the built-in one).
    pub fn from_names_with(
        names: &[String],
        unicode_map: Option<&Arc<UnicodeMap>>,
    ) -> Result<Self> {
        let mut transformations = Vec::new();

        for name in names {
            // Handle "none" specially - it clears the pipeline
            if name.eq_ignore_ascii_case("none") {
                transformations.clear();
                continue;
            }

            let t = create_transformation_with(name, unicode_map)?;
            transformations.push(t);
        }

        let key = chain_key(&transformations);
        let touches = chain_touches(&transformations);
        Ok(Self {
            transformations,
            key,
            touches,
        })
    }

    /// Add a transformation to the pipeline.
    pub fn add(&mut self, transformation: Arc<dyn Transformation>) {
        self.transformations.push(transformation);
        self.key = chain_key(&self.transformations);
        self.touches = chain_touches(&self.transformations);
    }

    /// Classes of bytes without which the whole chain leaves a value as it
    /// is: a value holding none of them is unchanged by the first
    /// transformation, so the second sees the same value, and so on. `None`
    /// when a transformation of the chain does not say what it touches.
    pub fn touches(&self) -> Option<u64> {
        self.touches
    }

    /// A number shared by every pipeline with the same transformations in the
    /// same order, and by no other.
    pub fn chain_key(&self) -> u32 {
        self.key
    }

    /// Apply all transformations in sequence.
    pub fn apply<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        if self.transformations.is_empty() {
            return Cow::Borrowed(input);
        }

        let mut current: Cow<[u8]> = Cow::Borrowed(input);

        for t in &self.transformations {
            current = match current {
                Cow::Borrowed(s) => t.transform(s),
                Cow::Owned(s) => {
                    let transformed = t.transform(&s);
                    match transformed {
                        Cow::Borrowed(same) if same.len() == s.len() => Cow::Owned(s),
                        Cow::Borrowed(part) => Cow::Owned(part.to_vec()),
                        Cow::Owned(new) => Cow::Owned(new),
                    }
                }
            };
        }

        current
    }

    /// The value before any transformation and after each transformation that
    /// changed it, in order: what `multiMatch` runs the operator against.
    pub fn apply_steps(&self, input: &[u8]) -> Vec<Vec<u8>> {
        let mut steps = vec![input.to_vec()];
        let mut current = input.to_vec();
        for t in &self.transformations {
            let next = t.transform(&current);
            if next.as_ref() != current.as_slice() {
                let next = next.into_owned();
                steps.push(next.clone());
                current = next;
            }
        }
        steps
    }

    /// Check if the pipeline is empty.
    pub fn is_empty(&self) -> bool {
        self.transformations.is_empty()
    }

    /// Get the number of transformations.
    pub fn len(&self) -> usize {
        self.transformations.len()
    }
}

impl Default for TransformationPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TransformationPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransformationPipeline")
            .field(
                "transformations",
                &self
                    .transformations
                    .iter()
                    .map(|t| t.name())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::create_transformation;
    use super::*;

    #[test]
    fn test_empty_pipeline() {
        let pipeline = TransformationPipeline::new();
        assert_eq!(pipeline.apply(b"hello").as_ref(), b"hello");
    }

    #[test]
    fn test_single_transformation() {
        let pipeline = TransformationPipeline::from_names(&["lowercase".to_string()]).unwrap();
        assert_eq!(pipeline.apply(b"HELLO").as_ref(), b"hello");
    }

    #[test]
    fn test_multiple_transformations() {
        let pipeline =
            TransformationPipeline::from_names(&["urlDecode".to_string(), "lowercase".to_string()])
                .unwrap();
        assert_eq!(pipeline.apply(b"HELLO%20WORLD").as_ref(), b"hello world");
    }

    #[test]
    fn test_chain_key_follows_the_transformations_and_their_order() {
        let chain = |names: &[&str]| {
            let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
            TransformationPipeline::from_names(&names)
                .unwrap()
                .chain_key()
        };
        assert_eq!(
            chain(&["urlDecodeUni", "lowercase"]),
            chain(&["none", "URLDECODEUNI", "lowercase"])
        );
        assert_ne!(
            chain(&["urlDecodeUni", "lowercase"]),
            chain(&["lowercase", "urlDecodeUni"])
        );
        assert_ne!(chain(&["lowercase"]), chain(&["urlDecodeUni", "lowercase"]));
        assert_eq!(chain(&["none"]), TransformationPipeline::new().chain_key());

        let mut built = TransformationPipeline::new();
        built.add(create_transformation("lowercase").unwrap());
        assert_eq!(built.chain_key(), chain(&["lowercase"]));
    }

    #[test]
    fn test_none_clears_pipeline() {
        let pipeline = TransformationPipeline::from_names(&[
            "lowercase".to_string(),
            "none".to_string(),
            "uppercase".to_string(),
        ])
        .unwrap();
        // Only uppercase should be applied
        assert_eq!(pipeline.apply(b"hello").as_ref(), b"HELLO");
    }
}
