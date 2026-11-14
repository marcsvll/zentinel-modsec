//! Transformation pipeline.

use super::{create_transformation, Transformation};
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
}

impl TransformationPipeline {
    /// Create an empty pipeline.
    pub fn new() -> Self {
        Self {
            transformations: Vec::new(),
            key: chain_key(&[]),
        }
    }

    /// Create a pipeline from transformation names.
    pub fn from_names(names: &[String]) -> Result<Self> {
        let mut transformations = Vec::new();

        for name in names {
            // Handle "none" specially - it clears the pipeline
            if name.eq_ignore_ascii_case("none") {
                transformations.clear();
                continue;
            }

            let t = create_transformation(name)?;
            transformations.push(t);
        }

        let key = chain_key(&transformations);
        Ok(Self {
            transformations,
            key,
        })
    }

    /// Add a transformation to the pipeline.
    pub fn add(&mut self, transformation: Arc<dyn Transformation>) {
        self.transformations.push(transformation);
        self.key = chain_key(&self.transformations);
    }

    /// A number shared by every pipeline with the same transformations in the
    /// same order, and by no other.
    pub fn chain_key(&self) -> u32 {
        self.key
    }

    /// Apply all transformations in sequence.
    pub fn apply<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if self.transformations.is_empty() {
            return Cow::Borrowed(input);
        }

        let mut current: Cow<str> = Cow::Borrowed(input);

        for t in &self.transformations {
            current = match current {
                Cow::Borrowed(s) => t.transform(s),
                Cow::Owned(s) => {
                    let transformed = t.transform(&s);
                    match transformed {
                        Cow::Borrowed(_) => Cow::Owned(s),
                        Cow::Owned(new) => Cow::Owned(new),
                    }
                }
            };
        }

        current
    }

    /// The value before any transformation and after each transformation that
    /// changed it, in order: what `multiMatch` runs the operator against.
    pub fn apply_steps(&self, input: &str) -> Vec<String> {
        let mut steps = vec![input.to_string()];
        let mut current = input.to_string();
        for t in &self.transformations {
            if let Cow::Owned(next) = t.transform(&current) {
                if next != current {
                    steps.push(next.clone());
                    current = next;
                }
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
    use super::*;

    #[test]
    fn test_empty_pipeline() {
        let pipeline = TransformationPipeline::new();
        assert_eq!(pipeline.apply("hello"), "hello");
    }

    #[test]
    fn test_single_transformation() {
        let pipeline = TransformationPipeline::from_names(&["lowercase".to_string()]).unwrap();
        assert_eq!(pipeline.apply("HELLO"), "hello");
    }

    #[test]
    fn test_multiple_transformations() {
        let pipeline =
            TransformationPipeline::from_names(&["urlDecode".to_string(), "lowercase".to_string()])
                .unwrap();
        assert_eq!(pipeline.apply("HELLO%20WORLD"), "hello world");
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
        assert_eq!(pipeline.apply("hello"), "HELLO");
    }
}
