//! What a phase works out once and every rule of it reuses.
//!
//! The request and the response do not change while the rules of a phase run:
//! rules write to TX, to the captures and to the per-transaction controls,
//! never to the request. CRS tests the same collections (`ARGS`,
//! `REQUEST_COOKIES`, `REQUEST_HEADERS`, ...) in rule after rule, so the values
//! are resolved the first time a rule of the phase asks and borrowed after
//! that. The same goes for what a transformation chain makes of each value: a
//! handful of chains (`t:none,t:urlDecodeUni`, ...) account for most rules.
//! The cache lives for one phase and is dropped with it.

use std::borrow::Cow;

use crate::parser::{Selection, VariableName, VariableSpec};
use crate::transformations::TransformationPipeline;
use crate::variables::VariableResolver;

/// One variable, as selected, resolved against the request or the response.
struct Entry {
    name: VariableName,
    selection: Option<Selection>,
    /// Before the rule's own exclusions (`!ARGS:x`), which differ per rule.
    values: Vec<(String, String)>,
}

/// What the phase that is running has worked out so far.
///
/// Two parts, so that a rule can hold the resolved values while it adds to
/// the transformed ones.
#[derive(Default)]
pub(crate) struct PhaseCache {
    pub(crate) resolved: Resolved,
    pub(crate) transformed: Transformed,
}

/// The variables resolved so far.
#[derive(Default)]
pub(crate) struct Resolved {
    entries: Vec<Entry>,
}

/// A resolved value: the slot of its variable and its position there.
pub(crate) type ValueAt = (usize, usize);

/// What the chains applied so far made of one value, by
/// [`TransformationPipeline::chain_key`]. `None` is a chain that left the value
/// as it was, which is not copied.
type Chains = Vec<(u32, Option<Box<str>>)>;

/// What each transformation chain made of each resolved value.
#[derive(Default)]
pub(crate) struct Transformed {
    /// Per slot, per value: the chains applied so far.
    by_slot: Vec<Vec<Chains>>,
    /// Bytes of transformed text kept so far.
    kept_bytes: usize,
}

/// How much transformed text one phase keeps. A value that every chain changes
/// is kept once per chain, so a large body full of escapes would otherwise be
/// held a dozen times over for the length of the phase, per request in flight.
/// Past the budget a value is transformed for the rule that asks and not kept,
/// which is what every rule did before there was a cache.
const TRANSFORMED_BUDGET_BYTES: usize = 4 * 1024 * 1024;

impl Transformed {
    /// `value`, which is the resolved value at `at`, through `pipeline`:
    /// transformed the first time, read back after that (while the budget
    /// lasts; see [`TRANSFORMED_BUDGET_BYTES`]).
    pub(crate) fn apply<'a>(
        &'a mut self,
        at: ValueAt,
        pipeline: &TransformationPipeline,
        value: &'a str,
    ) -> Cow<'a, str> {
        if pipeline.is_empty() {
            return Cow::Borrowed(value);
        }
        let (slot, item) = at;
        if self.by_slot.len() <= slot {
            self.by_slot.resize_with(slot + 1, Vec::new);
        }
        let values = &mut self.by_slot[slot];
        if values.len() <= item {
            values.resize_with(item + 1, Vec::new);
        }
        let chains = &mut values[item];
        let key = pipeline.chain_key();
        let found = match chains.iter().position(|(k, _)| *k == key) {
            Some(found) => found,
            None => {
                let result = match pipeline.apply(value) {
                    Cow::Borrowed(same)
                        if same.len() == value.len() && same.as_ptr() == value.as_ptr() =>
                    {
                        None
                    }
                    other => {
                        if self.kept_bytes + other.len() > TRANSFORMED_BUDGET_BYTES {
                            return Cow::Owned(other.into_owned());
                        }
                        self.kept_bytes += other.len();
                        Some(other.into_owned().into_boxed_str())
                    }
                };
                chains.push((key, result));
                chains.len() - 1
            }
        };
        Cow::Borrowed(chains[found].1.as_deref().unwrap_or(value))
    }
}

impl Resolved {
    /// Resolve this spec's values if no rule of the phase has asked for them
    /// yet. Nothing to do for a variable that can change while the phase runs
    /// (`TX`, `MATCHED_VAR`, ...): those are resolved again by every rule.
    pub(crate) fn prepare(&mut self, resolver: &VariableResolver<'_>, spec: &VariableSpec) {
        if fixed_for_the_phase(spec.name) && self.slot(spec).is_none() {
            self.entries.push(Entry {
                name: spec.name,
                selection: spec.selection.clone(),
                values: resolver.resolve_unfiltered(spec),
            });
        }
    }

    /// Where this spec's values are kept, once prepared; `None` for a variable
    /// that is not shared.
    pub(crate) fn slot(&self, spec: &VariableSpec) -> Option<usize> {
        // A phase of the CRS asks for a few dozen distinct variables; a scan
        // costs less than hashing the selection would.
        self.entries
            .iter()
            .position(|e| e.name == spec.name && e.selection == spec.selection)
    }

    /// The values kept at `slot`, as `(name, value)`.
    pub(crate) fn values(&self, slot: usize) -> &[(String, String)] {
        &self.entries[slot].values
    }
}

/// Whether a variable is read only from the request or the response, which
/// stay as they are for the length of a phase.
///
/// The list is of what is known to be fixed, not of what is known to change: a
/// variable added to the resolver later is resolved per rule until it is
/// listed here.
fn fixed_for_the_phase(name: VariableName) -> bool {
    matches!(
        name,
        VariableName::Args
            | VariableName::ArgsGet
            | VariableName::ArgsPost
            | VariableName::ArgsNames
            | VariableName::ArgsGetNames
            | VariableName::ArgsPostNames
            | VariableName::ArgsCombinedSize
            | VariableName::RequestHeaders
            | VariableName::RequestHeadersNames
            | VariableName::RequestCookies
            | VariableName::RequestCookiesNames
            | VariableName::RequestUri
            | VariableName::RequestUriRaw
            | VariableName::RequestMethod
            | VariableName::RequestProtocol
            | VariableName::RequestLine
            | VariableName::RequestFilename
            | VariableName::RequestBasename
            | VariableName::QueryString
            | VariableName::RequestBody
            | VariableName::RequestBodyLength
            | VariableName::Files
            | VariableName::FilesNames
            | VariableName::FilesSizes
            | VariableName::FilesCombinedSize
            | VariableName::MultipartPartHeaders
            | VariableName::Xml
            | VariableName::ResponseStatus
            | VariableName::ResponseHeaders
            | VariableName::ResponseBody
            | VariableName::ResponseContentType
    )
}
