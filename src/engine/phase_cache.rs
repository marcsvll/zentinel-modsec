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

use crate::engine::ruleset::LiteralIndex;
use crate::parser::{Selection, VariableName, VariableSpec};
use crate::transformations::TransformationPipeline;
use crate::variables::VariableResolver;

/// One variable, as selected, resolved against the request or the response.
struct Entry {
    name: VariableName,
    selection: Option<Selection>,
    /// Before the rule's own exclusions (`!ARGS:x`), which differ per rule.
    values: crate::variables::Vals,
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
type Chains = Vec<(u32, Option<Box<[u8]>>)>;

/// What each transformation chain made of each resolved value.
#[derive(Default)]
pub(crate) struct Transformed {
    /// Per slot, per value: the chains applied so far.
    by_slot: Vec<Vec<Chains>>,
    /// Per slot and value, the classes of bytes of the value as resolved
    /// ([`UNKNOWN`] until first asked for).
    raw_classes: Vec<Vec<u64>>,
    /// Per slot and chain, the classes of bytes of each value after the chain.
    classes: Vec<Vec<((u32, bool), Vec<u64>)>>,
    /// Per slot and value, which rules of the phase's literal index the value
    /// as resolved can match: a place in `sets` ([`UNSCANNED`] until asked).
    raw_hits: Vec<Vec<u32>>,
    /// Per slot and chain, the same for each value after the chain.
    hits: Vec<Vec<HitsOfChain>>,
    /// The sets of rules `raw_hits` and `hits` point into, each of the index's
    /// number of words; the first is the empty set. Each distinct set is kept
    /// once (`set_at`): a request has few of them, however many values.
    sets: Vec<u64>,
    /// Where each set of `sets` is.
    set_at: std::collections::HashMap<Vec<u64>, u32>,
    /// Whether the prefilter's shortcuts may be taken: off, every chain runs
    /// in full, the reference the prefilter is tested against.
    pub(crate) shortcuts: bool,
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
        value: &'a [u8],
    ) -> Cow<'a, [u8]> {
        if pipeline.is_empty() {
            return Cow::Borrowed(value);
        }
        // A value with none of the bytes the chain touches is its own result:
        // nothing to run, nothing to keep.
        if let Some(touches) = pipeline.touches().filter(|_| self.shortcuts) {
            if self.raw_classes(at, value) & touches == 0 {
                return Cow::Borrowed(value);
            }
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
                        Some(other.into_owned().into_boxed_slice())
                    }
                };
                chains.push((key, result));
                chains.len() - 1
            }
        };
        Cow::Borrowed(chains[found].1.as_deref().unwrap_or(value))
    }
}

impl Transformed {
    /// Whether `pipeline` is known to leave the value at `at` as it is, from
    /// the classes of its bytes alone (see
    /// [`TransformationPipeline::touches`]).
    pub(crate) fn untouched(
        &mut self,
        at: ValueAt,
        pipeline: &TransformationPipeline,
        value: &[u8],
    ) -> bool {
        pipeline.is_empty()
            || (self.shortcuts
                && pipeline
                    .touches()
                    .is_some_and(|t| self.raw_classes(at, value) & t == 0))
    }

    /// File a set of rules and say where; the empty set is always [`NO_RULE`].
    fn file(&mut self, set: &[u64]) -> u32 {
        if set.iter().all(|w| *w == 0) {
            return NO_RULE;
        }
        if let Some(&at) = self.set_at.get(set) {
            return at;
        }
        if self.sets.is_empty() {
            // The first place is the empty set's.
            self.sets.resize(set.len(), 0);
        }
        self.sets.extend_from_slice(set);
        let at = (self.sets.len() / set.len() - 1) as u32;
        self.set_at.insert(set.to_vec(), at);
        at
    }

    /// Which rules of the phase's literal index every value of a slot can
    /// match after `pipeline`, in the slot's order. As for
    /// [`classes`](Self::classes): computed once per slot and chain, a value
    /// the chain leaves alone is scanned once whatever the chain, and with
    /// `every_step` a value the chain touches rules nothing out.
    fn hits(
        &mut self,
        slot: usize,
        pipeline: &TransformationPipeline,
        every_step: bool,
        values: &[(Vec<u8>, Vec<u8>)],
        index: &LiteralIndex,
    ) -> usize {
        if self.hits.len() <= slot {
            self.hits.resize_with(slot + 1, Vec::new);
            self.raw_hits.resize_with(slot + 1, Vec::new);
        }
        if self.raw_hits[slot].len() < values.len() {
            self.raw_hits[slot].resize(values.len(), UNSCANNED);
        }
        let key = (pipeline.chain_key(), every_step);
        let found = match self.hits[slot].iter().position(|(k, _, _)| *k == key) {
            Some(found) => found,
            None => {
                let mut of_value = Vec::with_capacity(values.len());
                let mut found_in_form = vec![0u64; index.words()];
                for (item, (_, value)) in values.iter().enumerate() {
                    let raw = self.raw_classes((slot, item), value);
                    let untouched = pipeline.touches().is_some_and(|t| raw & t == 0);
                    if every_step && !untouched {
                        of_value.push(EVERY_RULE);
                        continue;
                    }
                    // The form the operator sees, if the chain changes the value:
                    // scanned into `found_in_form`, since the form is borrowed
                    // from the cache the sets are kept in.
                    found_in_form.iter_mut().for_each(|w| *w = 0);
                    let changed = if untouched {
                        false
                    } else {
                        match self.apply((slot, item), pipeline, value) {
                            Cow::Borrowed(same)
                                if same.len() == value.len() && same.as_ptr() == value.as_ptr() =>
                            {
                                false
                            }
                            form => {
                                index.scan(&form, &mut found_in_form);
                                true
                            }
                        }
                    };
                    of_value.push(if changed {
                        self.file(&found_in_form)
                    } else {
                        if self.raw_hits[slot][item] == UNSCANNED {
                            index.scan(value, &mut found_in_form);
                            self.raw_hits[slot][item] = self.file(&found_in_form);
                        }
                        self.raw_hits[slot][item]
                    });
                }
                let with_a_literal = (0..of_value.len() as u32)
                    .filter(|&i| of_value[i as usize] != NO_RULE)
                    .collect();
                self.hits[slot].push((key, of_value, with_a_literal));
                self.hits[slot].len() - 1
            }
        };
        found
    }

    /// What is known, before any operator runs, about which values of a slot
    /// a rule can match after `pipeline`: their classes of bytes when the rule
    /// has a need, the rules whose literals they contain when it has literals.
    pub(crate) fn candidates(
        &mut self,
        slot: usize,
        pipeline: &TransformationPipeline,
        every_step: bool,
        values: &[(Vec<u8>, Vec<u8>)],
        with_classes: bool,
        index: Option<&LiteralIndex>,
    ) -> Candidates<'_> {
        let classes = with_classes.then(|| self.classes(slot, pipeline, every_step, values));
        let hits = index.map(|index| (self.hits(slot, pipeline, every_step, values, index), index));
        Candidates {
            classes: classes.map(|found| self.classes[slot][found].1.as_slice()),
            hits: hits.map(|(found, index)| Hits {
                of_value: &self.hits[slot][found].1,
                with_a_literal: &self.hits[slot][found].2,
                sets: &self.sets,
                words: index.words(),
            }),
        }
    }

    /// The classes of bytes of a value as resolved, summarized on first use.
    fn raw_classes(&mut self, (slot, item): ValueAt, value: &[u8]) -> u64 {
        if self.raw_classes.len() <= slot {
            self.raw_classes.resize_with(slot + 1, Vec::new);
        }
        let of_slot = &mut self.raw_classes[slot];
        if of_slot.len() <= item {
            of_slot.resize(item + 1, UNKNOWN);
        }
        if of_slot[item] == UNKNOWN {
            of_slot[item] = crate::prefilter::classes(value);
        }
        of_slot[item]
    }

    /// The classes of bytes ([`crate::prefilter::classes`]) of every value of
    /// a slot after `pipeline`, in the slot's order: what a rule's
    /// [`Need`](crate::prefilter::Need) is tested against before its operator
    /// runs. Computed once per slot and chain; a value the chain leaves as it
    /// is has the classes of the value as resolved.
    ///
    /// With `every_step` (`multiMatch`) the operator also runs on the value
    /// before the chain and after each step, so only a value the chain is
    /// known not to touch has one form to summarize; any other is given every
    /// class, which no need rules out.
    fn classes(
        &mut self,
        slot: usize,
        pipeline: &TransformationPipeline,
        every_step: bool,
        values: &[(Vec<u8>, Vec<u8>)],
    ) -> usize {
        if self.classes.len() <= slot {
            self.classes.resize_with(slot + 1, Vec::new);
        }
        let key = (pipeline.chain_key(), every_step);
        let found = match self.classes[slot].iter().position(|(k, _)| *k == key) {
            Some(found) => found,
            None => {
                let mut masks = Vec::with_capacity(values.len());
                for (item, (_, value)) in values.iter().enumerate() {
                    let raw = self.raw_classes((slot, item), value);
                    if every_step {
                        let untouched = pipeline.touches().is_some_and(|t| raw & t == 0);
                        masks.push(if untouched { raw } else { u64::MAX });
                        continue;
                    }
                    let changed = match self.apply((slot, item), pipeline, value) {
                        Cow::Borrowed(same)
                            if same.len() == value.len() && same.as_ptr() == value.as_ptr() =>
                        {
                            None
                        }
                        other => Some(crate::prefilter::classes(&other)),
                    };
                    masks.push(changed.unwrap_or(raw));
                }
                self.classes[slot].push((key, masks));
                self.classes[slot].len() - 1
            }
        };
        found
    }
}

/// The set of no rule: most values contain no literal of any rule.
const NO_RULE: u32 = 0;
/// A value whose forms are not all known (`multiMatch` on a value the chain
/// touches): no rule is ruled out.
const EVERY_RULE: u32 = u32::MAX;
/// A value not scanned yet.
const UNSCANNED: u32 = u32::MAX - 1;

/// For one chain (its key and whether every step counts): the set of rules
/// each value can match, and the values that can match some rule.
type HitsOfChain = ((u32, bool), Vec<u32>, Vec<u32>);

/// See [`Transformed::candidates`].
pub(crate) struct Candidates<'a> {
    pub(crate) classes: Option<&'a [u64]>,
    pub(crate) hits: Option<Hits<'a>>,
}

/// Which rules of a phase's literal index each value of a slot can match.
pub(crate) struct Hits<'a> {
    of_value: &'a [u32],
    with_a_literal: &'a [u32],
    sets: &'a [u64],
    words: usize,
}

impl Hits<'_> {
    /// The values that hold a literal of some rule (or whose forms are not
    /// all known), in the slot's order: the only ones a rule with literals
    /// can match.
    pub(crate) fn with_a_literal(&self) -> &[u32] {
        self.with_a_literal
    }

    /// Whether the value at `item` contains a literal of `rule`.
    #[inline]
    pub(crate) fn allows(&self, item: usize, rule: u16) -> bool {
        match self.of_value[item] {
            NO_RULE => false,
            EVERY_RULE => true,
            set => {
                let rule = usize::from(rule);
                self.sets[set as usize * self.words + rule / 64] & (1 << (rule % 64)) != 0
            }
        }
    }
}

/// A summary not computed yet: no value has every bit set.
const UNKNOWN: u64 = u64::MAX;

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
    pub(crate) fn values(&self, slot: usize) -> &[(Vec<u8>, Vec<u8>)] {
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
