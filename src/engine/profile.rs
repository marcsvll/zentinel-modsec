//! Where a transaction spends its time, per phase and per rule.
//!
//! Recorded only when the caller asks (`Transaction::enable_profile`). The
//! clock is read around each stage of each rule, which costs more than some of
//! the stages themselves: a profile ranks rules and stages against each other
//! and is not a benchmark.

use std::time::Duration;

use super::phase::Phase;
use super::ruleset::CompiledRule;

/// What one rule cost in one transaction (summed when a phase runs twice).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleProfile {
    /// The rule's id; a chain link without one carries its starter's id.
    pub id: Option<String>,
    /// Whether this is a link of a chain after the starter.
    pub chain_link: bool,
    /// Times the rule was evaluated.
    pub evaluations: u64,
    /// Values the rule's variables resolved to.
    pub values: u64,
    /// The whole evaluation: the stages below and what is between them.
    pub total_ns: u64,
    /// Resolving the variables to values (target exclusions included).
    pub resolve_ns: u64,
    /// Compiling the operator, for one whose argument has a macro.
    pub operator_compile_ns: u64,
    /// Applying the transformations to every value.
    pub transform_ns: u64,
    /// Running the operator on every transformed value.
    pub operator_ns: u64,
}

/// What one phase cost.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhaseProfile {
    /// The whole phase.
    pub total_ns: u64,
    /// Before the first rule: taking the phase's rules out of the rule set.
    pub setup_ns: u64,
    /// The phase's rules, in rule-set order; a rule never reached has 0 evaluations.
    pub rules: Vec<RuleProfile>,
}

/// A transaction's profile: one entry per phase, index 0 for phase 1.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    /// Phases 1 to 5.
    pub phases: [PhaseProfile; 5],
}

pub(super) fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

impl Profile {
    fn phase_mut(&mut self, phase: Phase) -> &mut PhaseProfile {
        &mut self.phases[usize::from(phase.number()) - 1]
    }

    pub(super) fn begin_phase(&mut self, phase: Phase, rules: &[CompiledRule], setup: Duration) {
        let p = self.phase_mut(phase);
        p.setup_ns += nanos(setup);
        if p.rules.is_empty() {
            let mut starter: Option<String> = None;
            let mut in_chain = false;
            p.rules = rules
                .iter()
                .map(|rule| {
                    if !in_chain {
                        starter.clone_from(&rule.id);
                    }
                    let entry = RuleProfile {
                        id: rule.id.clone().or_else(|| starter.clone()),
                        chain_link: in_chain,
                        ..RuleProfile::default()
                    };
                    in_chain = rule.is_chain;
                    entry
                })
                .collect();
        }
    }

    pub(super) fn end_phase(&mut self, phase: Phase, total: Duration) {
        self.phase_mut(phase).total_ns += nanos(total);
    }

    pub(super) fn add_rule(&mut self, phase: Phase, index: usize, t: &RuleProfile) {
        if let Some(r) = self.phase_mut(phase).rules.get_mut(index) {
            r.evaluations += t.evaluations;
            r.values += t.values;
            r.total_ns += t.total_ns;
            r.resolve_ns += t.resolve_ns;
            r.operator_compile_ns += t.operator_compile_ns;
            r.transform_ns += t.transform_ns;
            r.operator_ns += t.operator_ns;
        }
    }
}
