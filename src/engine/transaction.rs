//! Transaction processing for ModSecurity.

use std::sync::Arc;

use super::chain::ChainState;
use super::control::{CtlDirective, TransactionControls};
use super::intervention::Intervention;
use super::phase::Phase;
use super::ruleset::{CompiledRule, CompiledRuleset, RuleEngineMode};
use super::scoring::AnomalyScore;
use crate::actions::{
    execute_actions, ActionResult, DisruptiveOutcome, FlowOutcome, SetVarOp, SetVarOperation,
};
use crate::error::Result;
use crate::operators::{compile_operator, Operator};
use crate::parser::{Action, DataAction, OperatorSpec};
use crate::variables::{
    Collection, MutableCollection, RequestData, ResponseData, TxCollection, VariableResolver,
};

/// Whether a lowercased Content-Type denotes a JSON body.
///
/// Covers the `+json` structured suffix (RFC 6839) as well as `application/json`,
/// so `application/vnd.api+json`, `application/problem+json` and friends are
/// inspected rather than silently falling through to the urlencoded parser.
fn is_json_content_type(ct_lower: &str) -> bool {
    let media_type = ct_lower.split(';').next().unwrap_or("").trim();
    media_type == "application/json"
        || media_type == "text/json"
        || media_type.ends_with("+json")
}

/// Whether a lowercased Content-Type denotes an XML body.
///
/// Covers the `+xml` structured suffix (RFC 6839), so SOAP
/// (`application/soap+xml`), Atom and friends are inspected rather than
/// falling through to a parser that finds nothing in them.
fn is_xml_content_type(ct_lower: &str) -> bool {
    let media_type = ct_lower.split(';').next().unwrap_or("").trim();
    media_type == "application/xml"
        || media_type == "text/xml"
        || media_type.ends_with("+xml")
}

/// A ModSecurity transaction for processing a single request.
pub struct Transaction {
    /// Compiled ruleset reference.
    ruleset: Arc<CompiledRuleset>,
    /// Request data.
    request: RequestData,
    /// Response data.
    response: ResponseData,
    /// TX collection (mutable variables).
    tx: TxCollection,
    /// Current phase.
    phase: Phase,
    /// Intervention (if any).
    intervention: Option<Intervention>,
    /// Anomaly score tracker.
    anomaly_score: AnomalyScore,
    /// Default block status.
    default_status: u16,
    /// Matched rules.
    matched_rules: Vec<String>,
    /// Allow flag (skip further processing).
    allowed: bool,
    /// Matched variables for current rule evaluation.
    matched_vars: Vec<(String, String)>,
    /// Regex captures from last match.
    captures: Vec<String>,
    /// Per-transaction `ctl:` overrides.
    controls: TransactionControls,
    /// Every variable that caused a rule to match, in order.
    ///
    /// Separate from `matched_vars`, which ModSecurity scopes to the current
    /// rule so that `MATCHED_VARS` reads correctly. This accumulates for the
    /// whole transaction, because audit logging wants to answer "what did
    /// rule 942100 actually see" after the fact.
    matched_data: Vec<MatchedData>,
}

/// The variable a rule matched on.
#[derive(Debug, Clone)]
struct MatchedVariable {
    name: String,
    value: String,
    portion: Option<String>,
}

/// Result of evaluating one rule.
struct RuleOutcome {
    matched: bool,
    captures: Vec<String>,
    matched_variable: Option<MatchedVariable>,
}

impl RuleOutcome {
    fn no_match() -> Self {
        Self {
            matched: false,
            captures: Vec::new(),
            matched_variable: None,
        }
    }
}

/// What a rule matched on.
///
/// `matched_rules()` gives rule IDs, which says a rule fired but not why.
/// Without the variable and value there is no way to tell a true positive
/// from a false one, or to write a useful audit log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedData {
    /// ID of the rule that matched, if it has one.
    pub rule_id: Option<String>,
    /// Name of the variable that matched, e.g. `ARGS:json.q`.
    pub variable: String,
    /// The variable's value, after transformations were applied.
    ///
    /// This is what `MATCHED_VAR` resolves to -- the whole value, not the
    /// portion the operator hit.
    pub value: String,
    /// The portion of the value the operator matched, when it reports one.
    ///
    /// `@contains evil` against `something-evil-here` gives `evil` here and
    /// the full string in `value`. Operators that match the whole value, or
    /// do not report a portion, leave this `None`.
    pub matched_portion: Option<String>,
}

impl Transaction {
    /// Create a new transaction.
    pub fn new(ruleset: Arc<CompiledRuleset>, default_status: u16) -> Self {
        Self {
            ruleset,
            request: RequestData::new(),
            response: ResponseData::new(),
            tx: TxCollection::new(),
            phase: Phase::RequestHeaders,
            intervention: None,
            anomaly_score: AnomalyScore::new(),
            default_status,
            matched_rules: Vec::new(),
            allowed: false,
            matched_vars: Vec::new(),
            captures: Vec::new(),
            controls: TransactionControls::default(),
            matched_data: Vec::new(),
        }
    }

    /// Set the client address, backing `REMOTE_ADDR` and `REMOTE_PORT`.
    ///
    /// Without this there is no way for a caller to populate them, so every
    /// IP-based rule -- `@ipMatch`, CRS IP reputation, allow and deny lists --
    /// evaluated against an empty string and never matched.
    pub fn set_client_addr(&mut self, ip: &str, port: u16) {
        self.request.client_ip = ip.to_string();
        self.request.client_port = port;
    }

    /// Set the local address, backing `SERVER_ADDR` and `SERVER_PORT`.
    pub fn set_server_addr(&mut self, ip: &str, port: u16) {
        self.request.server_addr = ip.to_string();
        self.request.server_port = port;
    }

    /// Set the server name, backing `SERVER_NAME`.
    pub fn set_server_name(&mut self, name: &str) {
        self.request.server_name = name.to_string();
    }

    /// Every variable that caused a rule to match, in order.
    ///
    /// Pairs with [`matched_rules`](Self::matched_rules): that says which
    /// rules fired, this says what they saw.
    pub fn matched_data(&self) -> &[MatchedData] {
        &self.matched_data
    }

    /// Process the request URI.
    pub fn process_uri(&mut self, uri: &str, method: &str, protocol: &str) -> Result<()> {
        self.request.set_uri(uri);
        self.request.set_method(method);
        self.request.set_protocol(protocol);
        Ok(())
    }

    /// Add a request header.
    pub fn add_request_header(&mut self, name: &str, value: &str) -> Result<()> {
        self.request.add_header(name, value);
        Ok(())
    }

    /// Process request headers (Phase 1).
    pub fn process_request_headers(&mut self) -> Result<()> {
        self.phase = Phase::RequestHeaders;
        self.run_phase(Phase::RequestHeaders)?;
        Ok(())
    }

    /// Append data to request body.
    pub fn append_request_body(&mut self, data: &[u8]) -> Result<()> {
        self.request.append_body(data);
        Ok(())
    }

    /// Process request body (Phase 2).
    pub fn process_request_body(&mut self) -> Result<()> {
        self.phase = Phase::RequestBody;

        let content_type = self
            .request
            .headers
            .get("content-type")
            .and_then(|v| v.first().map(|s| s.to_string()));
        let ct_lower = content_type
            .as_deref()
            .map(|ct| ct.trim_start().to_ascii_lowercase())
            .unwrap_or_default();

        // ctl:requestBodyAccess=Off, typically set in phase 1, suppresses body
        // parsing entirely. Phase 2 rules still run; they just find no ARGS_POST
        // or FILES, which is what disabling body access means.
        if !self.controls.request_body_access() {
            self.run_phase(Phase::RequestBody)?;
            return Ok(());
        }

        // ctl:requestBodyProcessor overrides Content-Type sniffing. CRS relies
        // on this to force a processor when the header is absent or lying.
        if let Some(forced) = self.controls.request_body_processor() {
            match forced {
                "MULTIPART" => {
                    if !self
                        .request
                        .parse_multipart_body(content_type.as_deref().unwrap_or_default())
                    {
                        tracing::warn!(
                            "ctl:requestBodyProcessor=MULTIPART, but the body has no parseable \
                             boundary; body arguments were not extracted"
                        );
                    }
                }
                "URLENCODED" => {
                    self.request.parse_form_body();
                    self.request.body_processor = "URLENCODED".to_string();
                }
                "JSON" => self.process_json_body(),
                "XML" => self.process_xml_body(),
                // CtlDirective::parse admits no other value.
                other => debug_assert!(false, "unsupported forced body processor: {other}"),
            }
            self.run_phase(Phase::RequestBody)?;
            return Ok(());
        }

        if ct_lower.starts_with("multipart/form-data") {
            // Multipart body processor: populates ARGS_POST, FILES and
            // MULTIPART_PART_HEADERS. Never fall back to the urlencoded
            // parser for multipart payloads — that would produce bogus ARGS.
            if !self
                .request
                .parse_multipart_body(content_type.as_deref().unwrap_or_default())
            {
                tracing::warn!(
                    "multipart/form-data request without a parseable boundary; \
                     body arguments were not extracted"
                );
            }
        } else if is_xml_content_type(&ct_lower) {
            self.process_xml_body();
        } else if is_json_content_type(&ct_lower) {
            // JSON bodies previously fell through to the urlencoded parser,
            // which extracts nothing usable from them -- so ARGS was empty and
            // rules like CRS 942100 (`SecRule ARGS "@detectSQLi"`) had nothing
            // to inspect. An injection payload was blocked in a form body and
            // passed unexamined in a JSON body.
            self.process_json_body();
        } else {
            self.request.parse_form_body();
            if ct_lower.starts_with("application/x-www-form-urlencoded") {
                self.request.body_processor = "URLENCODED".to_string();
            }
        }

        self.run_phase(Phase::RequestBody)?;
        Ok(())
    }

    /// Run the XML body processor, recording any failure.
    ///
    /// As with JSON, a failure is not fatal: phase 2 still runs so a rule
    /// testing `REQBODY_ERROR` can act on it.
    fn process_xml_body(&mut self) {
        if let Err(e) = self.request.parse_xml_body() {
            tracing::debug!(
                error = %e,
                "request body could not be processed as XML; REQBODY_ERROR is set"
            );
        }
    }

    /// Run the JSON body processor, recording any failure.
    ///
    /// A failure is deliberately not fatal: the request still goes through
    /// phase 2 so that rules testing `REQBODY_ERROR` can act on it, which is
    /// how CRS rule 200002 blocks bodies it could not parse. Dropping the
    /// request here instead would take that decision away from the ruleset.
    fn process_json_body(&mut self) {
        if let Err(e) = self.request.parse_json_body() {
            tracing::debug!(
                error = %e,
                "request body could not be processed as JSON; REQBODY_ERROR is set"
            );
        }
    }

    /// Add a response header.
    pub fn add_response_header(&mut self, name: &str, value: &str) -> Result<()> {
        self.response.add_header(name, value);
        Ok(())
    }

    /// Set the response status code (`RESPONSE_STATUS`). Call it before
    /// [`process_response_headers`](Self::process_response_headers): CRS 950100
    /// and the 95x response rules read it in phase 3 and 4.
    pub fn set_response_status(&mut self, status: u16) {
        self.response.set_status(status);
    }

    /// Process response headers (Phase 3).
    pub fn process_response_headers(&mut self) -> Result<()> {
        self.phase = Phase::ResponseHeaders;
        self.run_phase(Phase::ResponseHeaders)?;
        Ok(())
    }

    /// Append data to response body.
    pub fn append_response_body(&mut self, data: &[u8]) -> Result<()> {
        self.response.append_body(data);
        Ok(())
    }

    /// Process response body (Phase 4).
    pub fn process_response_body(&mut self) -> Result<()> {
        self.phase = Phase::ResponseBody;
        self.run_phase(Phase::ResponseBody)?;
        Ok(())
    }

    /// Process logging phase (Phase 5).
    pub fn process_logging(&mut self) -> Result<()> {
        self.phase = Phase::Logging;
        self.run_phase(Phase::Logging)?;
        Ok(())
    }

    /// Get current intervention (if any).
    pub fn intervention(&self) -> Option<&Intervention> {
        self.intervention.as_ref()
    }

    /// Check if there's an intervention.
    pub fn has_intervention(&self) -> bool {
        self.intervention.is_some()
    }

    /// Get matched rule IDs.
    pub fn matched_rules(&self) -> &[String] {
        &self.matched_rules
    }

    /// Get the anomaly score.
    pub fn anomaly_score(&self) -> i32 {
        self.anomaly_score.inbound
    }

    /// Get the TX collection.
    pub fn tx(&self) -> &TxCollection {
        &self.tx
    }

    /// Get mutable TX collection.
    pub fn tx_mut(&mut self) -> &mut TxCollection {
        &mut self.tx
    }

    /// The engine mode in force for this transaction.
    ///
    /// `ctl:ruleEngine` overrides the ruleset's configured mode for the
    /// remainder of the transaction; with no override this is the ruleset's
    /// own mode.
    fn engine_mode(&self) -> RuleEngineMode {
        self.controls.engine_mode(self.ruleset.engine_mode())
    }

    /// Run rules for a specific phase.
    fn run_phase(&mut self, phase: Phase) -> Result<()> {
        if self.allowed || self.intervention.is_some() {
            return Ok(());
        }

        // ctl:ruleEngine overrides the ruleset's mode for this transaction, so
        // the effective mode has to be re-read rather than captured once: a
        // rule in an earlier phase may have switched it off.
        if self.engine_mode() == RuleEngineMode::Off {
            return Ok(());
        }

        // Clone rules to avoid borrow conflicts with mutable self
        let rules: Vec<CompiledRule> = self.ruleset.rules_for_phase(phase).to_vec();
        if rules.is_empty() {
            return Ok(());
        }

        let mut chain_state = ChainState::new();
        // A chain is one logical rule: the starter's actions fire only when
        // every link matches, so they are held here until the chain completes.
        let mut pending_chain_actions: Option<ActionResult> = None;
        let mut skip_count: u32 = 0;
        let mut skip_after: Option<String> = None;

        let mut idx = 0;
        while idx < rules.len() {
            // Handle skip
            if skip_count > 0 {
                skip_count -= 1;
                idx += 1;
                continue;
            }

            // Handle skipAfter
            if let Some(ref marker) = skip_after {
                if let Some(marker_idx) = self.ruleset.marker(marker, phase) {
                    if marker_idx > idx {
                        idx = marker_idx;
                        skip_after = None;
                        continue;
                    }
                }
                // The marker is unknown, or sits at or behind the current
                // position: ModSecurity does not jump backwards, so the rest of
                // the phase is skipped.
                idx += 1;
                continue;
            }

            // A ctl:ruleEngine=Off from an earlier rule stops this phase where
            // it stands, rather than only taking effect from the next phase.
            if self.engine_mode() == RuleEngineMode::Off {
                return Ok(());
            }

            let rule = &rules[idx];

            // ctl:ruleRemoveById excluded this rule for this transaction. Skip
            // it as though it were not in the ruleset -- including its chain
            // links, which cannot fire without their starter.
            if self.controls.is_rule_removed(rule.id.as_deref()) {
                if rule.is_chain {
                    chain_state.reset();
                    pending_chain_actions = None;
                    idx += 1;
                    while idx < rules.len() && rules[idx - 1].is_chain {
                        idx += 1;
                    }
                    continue;
                }
                idx += 1;
                continue;
            }

            // Handle chain continuation
            if chain_state.in_chain && !rule.is_chain && rule.chain_next.is_none() {
                // End of chain, check if previous rules in chain matched
                if !chain_state.chain_matched {
                    chain_state.reset();
                    idx += 1;
                    continue;
                }
            }

            // Evaluate rule
            let outcome = self.evaluate_rule(rule)?;
            let matched = outcome.matched;
            let captures = outcome.captures;

            if matched {
                // `capture`: the operator's match and groups become TX:0..TX:9
                // for the rest of the transaction, as in ModSecurity, so a
                // `setvar:tx.x=%{tx.1}` on this rule, or a `TX:1` target in the
                // next chain link, sees them.
                if has_capture(rule) {
                    let full = outcome.matched_variable.as_ref().and_then(|v| v.portion.clone());
                    self.store_captures(full, &captures);
                }
                // MATCHED_VARS is scoped to the current rule in ModSecurity,
                // so this replaces rather than appends -- otherwise a later
                // rule would read the previous rule's matches.
                self.matched_vars.clear();
                if let Some(ref var) = outcome.matched_variable {
                    self.matched_vars
                        .push((var.name.clone(), var.value.clone()));
                    self.matched_data.push(MatchedData {
                        rule_id: rule.id.clone(),
                        variable: var.name.clone(),
                        value: var.value.clone(),
                        matched_portion: var.portion.clone(),
                    });
                }
            }

            if matched {
                // Execute actions
                let action_result = execute_actions(&rule.actions, None, &captures);

                // Track matched rule. A chain is one logical rule identified
                // by its starter: it is reported only once every link has
                // matched (below), not when the starter alone does.
                if !rule.is_chain && !chain_state.in_chain {
                    if let Some(ref id) = rule.id {
                        self.matched_rules.push(id.clone());
                    }
                }

                if rule.is_chain {
                    // A link that expects more links after it. Its `setvar`s
                    // take effect now, as in ModSecurity: CRS writes a value in
                    // the starter and reads it in the next link. Disruptive,
                    // flow and metadata actions wait until the whole chain has
                    // matched, so they are held with the starter's result.
                    let mut action_result = action_result;
                    for op in std::mem::take(&mut action_result.setvar_ops) {
                        self.apply_setvar(&op);
                    }
                    if !chain_state.in_chain {
                        chain_state.start_chain(idx);
                        pending_chain_actions = Some(action_result);
                    }
                    chain_state.continue_chain(true, &captures);
                    idx += 1;
                    continue;
                }

                // Either a standalone rule, or the final link of a chain that
                // has now matched in full. A completed chain executes the
                // starter's actions, not the last link's.
                let fired_id = if chain_state.in_chain {
                    chain_state.chain_start.and_then(|i| rules[i].id.clone())
                } else {
                    rule.id.clone()
                };
                let action_result = if chain_state.in_chain {
                    if let Some(ref id) = fired_id {
                        self.matched_rules.push(id.clone());
                    }
                    // The last link's own `setvar`s (CRS puts the anomaly score
                    // increments there) run now; the starter's held actions
                    // then take over for the disruptive and flow part.
                    let mut last = action_result;
                    for op in std::mem::take(&mut last.setvar_ops) {
                        self.apply_setvar(&op);
                    }
                    // So do its `ctl` overrides: in ModSecurity a link's
                    // non-disruptive actions run when the link matches, and
                    // exclusion rules (the CRS plugins, generated overlays)
                    // put `ctl:ruleRemoveById` on the last link, after the
                    // path and method conditions.
                    for ctl in &std::mem::take(&mut last.control_ops) {
                        self.controls.apply(CtlDirective::parse(ctl));
                    }
                    chain_state.reset();
                    pending_chain_actions.take().unwrap_or(last)
                } else {
                    action_result
                };

                // Apply setvar operations
                for op in &action_result.setvar_ops {
                    self.apply_setvar(op);
                }

                // Apply ctl: overrides before the disruptive action below, so
                // that ctl:ruleEngine=DetectionOnly on the same rule governs
                // whether that rule blocks.
                for ctl in &action_result.control_ops {
                    self.controls.apply(CtlDirective::parse(ctl));
                }

                // Handle flow control
                match action_result.flow {
                    FlowOutcome::Chain => {
                        if !chain_state.in_chain {
                            chain_state.start_chain(idx);
                        }
                        chain_state.continue_chain(true, &captures);
                    }
                    FlowOutcome::Skip(n) => {
                        skip_count = n;
                    }
                    FlowOutcome::SkipAfter(marker) => {
                        skip_after = Some(marker);
                    }
                    FlowOutcome::Continue => {}
                }

                // Handle disruptive action
                if let Some(outcome) = action_result.disruptive {
                    // Only apply if not in detection-only mode
                    let should_block = self.engine_mode() == RuleEngineMode::On;

                    match outcome {
                        DisruptiveOutcome::Deny(status) => {
                            if should_block {
                                let mut intervention = Intervention::deny(status, phase, fired_id.clone());
                                intervention.add_metadata(action_result.metadata);
                                self.intervention = Some(intervention);
                                return Ok(());
                            }
                        }
                        DisruptiveOutcome::Block => {
                            if should_block {
                                let mut intervention = Intervention::deny(self.default_status, phase, fired_id.clone());
                                intervention.add_metadata(action_result.metadata);
                                self.intervention = Some(intervention);
                                return Ok(());
                            }
                        }
                        DisruptiveOutcome::Allow => {
                            self.allowed = true;
                            return Ok(());
                        }
                        DisruptiveOutcome::Redirect(url) => {
                            if should_block {
                                let mut intervention = Intervention::redirect(url, phase, fired_id.clone());
                                intervention.add_metadata(action_result.metadata);
                                self.intervention = Some(intervention);
                                return Ok(());
                            }
                        }
                        DisruptiveOutcome::Drop => {
                            if should_block {
                                let mut intervention = Intervention::drop(phase, fired_id.clone());
                                intervention.add_metadata(action_result.metadata);
                                self.intervention = Some(intervention);
                                return Ok(());
                            }
                        }
                        DisruptiveOutcome::Pass => {
                            // Continue processing
                        }
                    }
                }
            } else {
                // Rule didn't match. If it belongs to a chain, the chain as a
                // whole cannot match: drop the starter's held actions and skip
                // past the remaining links so they are never evaluated on
                // their own.
                if chain_state.in_chain || rule.is_chain {
                    chain_state.reset();
                    pending_chain_actions = None;
                    while idx < rules.len() && rules[idx].is_chain {
                        idx += 1;
                    }
                    idx += 1;
                    continue;
                }
            }

            // End chain if this is the last rule in chain
            if chain_state.in_chain && !rule.is_chain {
                chain_state.end_chain();
            }

            idx += 1;
        }

        // Sync anomaly score to TX
        self.anomaly_score.sync_to_tx(&mut self.tx);

        Ok(())
    }

    /// Evaluate a single rule.
    fn evaluate_rule(&self, rule: &CompiledRule) -> Result<RuleOutcome> {
        let resolver = VariableResolver::new(
            &self.request,
            &self.response,
            &self.tx,
            // MATCHED_VAR is the value the previous rule matched on. This was
            // a literal `None`, so a rule reading MATCHED_VAR could never
            // fire, however many rules had matched before it.
            self.matched_vars.last().map(|(_, value)| value.as_str()),
            &self.matched_vars,
            &self.captures,
        );

        // Resolve variables from all specs.
        //
        // A spec in count mode (`&VAR`) contributes the *number* of matching
        // values as a single value — 0 when the variable is absent — rather than
        // the values themselves. This matches ModSecurity's `&VARIABLE` semantics
        // and is what CRS's `SecRule &TX:x "@eq 0"` initialization relies on.
        // Emitting a value even for an absent count also keeps the spec out of
        // the "resolved to nothing" early-return below, so `&x "@eq 0"` matches.
        // ctl:ruleRemoveTargetById drops individual targets from this rule for
        // this transaction. The check is hoisted so rules with no exclusion --
        // effectively all of them -- pay one comparison rather than a scan per
        // variable.
        let filter_targets = self.controls.has_target_removals(rule.id.as_deref());

        let mut all_values = Vec::new();
        let mut any_excluded = false;
        for spec in &rule.variables {
            let mut resolved = resolver.resolve(spec);
            if filter_targets {
                let before = resolved.len();
                resolved.retain(|(name, _)| {
                    !self
                        .controls
                        .is_target_removed(rule.id.as_deref(), spec, name)
                });
                any_excluded |= resolved.len() != before;
            }
            if spec.count_mode {
                // An exclusion reduces the count, which is what a rule like
                // `SecRule &ARGS:x "@eq 0"` is asking about.
                all_values.push((format!("&{:?}", spec.name), resolved.len().to_string()));
            } else {
                all_values.extend(resolved);
            }
        }

        // Exclusions removed everything this rule had to test. Return before
        // the branch below: a rule stripped down to nothing is not the same as
        // a SecAction with no targets, and running the operator unconditionally
        // could match.
        if any_excluded && all_values.is_empty() {
            return Ok(RuleOutcome::no_match());
        }

        if all_values.is_empty() {
            // A rule with no variable specs at all (i.e. SecAction) runs its
            // operator unconditionally — this is how CRS sets up TX thresholds.
            if rule.variables.is_empty() {
                let result = rule.operator.execute("");
                let matched = if rule.operator_negated { !result.matched } else { result.matched };
                // A SecAction has no variable, so there is nothing to report
                // as the match target.
                return Ok(RuleOutcome {
                    matched,
                    captures: result.captures,
                    matched_variable: None,
                });
            }
            // Variables were specified but resolved to nothing (e.g. absent
            // header). ModSecurity does not run the operator when there is no
            // value to run it against, so the rule does not match -- including
            // when the operator is negated. Reporting a negated operator as a
            // match here inverts "this variable is absent" into "every request
            // matches", which is how an unimplemented variable turned CRS
            // 920100 (`REQUEST_LINE "!@rx ..."`) into a rule that denied all
            // traffic. Absence is tested with `&VAR "@eq 0"`, which resolves to
            // a count and so never reaches this branch.
            return Ok(RuleOutcome {
                matched: false,
                captures: Vec::new(),
                matched_variable: None,
            });
        }

        // If the operator argument references runtime macros (e.g.
        // `@ge %{tx.inbound_anomaly_score_threshold}`), expand them against the
        // current TX state and recompile the operator so the comparison runs
        // against the resolved value. Otherwise use the precompiled operator.
        let dynamic_operator;
        let operator: &dyn Operator = if rule.operator_spec.argument.contains("%{") {
            let expanded = self.expand_operator_macros(&rule.operator_spec.argument);
            dynamic_operator = compile_operator(&OperatorSpec {
                negated: rule.operator_spec.negated,
                name: rule.operator_spec.name,
                argument: expanded,
            })?;
            dynamic_operator.as_ref()
        } else {
            rule.operator.as_ref()
        };

        // Apply transformations and match
        for (name, value) in all_values {
            let transformed = rule.transformations.apply(&value);
            let result = operator.execute(&transformed);

            let final_match = if rule.operator_negated { !result.matched } else { result.matched };

            if final_match {
                let matched = MatchedVariable {
                    name,
                    // ModSecurity's MATCHED_VAR is the *variable's* value, not
                    // the portion the operator hit. The portion is reported
                    // separately, since an audit log wants both: the value to
                    // judge the match, the portion to see what triggered it.
                    value: transformed.into_owned(),
                    portion: result.matched_value,
                };
                return Ok(RuleOutcome {
                    matched: true,
                    captures: result.captures,
                    matched_variable: Some(matched),
                });
            }
        }

        Ok(RuleOutcome::no_match())
    }

    /// Publish a `capture` result as `TX:0` (the whole match) and `TX:1..TX:9`
    /// (the groups), replacing the previous rule's captures.
    fn store_captures(&mut self, full: Option<String>, groups: &[String]) {
        for i in 0..10usize {
            let key = i.to_string();
            let value = if i == 0 { full.clone() } else { groups.get(i - 1).cloned() };
            match value {
                Some(v) => self.tx.set(key, v),
                None => self.tx.delete(&key),
            }
        }
        self.captures = groups.to_vec();
    }

    /// Expand `%{...}` macros in an operator argument or a `setvar` against
    /// the transaction: `tx.*` (with the `capture` slots `tx.0`..`tx.9`),
    /// `MATCHED_VAR`, `MATCHED_VAR_NAME`, `REMOTE_ADDR`, `request_headers.<name>`
    /// and `args.<name>`. An unresolved macro expands to the empty string,
    /// matching ModSecurity behaviour.
    fn expand_operator_macros(&self, arg: &str) -> String {
        let re = regex::Regex::new(r"%\{([^}]+)\}").expect("static macro regex is valid");
        re.replace_all(arg, |caps: &regex::Captures| {
            let inner = &caps[1];
            if inner.eq_ignore_ascii_case("MATCHED_VAR") {
                return self.matched_vars.last().map(|(_, v)| v.clone()).unwrap_or_default();
            }
            if inner.eq_ignore_ascii_case("MATCHED_VAR_NAME") {
                return self.matched_vars.last().map(|(n, _)| n.clone()).unwrap_or_default();
            }
            if inner.eq_ignore_ascii_case("REMOTE_ADDR") {
                return self.request.client_ip.clone();
            }
            let (collection, name) = match inner.split_once(['.', ':']) {
                Some((c, n)) => (c.to_ascii_lowercase(), n),
                None => ("tx".to_string(), inner),
            };
            match collection.as_str() {
                "tx" => first_value(self.tx.get(name)),
                "request_headers" => {
                    first_value(self.request.headers.get(&name.to_ascii_lowercase()))
                }
                "args" => first_value(
                    self.request.args_get.get(name).or_else(|| self.request.args_post.get(name)),
                ),
                _ => String::new(),
            }
        })
        .into_owned()
    }

    /// Apply a setvar operation. Macros are expanded in the value
    /// (`+%{tx.critical_anomaly_score}`) and in the name
    /// (`tx.header_name_%{tx.0}`), here, where TX state is available.
    fn apply_setvar(&mut self, op: &SetVarOp) {
        let name = if op.name.contains("%{") {
            self.expand_operator_macros(&op.name)
        } else {
            op.name.clone()
        };
        match &op.operation {
            SetVarOperation::Macro(raw) => {
                let expanded = self.expand_operator_macros(raw);
                let resolved = SetVarOp {
                    collection: op.collection.clone(),
                    name: name.clone(),
                    operation: interpret_setvar_rhs(&expanded),
                };
                crate::actions::apply_setvar(&mut self.tx, &resolved);
            }
            SetVarOperation::Set(value) => self.tx.set(name.clone(), value.clone()),
            SetVarOperation::Increment(delta) => self.tx.increment(&name, *delta),
            SetVarOperation::Decrement(delta) => self.tx.decrement(&name, *delta),
            SetVarOperation::Delete => self.tx.delete(&name),
        }

        // Sync anomaly score from TX if relevant
        if name == "anomaly_score" {
            self.anomaly_score.sync_from_tx(&self.tx);
        }
    }
}

/// First value of a collection lookup, or the empty string.
fn first_value(values: Option<Vec<&str>>) -> String {
    values.and_then(|v| v.first().map(|s| (*s).to_string())).unwrap_or_default()
}

/// Whether a rule carries the `capture` action.
fn has_capture(rule: &CompiledRule) -> bool {
    rule.actions.iter().any(|a| matches!(a, Action::Data(DataAction::Capture)))
}

fn interpret_setvar_rhs(value: &str) -> SetVarOperation {
    if let Some(rest) = value.strip_prefix('+') {
        SetVarOperation::Increment(rest.trim().parse().unwrap_or(0))
    } else if let Some(rest) = value.strip_prefix('-') {
        SetVarOperation::Decrement(rest.trim().parse().unwrap_or(0))
    } else {
        SetVarOperation::Set(value.to_string())
    }
}

impl std::fmt::Debug for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transaction")
            .field("phase", &self.phase)
            .field("has_intervention", &self.intervention.is_some())
            .field("anomaly_score", &self.anomaly_score.inbound)
            .field("matched_rules", &self.matched_rules)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::variables::Collection;

    fn make_ruleset(rules: &str) -> Arc<CompiledRuleset> {
        Arc::new(CompiledRuleset::from_string(rules).unwrap())
    }

    #[test]
    fn test_basic_match() {
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/admin/dashboard", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();

        assert!(tx.has_intervention());
        let intervention = tx.intervention().unwrap();
        assert_eq!(intervention.status, 403);
    }

    #[test]
    fn test_no_match() {
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/public/index.html", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();

        assert!(!tx.has_intervention());
    }

    #[test]
    fn test_setvar() {
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /test" "id:1,phase:1,pass,setvar:TX.score=5"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/test/page", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();

        assert!(!tx.has_intervention());
        let score = tx.tx().get("score").and_then(|v| v.first().map(|s| s.to_string()));
        assert_eq!(score, Some("5".to_string()));
    }

    #[test]
    fn test_operator_arg_macro_ge_threshold() {
        // @ge with a %{tx.*} argument must compare against the resolved value.
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /" "id:1,phase:1,pass,nolog,setvar:tx.threshold=5"
            SecRule REQUEST_URI "@contains /" "id:2,phase:1,pass,nolog,setvar:tx.score=10"
            SecRule TX:score "@ge %{tx.threshold}" "id:3,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert!(tx.has_intervention(), "score 10 >= threshold 5 should block");
    }

    #[test]
    fn test_operator_arg_macro_ge_below_threshold() {
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /" "id:1,phase:1,pass,nolog,setvar:tx.threshold=5"
            SecRule REQUEST_URI "@contains /" "id:2,phase:1,pass,nolog,setvar:tx.score=3"
            SecRule TX:score "@ge %{tx.threshold}" "id:3,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert!(!tx.has_intervention(), "score 3 < threshold 5 should not block");
    }

    #[test]
    fn test_negated_within_macro_does_not_block_allowed() {
        // Regression for the 911100 case: a negated @within whose argument is a
        // resolvable macro must not block when the value IS in the list.
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /" "id:1,phase:1,pass,nolog,setvar:tx.allowed=GET"
            SecRule REQUEST_METHOD "!@within %{tx.allowed}" "id:2,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert!(!tx.has_intervention(), "GET is allowed, must not block");
    }

    #[test]
    fn test_negated_within_macro_blocks_disallowed() {
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /" "id:1,phase:1,pass,nolog,setvar:tx.allowed=GET"
            SecRule REQUEST_METHOD "!@within %{tx.allowed}" "id:2,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert!(tx.has_intervention(), "POST is not allowed, must block");
    }

    #[test]
    fn test_secaction_sets_tx_and_macro_resolves() {
        // CRS-style: SecAction (no variables) seeds a TX threshold that a later
        // rule's operator macro resolves against.
        let ruleset = make_ruleset(r#"
            SecAction "id:1,phase:1,pass,nolog,setvar:tx.threshold=5"
            SecRule REQUEST_URI "@contains /" "id:2,phase:1,pass,nolog,setvar:tx.score=10"
            SecRule TX:score "@ge %{tx.threshold}" "id:3,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        let threshold = tx.tx().get("threshold").and_then(|v| v.first().map(|s| s.to_string()));
        assert_eq!(threshold, Some("5".to_string()), "SecAction setvar must apply");
        assert!(tx.has_intervention(), "10 >= 5 should block");
    }

    #[test]
    fn test_request_header_named_selector_matches() {
        // REQUEST_HEADERS:User-Agent must match regardless of header-name case.
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" "id:1,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.add_request_header("User-Agent", "sqlmap/1.0").unwrap();
        tx.process_request_headers().unwrap();
        assert!(tx.has_intervention(), "User-Agent selector should match");
    }

    #[test]
    fn test_setvar_value_macro_accumulates() {
        // CRS-style score accumulation: setvar:'tx.anomaly_score=+%{tx.critical_anomaly_score}'
        // must add the resolved delta (5), and twice must yield 10.
        let ruleset = make_ruleset(r#"
            SecAction "id:1,phase:1,pass,nolog,setvar:tx.critical_anomaly_score=5"
            SecRule REQUEST_URI "@contains /" "id:2,phase:1,pass,nolog,setvar:'tx.anomaly_score=+%{tx.critical_anomaly_score}'"
            SecRule REQUEST_URI "@contains /" "id:3,phase:1,pass,nolog,setvar:'tx.anomaly_score=+%{tx.critical_anomaly_score}'"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        let score = tx.tx().get("anomaly_score").and_then(|v| v.first().map(|s| s.to_string()));
        assert_eq!(score, Some("10".to_string()), "two +5 macro increments should total 10");
    }

    #[test]
    fn test_setvar_value_macro_unresolved_is_noop() {
        // An unresolved macro delta must not silently increment by 1.
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /" "id:1,phase:1,pass,nolog,setvar:'tx.anomaly_score=+%{tx.missing}'"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        let score = tx.tx().get("anomaly_score").and_then(|v| v.first().map(|s| s.to_string()));
        assert_eq!(score, Some("0".to_string()), "unresolved macro increment should be a no-op");
    }

    #[test]
    fn test_detection_only_mode() {
        let ruleset = make_ruleset(r#"
            SecRuleEngine DetectionOnly
            SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
        "#);
        let mut tx = Transaction::new(Arc::new(
            CompiledRuleset::from_string(r#"
                SecRuleEngine DetectionOnly
                SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny"
            "#).unwrap()
        ), 403);
        tx.process_uri("/admin/dashboard", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();

        // Should match but not block
        assert!(!tx.has_intervention());
        assert!(tx.matched_rules().contains(&"1".to_string()));
    }

    #[test]
    fn chain_starter_is_not_reported_when_a_later_link_fails() {
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /admin" "id:100,phase:1,deny,chain"
                SecRule REQUEST_HEADERS:User-Agent "@contains evil" "t:none"
            SecRule REQUEST_URI "@contains /admin" "id:200,phase:1,pass"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/admin", "GET", "HTTP/1.1").unwrap();
        tx.add_request_header("User-Agent", "friendly").unwrap();
        tx.process_request_headers().unwrap();
        assert!(!tx.has_intervention());
        assert_eq!(tx.matched_rules(), &["200".to_string()]);
    }

    #[test]
    fn completed_chain_is_reported_and_blocks_under_the_starter_id() {
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@contains /admin" "id:100,phase:1,deny,chain"
                SecRule REQUEST_HEADERS:User-Agent "@contains evil" "t:none"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/admin", "GET", "HTTP/1.1").unwrap();
        tx.add_request_header("User-Agent", "evil bot").unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(tx.matched_rules(), &["100".to_string()]);
        let intervention = tx.intervention().expect("chain blocks");
        assert_eq!(intervention.rule_ids, vec!["100".to_string()]);
    }

    fn tx_var(tx: &Transaction, key: &str) -> Option<String> {
        tx.tx().get(key).and_then(|v| v.first().map(|s| s.to_string()))
    }

    #[test]
    fn capture_publishes_the_match_and_groups_as_tx_0_to_9() {
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_URI "@rx ^/(\w+)/(\w+)" "id:1,phase:1,pass,capture,setvar:tx.first=%{tx.1}"
            SecRule REQUEST_URI "@rx ^/(\w+)" "id:3,phase:1,pass"
            SecRule TX:2 "@rx ^second$" "id:2,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/first/second", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(tx_var(&tx, "0"), Some("/first/second".to_string()));
        assert_eq!(tx_var(&tx, "1"), Some("first".to_string()));
        assert_eq!(tx_var(&tx, "first"), Some("first".to_string()));
        assert!(tx.has_intervention(), "TX:2 holds the second group; rule 3 has no capture");
    }

    #[test]
    fn chain_links_apply_setvar_as_they_match_and_the_last_link_scores() {
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_HEADERS:Content-Type "@rx ^[^;\s]+" "id:1,phase:1,pass,capture,setvar:'tx.ct=|%{tx.0}|',chain"
                SecRule TX:ct "!@within |text/plain|" "setvar:tx.score=+5"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "POST", "HTTP/1.1").unwrap();
        tx.add_request_header("Content-Type", "my/type; charset=utf-8").unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(tx.matched_rules(), &["1".to_string()]);
        assert_eq!(tx_var(&tx, "ct"), Some("|my/type|".to_string()));
        assert_eq!(tx_var(&tx, "score"), Some("5".to_string()));
    }

    #[test]
    fn the_last_chain_link_applies_its_ctl_when_the_chain_matches() {
        let ruleset = make_ruleset(r#"
            SecRule REQUEST_FILENAME "@streq /api/inventory" "id:10,phase:1,pass,nolog,chain"
                SecRule REQUEST_METHOD "@pm GET" "t:none,ctl:ruleRemoveById=20"
            SecRule ARGS "@contains evil" "id:20,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset.clone(), 403);
        tx.process_uri("/api/inventory?q=evil", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert!(!tx.has_intervention(), "the chain matched: rule 20 is removed");
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/api/inventory?q=evil", "POST", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert!(tx.has_intervention(), "the method link failed: rule 20 still runs");
    }

    #[test]
    fn macros_resolve_matched_var_request_headers_and_setvar_names() {
        let ruleset = make_ruleset(r#"
            SecRule ARGS:q "@contains evil" "id:1,phase:2,pass,setvar:'tx.seen_%{MATCHED_VAR_NAME}=%{MATCHED_VAR}'"
            SecRule TX:/^seen_/ "!@endsWith %{request_headers.host}" "id:2,phase:2,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/?q=evil-payload", "GET", "HTTP/1.1").unwrap();
        tx.add_request_header("Host", "example.com").unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        assert_eq!(tx_var(&tx, "seen_args:q"), Some("evil-payload".to_string()));
        assert!(tx.has_intervention(), "evil-payload does not end with example.com");
    }

    #[test]
    fn tx_regex_selection_is_case_insensitive_like_tx_keys() {
        let ruleset = make_ruleset(r#"
            SecAction "id:1,phase:1,pass,setvar:tx.multipart_headers_content_types_0=text/plain"
            SecRule TX:/MULTIPART_HEADERS_CONTENT_TYPES_*/ "@contains text/plain" "id:2,phase:1,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert!(tx.has_intervention());
    }

    #[test]
    fn response_status_is_visible_to_response_phase_rules() {
        let ruleset = make_ruleset(r#"
            SecRule RESPONSE_STATUS "@rx ^5\d{2}$" "id:950100,phase:3,deny"
        "#);
        let mut tx = Transaction::new(ruleset, 403);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        tx.set_response_status(500);
        tx.add_response_header("Content-Type", "text/html").unwrap();
        tx.process_response_headers().unwrap();
        assert!(tx.has_intervention(), "RESPONSE_STATUS 500 matches ^5\\d{{2}}$");
        assert_eq!(tx.matched_rules(), &["950100".to_string()]);
    }
}
