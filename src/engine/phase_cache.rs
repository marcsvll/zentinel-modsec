//! What a phase works out once and every rule of it reuses.
//!
//! The request and the response do not change while the rules of a phase run:
//! rules write to TX, to the captures and to the per-transaction controls,
//! never to the request. CRS tests the same collections (`ARGS`,
//! `REQUEST_COOKIES`, `REQUEST_HEADERS`, ...) in rule after rule, so the values
//! are resolved the first time a rule of the phase asks and borrowed after
//! that. The cache lives for one phase and is dropped with it.

use crate::parser::{Selection, VariableName, VariableSpec};
use crate::variables::VariableResolver;

/// One variable, as selected, resolved against the request or the response.
struct Entry {
    name: VariableName,
    selection: Option<Selection>,
    /// Before the rule's own exclusions (`!ARGS:x`), which differ per rule.
    values: Vec<(String, String)>,
}

/// The variables resolved so far in the phase that is running.
#[derive(Default)]
pub(crate) struct PhaseCache {
    entries: Vec<Entry>,
}

impl PhaseCache {
    /// Where this spec's values are kept, resolving them on first use.
    ///
    /// `None` when the variable can change while the phase runs (`TX`,
    /// `MATCHED_VAR`, ...): those are resolved again by every rule.
    pub(crate) fn slot(
        &mut self,
        resolver: &VariableResolver<'_>,
        spec: &VariableSpec,
    ) -> Option<usize> {
        if !fixed_for_the_phase(spec.name) {
            return None;
        }
        // A phase of the CRS asks for a few dozen distinct variables; a scan
        // costs less than hashing the selection would.
        if let Some(found) = self
            .entries
            .iter()
            .position(|e| e.name == spec.name && e.selection == spec.selection)
        {
            return Some(found);
        }
        self.entries.push(Entry {
            name: spec.name,
            selection: spec.selection.clone(),
            values: resolver.resolve_unfiltered(spec),
        });
        Some(self.entries.len() - 1)
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
