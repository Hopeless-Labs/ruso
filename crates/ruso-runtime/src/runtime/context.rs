//! The mutable state a single script run carries: variables, stored probe
//! responses, open sockets, collected evidence, and the loop stack.
//!
//! One [`Context`] exists per execution. The executor threads it through every
//! instruction; nothing else in the runtime holds state between instructions.

use std::collections::HashMap;

use crate::runtime::report::{Finding, Report};
use crate::runtime::response::ProbeResponse;
use crate::runtime::session::ProbeSession;
use crate::runtime::spec::{CheckMetadata, ProgramSpec};

/// What a script variable can hold.
///
/// RSL has two kinds of variable: a plain string (`set x = "…"`) and a list
/// (`set xs = ["a", "b"]`, or the loop variable of a `for`).
#[derive(Debug, Clone, PartialEq)]
pub enum VariableValue {
    /// A single string. Interpolation (`{{ x }}`) substitutes this directly.
    String(String),
    /// An ordered list of strings, iterated by `for` and expanded by
    /// list-valued interpolation.
    List(Vec<String>),
}

impl VariableValue {
    /// The string behind a [`VariableValue::String`], or `None` for a list.
    ///
    /// Call sites that interpolate a variable into a request use this to
    /// reject a list where a scalar is required.
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            Self::List(_) => None,
        }
    }
}

/// The per-iteration bookkeeping of an active loop.
#[derive(Debug)]
pub enum LoopState {
    /// A `for <item> in <list>` loop.
    ForEach {
        /// Name of the loop variable rebound on each iteration.
        item: String,
        /// The values being iterated, snapshotted when the loop was entered.
        values: Vec<String>,
        /// Index of the current iteration into `values`.
        index: usize,
        /// Whatever `item` was bound to before the loop, restored on exit so a
        /// loop variable cannot leak into the enclosing scope.
        previous: Option<VariableValue>,
    },
}

/// One entry on the loop stack: the loop's state plus the jump targets the
/// control-flow opcodes resolve against.
#[derive(Debug)]
pub struct LoopFrame {
    /// Iteration state for this loop.
    pub state: LoopState,
    /// Program counter of the loop header, re-entered on `loop_back`.
    pub head_pc: usize,
    /// Where `continue` jumps to.
    pub continue_pc: usize,
    /// Where `break` (and normal exhaustion) jumps to.
    pub end_pc: usize,
}

/// All mutable state of one script run.
#[derive(Debug)]
pub struct Context {
    /// Variables currently in scope, by name.
    pub variables: HashMap<String, VariableValue>,
    /// Responses of probes that have been sent, keyed by probe name. A matcher
    /// like `home.status == 200` reads from here.
    pub responses: HashMap<String, ProbeResponse>,
    /// Live TCP/UDP sessions, keyed by probe name, kept open so a later `send`
    /// to the same probe reuses the connection.
    pub sessions: HashMap<String, ProbeSession>,
    /// The check's declared metadata (name, severity, impact, …), used to build
    /// the finding.
    pub metadata: CheckMetadata,
    /// The report being accumulated; receives the finding at the end of the run.
    pub report: Report,
    /// Proof strings collected by `evidence` instructions so far.
    pub evidence: Vec<String>,
    /// Delay inserted between retry attempts, set by `retry_delay`.
    pub retry_delay: Option<std::time::Duration>,
    /// Set when `fail` ran or a probe errored fatally; the run is reported as
    /// failed rather than clean.
    pub failed: bool,
    /// Whether every matcher evaluated so far has held. Starts `true` — a
    /// script with no matchers at all is a match.
    pub matched: bool,
    /// When false, `stop` was hit — do not emit a finding even if matchers passed.
    pub emit_finding: bool,
    /// Active loops, innermost last.
    pub loop_stack: Vec<LoopFrame>,
}

impl Default for Context {
    fn default() -> Self {
        Self {
            variables: HashMap::new(),
            responses: HashMap::new(),
            sessions: HashMap::new(),
            metadata: CheckMetadata::default(),
            report: Report::default(),
            evidence: Vec::new(),
            retry_delay: None,
            failed: false,
            matched: true,
            emit_finding: true,
            loop_stack: Vec::new(),
        }
    }
}

impl Context {
    /// A fresh context seeded with the program's declared metadata.
    pub fn from_spec(spec: &ProgramSpec) -> Self {
        Self {
            metadata: spec.metadata.clone(),
            ..Default::default()
        }
    }

    /// Bind `name` to a string value, replacing any previous binding.
    pub fn set_variable(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.variables
            .insert(name.into(), VariableValue::String(value.into()));
    }

    /// Bind `name` to a list value, replacing any previous binding.
    pub fn set_list_variable(&mut self, name: impl Into<String>, values: Vec<String>) {
        self.variables
            .insert(name.into(), VariableValue::List(values));
    }

    /// Put a saved binding back, or remove the variable when there was none.
    ///
    /// This is how a loop undoes its loop variable on exit: `value` is whatever
    /// [`LoopState::ForEach::previous`] held.
    pub fn restore_or_remove_variable(
        &mut self,
        name: impl Into<String>,
        value: Option<VariableValue>,
    ) {
        let name = name.into();
        match value {
            Some(value) => {
                self.variables.insert(name, value);
            }
            None => {
                self.variables.remove(&name);
            }
        }
    }

    /// The stored response of probe `name`, if it has been sent.
    pub fn response(&self, name: &str) -> Option<&ProbeResponse> {
        self.responses.get(name)
    }

    /// Record a probe's response, replacing an earlier one under the same name
    /// (a re-sent or retried probe reports its latest attempt).
    pub fn store_response(&mut self, name: impl Into<String>, response: ProbeResponse) {
        self.responses.insert(name.into(), response);
    }

    /// Make the response stored under `from` also reachable as `alias`.
    ///
    /// Used so an inline probe can be referred to by the name the script gave
    /// it. A no-op when `from` has no stored response.
    pub fn alias_response(&mut self, from: &str, alias: impl Into<String>) {
        if let Some(response) = self.responses.get(from).cloned() {
            self.responses.insert(alias.into(), response);
        }
    }

    /// Drop every open socket session, closing the connections.
    pub fn close_sessions(&mut self) {
        self.sessions.clear();
    }

    /// Turn the run into a finding on the report, if it earned one.
    ///
    /// Nothing is emitted when a matcher failed (`matched == false`) or the
    /// script ran `stop` (`emit_finding == false`). Collected evidence is moved
    /// onto the finding.
    pub fn finalize_finding(&mut self) {
        if !self.matched || !self.emit_finding {
            return;
        }
        let evidence = std::mem::take(&mut self.evidence);
        if let Some(finding) = Finding::from_metadata(&self.metadata, evidence) {
            self.report.set_finding(finding);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::contract::Severity;

    use super::Context;

    #[test]
    fn finalize_emits_finding_when_matched() {
        let mut ctx = Context {
            matched: true,
            ..Context::default()
        };
        ctx.metadata.name = Some("Exposed .env".into());
        ctx.metadata.severity = Some(Severity::High);
        ctx.evidence.push("DB_PASSWORD=secret".into());
        ctx.finalize_finding();
        assert_eq!(ctx.report.findings.len(), 1);
        assert_eq!(ctx.report.findings[0].name, "Exposed .env");
        assert_eq!(ctx.report.findings[0].severity, Severity::High);
    }

    #[test]
    fn finalize_skips_when_match_chain_failed() {
        let mut ctx = Context {
            matched: false,
            ..Context::default()
        };
        ctx.metadata.name = Some("Should not emit".into());
        ctx.finalize_finding();
        assert!(ctx.report.findings.is_empty());
    }

    #[test]
    fn finalize_skips_after_stop() {
        let mut ctx = Context {
            matched: true,
            emit_finding: false,
            ..Context::default()
        };
        ctx.metadata.name = Some("Stopped".into());
        ctx.finalize_finding();
        assert!(ctx.report.findings.is_empty());
    }
}
