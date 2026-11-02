//! Mutators that append one SQL-breaking character (a quote, a bracket, a
//! comment opener) so the query fails to parse. WSan reports a SQL injection
//! only when the query fails to parse, so a valid payload like `' OR 1=1--`
//! is not enough: it runs cleanly and WSan never sees it.

use std::borrow::Cow;
use std::collections::HashMap;

use libafl::{
    Error, HasMetadata,
    corpus::CorpusId,
    inputs::{BytesInput, ResizableMutator},
    mutators::{MutationResult, Mutator},
    state::HasRand,
};
use libafl_bolts::{Named, rands::Rand};

use crate::input::{Body, OpenApiInput, ParameterContents, parameter::SimpleValue};
use crate::wsan_taint::WsanTaintMap;

/// Characters that leave a SQL statement unbalanced: an opening quote or
/// backtick, a lone bracket, an unclosed comment, a trailing backslash.
/// Appended to a value, any of them makes the query fail to parse.
pub const SQL_BREAKERS: [&str; 7] = ["'", "\"", "`", ")", "(", "/*", "\\"];

// Breakers for other kinds of sink, chosen by the CWE WSan reports. Unused for
// now: on the current benchmark WSan only reports SQL sinks (CWE-89).
/// Breakers for path traversal sinks (CWE-22).
const PATH_BREAKERS: [&str; 4] = ["../", "..\\", "%2e%2e/", "/.."];
/// Breakers for OS command sinks (CWE-78).
const CMD_BREAKERS: [&str; 6] = [";", "|", "&", "`", "$(", "\n"];

/// The breakers to use on a sink with the given CWE.
fn breakers_for_cwe(cwe: u32) -> &'static [&'static str] {
    match cwe {
        22 => &PATH_BREAKERS[..], // path traversal
        78 => &CMD_BREAKERS[..],  // OS command injection
        _ => &SQL_BREAKERS[..],   // 89 SQL injection, and the default
    }
}

/// Appends a breaker to the one string value WuppieFuzz picked to mutate this
/// round. Finds bugs early, but WuppieFuzz mostly picks query parameters, so
/// SqlBreakTargetedMutator covers form fields, headers and cookies.
pub struct SqlBreakMutator {
    /// False without --enable-wsan, or with WSAN_WF_SQLBREAK=0.
    active: bool,
}

impl SqlBreakMutator {
    /// Active with --enable-wsan; WSAN_WF_SQLBREAK=0 turns it off anyway.
    #[must_use]
    pub fn new(enable_wsan: bool) -> Self {
        Self {
            active: enable_wsan && sql_break_env(),
        }
    }
}

/// False when WSAN_WF_SQLBREAK=0, to compare runs without the mutators.
fn sql_break_env() -> bool {
    std::env::var("WSAN_WF_SQLBREAK").map_or(true, |v| v != "0")
}

impl Named for SqlBreakMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("SqlBreakMutator")
    }
}

impl<S> Mutator<BytesInput, S> for SqlBreakMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        if !self.active {
            return Ok(MutationResult::Skipped);
        }
        // Append instead of replacing, so the value still passes any check the
        // app does before running the query.
        input.extend(state.rand_mut().choose(SQL_BREAKERS).unwrap().as_bytes());
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

/// Appends a breaker only to the parameters that WSan has seen reach a sink on
/// this request's path (from WsanTaintMap). Until the path has any, it breaks
/// every string field.
pub struct SqlBreakTargetedMutator {
    /// False without --enable-wsan, or with WSAN_WF_SQLBREAK=0.
    active: bool,
    /// False when WSAN_WF_TARGETED=0: ignore WsanTaintMap.
    targeted: bool,
}

impl SqlBreakTargetedMutator {
    /// Active with --enable-wsan; WSAN_WF_SQLBREAK=0 turns it off anyway.
    /// WSAN_WF_TARGETED=0 ignores WsanTaintMap and breaks every string field.
    #[must_use]
    pub fn new(enable_wsan: bool) -> Self {
        Self {
            active: enable_wsan && sql_break_env(),
            targeted: std::env::var("WSAN_WF_TARGETED").map_or(true, |v| v != "0"),
        }
    }
}

impl Named for SqlBreakTargetedMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("SqlBreakTargetedMutator")
    }
}

/// Appends `breaker` to every string value under `pc`; true if any changed.
fn append_breaker(pc: &mut ParameterContents, breaker: &str) -> bool {
    match pc {
        ParameterContents::LeafValue(SimpleValue::String(s)) => {
            s.push_str(breaker);
            true
        }
        ParameterContents::Bytes(b) => {
            b.extend_from_slice(breaker.as_bytes());
            true
        }
        ParameterContents::Object(m) => {
            let mut c = false;
            for v in m.values_mut() {
                c |= append_breaker(v, breaker);
            }
            c
        }
        ParameterContents::Array(a) => {
            let mut c = false;
            for v in a.iter_mut() {
                c |= append_breaker(v, breaker);
            }
            c
        }
        _ => false,
    }
}

/// The breakers for one parameter, or None to leave it alone. If the path is in
/// WsanTaintMap (Some), only its listed parameters are broken, each with the
/// breakers for its CWE. Otherwise every string field gets the SQL breakers.
fn palette_for(snap: &Option<HashMap<String, u32>>, name: &str) -> Option<&'static [&'static str]> {
    match snap {
        Some(tainted) => tainted.get(name).map(|&cwe| breakers_for_cwe(cwe)),
        None => Some(&SQL_BREAKERS[..]),
    }
}

impl<S> Mutator<OpenApiInput, S> for SqlBreakTargetedMutator
where
    S: HasRand + HasMetadata,
{
    fn mutate(&mut self, state: &mut S, input: &mut OpenApiInput) -> Result<MutationResult, Error> {
        if !self.active {
            return Ok(MutationResult::Skipped);
        }
        // Copy this path's entries first: rand_mut below borrows the state.
        let snaps: Vec<Option<HashMap<String, u32>>> = if self.targeted {
            let taint = state.metadata::<WsanTaintMap>().ok();
            input
                .0
                .iter()
                .map(|req| taint.and_then(|m| m.tainted(&req.path)).cloned())
                .collect()
        } else {
            input.0.iter().map(|_| None).collect()
        };
        let mut changed = false;
        for (req, snap) in input.0.iter_mut().zip(snaps.iter()) {
            for ((name, _kind), pc) in req.parameters.iter_mut() {
                if let Some(palette) = palette_for(snap, name) {
                    let breaker = *state.rand_mut().choose(palette).unwrap();
                    changed |= append_breaker(pc, breaker);
                }
            }
            match &mut req.body {
                Body::ApplicationJson(pc) | Body::XWwwFormUrlencoded(pc) | Body::TextPlain(pc) => {
                    if let ParameterContents::Object(m) = pc {
                        for (name, child) in m.iter_mut() {
                            if let Some(palette) = palette_for(snap, name) {
                                let breaker = *state.rand_mut().choose(palette).unwrap();
                                changed |= append_breaker(child, breaker);
                            }
                        }
                    } else if let Some(palette) = palette_for(snap, "body") {
                        let breaker = *state.rand_mut().choose(palette).unwrap();
                        changed |= append_breaker(pc, breaker);
                    }
                }
                Body::Empty => {}
            }
        }
        Ok(if changed {
            MutationResult::Mutated
        } else {
            MutationResult::Skipped
        })
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{
        CMD_BREAKERS, SQL_BREAKERS, SqlBreakMutator, SqlBreakTargetedMutator, palette_for,
    };

    #[test]
    fn palette_follows_learned_taint() {
        // Path not in WsanTaintMap yet: every field gets the SQL breakers.
        assert_eq!(palette_for(&None, "any"), Some(&SQL_BREAKERS[..]));
        let taint = Some(HashMap::from([("cmd".to_owned(), 78)]));
        assert_eq!(palette_for(&taint, "cmd"), Some(&CMD_BREAKERS[..]));
        assert_eq!(palette_for(&taint, "other"), None);
    }

    #[test]
    fn mutators_off_without_enable_wsan() {
        assert!(!SqlBreakMutator::new(false).active);
        assert!(!SqlBreakTargetedMutator::new(false).active);
    }
}
