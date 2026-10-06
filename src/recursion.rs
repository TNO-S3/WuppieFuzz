//! Shared helper for guarding against unbounded schema recursion.
//!
//! OpenAPI schemas can be (mutually) self-referential (e.g. `User` ->
//! `UserIdentity` -> `User`). Example generation
//! ([`crate::openapi::examples`]) and the link mutator's field discovery
//! ([`crate::parameter_access`]) both walk schemas recursively and need a
//! depth limit as a backstop against such cycles, and against long chains of
//! distinct, non-repeating `$ref`s which a cycle check alone can't bound.
//!
//! The limit can be hit many times per run, so the warning is logged once
//! per process to avoid flooding the terminal.

use std::sync::Once;

/// Returns `true` once `recursion_depth` reaches `limit`, logging `message()`
/// once (via `warned`) the first time this happens. Use one `static WARNED:
/// Once` per call site, so hitting the limit in one place doesn't suppress an
/// independent warning elsewhere.
pub(crate) fn recursion_limit_exceeded(
    recursion_depth: usize,
    limit: usize,
    warned: &Once,
    message: impl FnOnce() -> String,
) -> bool {
    if recursion_depth >= limit {
        warned.call_once(|| log::warn!("{}", message()));
        true
    } else {
        false
    }
}
