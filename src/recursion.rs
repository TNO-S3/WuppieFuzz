//! Shared helper for guarding against unbounded schema recursion.
//!
//! OpenAPI schemas can be (mutually) self-referential, e.g. `User` having a
//! field of type `UserIdentity`, which in turn has a field of type `User`.
//! Both example generation ([`crate::openapi::examples`]) and the link
//! mutator's field discovery ([`crate::parameter_access`]) walk schemas
//! recursively and need a depth limit as a backstop against such cycles (and
//! against long chains of distinct, non-repeating `$ref`s, which a cycle
//! check alone does not bound).
//!
//! This limit can be hit many times in a single run (once per affected
//! schema occurrence, possibly every fuzzing iteration), so the resulting
//! warning is only ever logged once per process to avoid flooding the
//! terminal.

use std::sync::Once;

/// Returns `true` once `recursion_depth` reaches `limit`. The first time
/// this happens for the given `warned` guard, `message` is called to build
/// and log a warning; later calls (even for a different `recursion_depth` or
/// schema) are silently suppressed.
///
/// Callers should declare one `static WARNED: Once` per call site (i.e. per
/// kind of recursion being guarded), so that hitting the limit in example
/// generation doesn't suppress a later, independent warning in parameter
/// access resolution, or vice versa.
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
