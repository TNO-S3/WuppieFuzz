//! A no-op version of corpus minimization. Minimization is not supported on all
//! platforms, and this module is loaded for ones where it isn't.

use crate::types::{
    CombinedMapObserverType, EventManagerType, ExecutorType, FuzzerType, OpenApiFuzzerStateType,
};

/// Yields a corpus minimizer which uses the given observer to
/// minimize a corpus based on observed code coverage.
pub fn get_minimizer<'a>(_combined_map_observer: &CombinedMapObserverType<'a>) {
    // No-op version; see `minimizer` module for real implementation
}

/// Uses the given minimizer to minimize the given state's corpus.
/// (No-op version)
pub fn minimize_corpus<'a>(
    _mgr: &mut EventManagerType,
    _minimizer: (),
    _state: &mut OpenApiFuzzerStateType,
    _fuzzer: &mut FuzzerType<'a>,
    _executor: &mut ExecutorType<'a>,
) -> anyhow::Result<()> {
    // No-op version; see `minimizer` module for real implementation
    Ok(())
}
