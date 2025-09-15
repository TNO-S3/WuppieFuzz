//! Functionality for corpus minimization based on code coverage.

use anyhow::Context;
use libafl::{
    corpus::{Corpus, MapCorpusMinimizer},
    events::{Event, EventFirer, EventWithStats, ExecStats},
    executors::ExitKind,
    observers::MapObserver,
    schedulers::testcase_score::CorpusPowerTestcaseScore,
    state::HasCorpus,
};
use libafl_bolts::{AsIter, Named, current_time};

use crate::{
    initial_corpus::Hash,
    input::OpenApiInput,
    types::{
        CombinedMapObserverType, EventManagerType, ExecutorType, FuzzerType, OpenApiFuzzerStateType,
    },
};

/// Yields a corpus minimizer which uses the given observer to
/// minimize a corpus based on observed code coverage.
pub fn get_minimizer<'a, O, T>(
    combined_map_observer: &CombinedMapObserverType<'a>,
) -> MapCorpusMinimizer<
    CombinedMapObserverType<'a>,
    ExecutorType<'a>,
    OpenApiInput,
    O,
    OpenApiFuzzerStateType,
    T,
    CorpusPowerTestcaseScore,
> {
    MapCorpusMinimizer::new(combined_map_observer)
}

/// Uses the given minimizer to minimize the given state's corpus.
pub fn minimize_corpus<'a, C, O, T>(
    mgr: &mut EventManagerType,
    minimizer: MapCorpusMinimizer<
        C,
        ExecutorType<'a>,
        OpenApiInput,
        O,
        OpenApiFuzzerStateType,
        T,
        CorpusPowerTestcaseScore,
    >,
    state: &mut OpenApiFuzzerStateType,
    fuzzer: &mut FuzzerType<'a>,
    executor: &mut ExecutorType<'a>,
) -> anyhow::Result<()>
where
    C: Named + AsRef<O>,
    for<'b> O: MapObserver<Entry = T> + AsIter<'b, Item = T>,
    T: Copy + Hash + Eq,
{
    log::info!("Start corpus minimization");
    log::info!("Size before {}", state.corpus().count());
    minimizer.minimize(fuzzer, executor, mgr, state)?;
    log::info!("Size after {}", state.corpus().count());
    let corpus_size = state.corpus().count();
    mgr.fire(
        state,
        EventWithStats::new(
            Event::NewTestcase {
                input: OpenApiInput(vec![]),
                observers_buf: None,
                exit_kind: ExitKind::Ok,
                corpus_size,
                client_config: mgr.configuration(),
                forward_id: None,
            },
            ExecStats::new(current_time(), 0),
        ),
    )
    .context("Firing event after corpus minimization")?;
    Ok(())
}
