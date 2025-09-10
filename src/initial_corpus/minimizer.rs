#[cfg(enable_minimizer)]
use libafl::observers::MapObserver;
#[cfg(enable_minimizer)]
use libafl::schedulers::testcase_score::CorpusPowerTestcaseScore;
#[cfg(enable_minimizer)]
use libafl_bolts::{AsIter, Named};

use crate::types::{
    CombinedMapObserverType, EventManagerType, ExecutorType, FuzzerType, OpenApiFuzzerStateType,
};
#[cfg(enable_minimizer)]
use crate::{initial_corpus::Hash, input::OpenApiInput};

#[cfg(enable_minimizer)]
pub fn get_minimizer<'a, O, T>(
    combined_map_observer: &CombinedMapObserverType<'a>,
) -> libafl::corpus::MapCorpusMinimizer<
    CombinedMapObserverType<'a>,
    ExecutorType<'a>,
    OpenApiInput,
    O,
    OpenApiFuzzerStateType,
    T,
    CorpusPowerTestcaseScore,
> {
    libafl::corpus::MapCorpusMinimizer::new(combined_map_observer)
}

#[cfg(enable_minimizer)]
pub fn minimize_corpus<'a, C, O, T>(
    mgr: &mut EventManagerType,
    minimizer: libafl::corpus::MapCorpusMinimizer<
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
    use anyhow::Context;
    use libafl::{
        corpus::Corpus,
        events::{Event, EventFirer, EventWithStats, ExecStats},
        executors::ExitKind,
        state::HasCorpus,
    };
    use libafl_bolts::current_time;

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

#[cfg(not(enable_minimizer))]
pub fn get_minimizer<'a>(_combined_map_observer: &CombinedMapObserverType<'a>) {}

#[cfg(not(enable_minimizer))]
pub fn minimize_corpus<'a>(
    _mgr: &mut EventManagerType,
    _minimizer: (),
    _state: &mut OpenApiFuzzerStateType,
    _fuzzer: &mut FuzzerType<'a>,
    _executor: &mut ExecutorType<'a>,
) -> anyhow::Result<()> {
    Ok(())
}
