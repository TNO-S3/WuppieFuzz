#[cfg(windows)]
use std::ptr::write_volatile;

// This may be marked unused, but will make the compiler give you crucial error messages
use libafl::{
    NopInputFilter, StdFuzzer,
    events::SimpleEventManager,
    feedbacks::{
        CombinedFeedback, CrashLogic, DifferentIsNovel, ExitKindFeedback, LogicEagerOr,
        MapFeedback, MapIndexesMetadata, TimeFeedback, TimeoutLogic,
    },
    inputs::BytesInputConverter,
    observers::{ExplicitTracking, MultiMapObserver, TimeObserver},
    schedulers::{LenTimeMulTestcasePenalty, MinimizerScheduler, PowerQueueScheduler},
};
use libafl_bolts::simd::MaxReducer;

use crate::{
    executor::SequenceExecutor, input::OpenApiInput, monitors::CoverageMonitor,
    state::OpenApiFuzzerState,
};

pub type FuzzerType<'a> = StdFuzzer<
    SchedulerType<'a>,
    CombinedFeedbackType<'a>,
    BytesInputConverter,
    NopInputFilter,
    CombinedObjectiveType,
>;

pub type ExecutorType<'a> = SequenceExecutor<ObserversTupleType<'a>>;

pub type EventManagerType = SimpleEventManager<
    OpenApiInput,
    CoverageMonitor<Box<dyn FnMut(String)>>,
    OpenApiFuzzerState<OpenApiInput>,
>;

pub type ObserversTupleType<'a> = (CombinedMapObserverType<'a>, (TimeObserver, ()));

pub type CombinedFeedbackType<'a> =
    CombinedFeedback<CoverageFeedbackType<'a>, TimeFeedback, LogicEagerOr>;

/// The objective feedback: an input is a "solution" (saved to the `solutions`
/// corpus) if the target either crashed or timed out. Timeouts are included
/// because time-based blind injection payloads (e.g. SQL `SLEEP`/`WAITFOR
/// DELAY`) don't produce a distinctive status code or crash; their only
/// observable effect is that the request runs past the configured timeout.
pub type CombinedObjectiveType =
    CombinedFeedback<ExitKindFeedback<CrashLogic>, ExitKindFeedback<TimeoutLogic>, LogicEagerOr>;

pub type OpenApiFuzzerStateType = OpenApiFuzzerState<OpenApiInput>;

pub type CombinedMapObserverType<'a> =
    ExplicitTracking<MultiMapObserver<'a, u8, false>, true, false>;

pub type SchedulerType<'a> = MinimizerScheduler<
    PowerQueueScheduler<CombinedMapObserverType<'a>, MultiMapObserver<'a, u8, false>>,
    LenTimeMulTestcasePenalty,
    OpenApiInput,
    MapIndexesMetadata,
    CombinedMapObserverType<'a>,
>;

pub type CoverageFeedbackType<'a> = MapFeedback<
    ExplicitTracking<MultiMapObserver<'a, u8, false>, true, false>,
    DifferentIsNovel,
    MultiMapObserver<'a, u8, false>,
    MaxReducer,
>;
