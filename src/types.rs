#[cfg(windows)]
use std::ptr::write_volatile;

// This may be marked unused, but will make the compiler give you crucial error messages
use libafl::{
    NopInputFilter, StdFuzzer,
    events::SimpleEventManager,
    feedbacks::{
        CombinedFeedback, CrashLogic, DifferentIsNovel, ExitKindFeedback, LogicEagerOr,
        MapFeedback, MapIndexesMetadata, TimeFeedback,
    },
    inputs::NopToTargetBytes,
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
    NopToTargetBytes,
    NopInputFilter,
    ExitKindFeedback<CrashLogic>,
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
