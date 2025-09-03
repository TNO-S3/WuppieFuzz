#[cfg(windows)]
use std::ptr::write_volatile;

// This may be marked unused, but will make the compiler give you crucial error messages
use libafl::{
    NopInputFilter, StdFuzzer,
    events::SimpleEventManager,
    feedbacks::{
        CombinedFeedback, CrashLogic, ExitKindFeedback, LogicEagerOr, MapIndexesMetadata,
        MaxMapFeedback, TimeFeedback,
    },
    inputs::NopToTargetBytes,
    observers::{ExplicitTracking, MultiMapObserver, StdMapObserver, TimeObserver},
    schedulers::{LenTimeMulTestcaseScore, MinimizerScheduler, PowerQueueScheduler},
};

use crate::{
    coverage_clients::CoverageClient, executor::SequenceExecutor, input::OpenApiInput,
    monitors::CoverageMonitor, state::OpenApiFuzzerState,
};

pub type FuzzerType<'a> = StdFuzzer<
    SchedulerType<'a>,
    CombinedFeedbackType<'a>,
    NopToTargetBytes,
    NopInputFilter,
    ExitKindFeedback<CrashLogic>,
>;

pub type ExecutorType<'a> = SequenceExecutor<'a, ObserversTupleType<'a>>;

pub type EventManagerType = SimpleEventManager<
    OpenApiInput,
    CoverageMonitor<Box<dyn FnMut(String)>>,
    OpenApiFuzzerState<OpenApiInput>,
>;

pub type ObserversTupleType<'a> = (
    LineCovObserverType<'a>,
    (
        EndpointObserverType<'a>,
        (CombinedMapObserverType<'a>, (TimeObserver, ())),
    ),
);

pub type CombinedFeedbackType<'a> = CombinedFeedback<
    EndpointFeedbackType<'a>,
    CombinedFeedback<LineCovFeedbackType<'a>, TimeFeedback, LogicEagerOr>,
    LogicEagerOr,
>;

pub type OpenApiFuzzerStateType = OpenApiFuzzerState<OpenApiInput>;

pub type CombinedMapObserverType<'a> =
    ExplicitTracking<MultiMapObserver<'a, u8, false>, true, false>;

pub type SchedulerType<'a> = MinimizerScheduler<
    PowerQueueScheduler<CombinedMapObserverType<'a>, MultiMapObserver<'a, u8, false>>,
    LenTimeMulTestcaseScore,
    OpenApiInput,
    MapIndexesMetadata,
    CombinedMapObserverType<'a>,
>;

pub type LineCovObserverType<'a> = ExplicitTracking<StdMapObserver<'a, u8, false>, true, true>;

pub type LineCovFeedbackType<'a> =
    MaxMapFeedback<LineCovObserverType<'a>, StdMapObserver<'a, u8, false>>;

pub type LineCovClientObserverFeedbackType<'a> = (
    Box<dyn CoverageClient>,
    LineCovObserverType<'a>,
    LineCovFeedbackType<'a>,
);

pub type EndpointObserverType<'a> = ExplicitTracking<StdMapObserver<'a, u8, false>, false, true>;

pub type EndpointFeedbackType<'a> =
    MaxMapFeedback<EndpointObserverType<'a>, StdMapObserver<'a, u8, false>>;
