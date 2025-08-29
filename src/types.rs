#[cfg(windows)]
use std::ptr::write_volatile;

#[allow(unused_imports)]
use libafl::Fuzzer; // This may be marked unused, but will make the compiler give you crucial error messages
use libafl::{
    NopInputFilter, StdFuzzer,
    corpus::{InMemoryOnDiskCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    feedbacks::{
        CombinedFeedback, CrashLogic, ExitKindFeedback, LogicEagerOr, MaxMapFeedback, TimeFeedback,
    },
    inputs::NopToTargetBytes,
    observers::{ExplicitTracking, MultiMapObserver, StdMapObserver, TimeObserver},
    schedulers::PowerQueueScheduler,
    stages::CalibrationStage,
};

use crate::{
    coverage_clients::CoverageClient, executor::SequenceExecutor, input::OpenApiInput,
    monitors::CoverageMonitor, state::OpenApiFuzzerState,
};

pub type CalibrationStageType<'a> = CalibrationStage<
    LineCovObserverType<'a>,
    OpenApiInput,
    StdMapObserver<'a, u8, false>,
    ObserversTupleType<'a>,
    OpenApiFuzzerStateType,
>;

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
    OpenApiFuzzerState<
        OpenApiInput,
        InMemoryOnDiskCorpus<OpenApiInput>,
        libafl_bolts::prelude::RomuDuoJrRand,
        OnDiskCorpus<OpenApiInput>,
    >,
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

pub type OpenApiFuzzerStateType = OpenApiFuzzerState<
    OpenApiInput,
    libafl::corpus::InMemoryOnDiskCorpus<OpenApiInput>,
    libafl_bolts::prelude::RomuDuoJrRand,
    OnDiskCorpus<OpenApiInput>,
>;

pub type CombinedMapObserverType<'a> =
    ExplicitTracking<MultiMapObserver<'a, u8, false>, true, false>;

pub type SchedulerType<'a> = libafl::schedulers::MinimizerScheduler<
    PowerQueueScheduler<CombinedMapObserverType<'a>, MultiMapObserver<'a, u8, false>>,
    libafl::schedulers::LenTimeMulTestcaseScore,
    OpenApiInput,
    libafl::feedbacks::MapIndexesMetadata,
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
