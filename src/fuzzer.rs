use core::fmt::Debug;
#[cfg(windows)]
use std::ptr::write_volatile;
use std::{
    fs::create_dir_all,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use indexmap::IndexMap;
#[allow(unused_imports)]
use libafl::Fuzzer; // This may be marked unused, but will make the compiler give you crucial error messages
use libafl::{
    corpus::{Corpus, OnDiskCorpus, minimizer::MapCorpusMinimizer},
    events::{Event, EventFirer, EventWithStats, ExecStats, SimpleEventManager},
    executors::ExitKind,
    feedback_or,
    feedbacks::{CombinedFeedback, CrashFeedback, LogicEagerOr, MaxMapFeedback, TimeFeedback},
    fuzzer::StdFuzzer,
    mutators::HavocScheduledMutator,
    observers::{CanTrack, ExplicitTracking, MultiMapObserver, StdMapObserver, TimeObserver},
    schedulers::{
        IndexesLenTimeMinimizerScheduler, PowerQueueScheduler, powersched::PowerSchedule,
        testcase_score::CorpusPowerTestcaseScore,
    },
    stages::{CalibrationStage, StdPowerMutationalStage},
    state::{HasCorpus, HasExecutions, Stoppable},
};
use libafl_bolts::{
    current_nanos, current_time, prelude::OwnedMutSlice, rands::StdRand, tuples::tuple_list,
};
use log::{error, info};
use openapiv3::{OpenAPI, Server};

use crate::{
    configuration::Configuration,
    coverage_clients::{CoverageClient, endpoint::EndpointCoverageClient},
    executor::SequenceExecutor,
    input::OpenApiInput,
    monitors::CoverageMonitor,
    openapi_mutator::havoc_mutations_openapi,
    state::OpenApiFuzzerState,
};

/// Main fuzzer function.
///
/// Sets up the various nuts and bolts required by LibAFL and runs the fuzzer until the configured
/// timeout is reached, or until a (ctrl-c) interrupt is caught.
pub fn fuzz() -> Result<()> {
    let config = &Configuration::get().map_err(anyhow::Error::msg)?;
    crate::setup_logging(config);
    let report_path = config.report.then(generate_report_path);
    let api = parse_api_spec(config)?;
    let mut mgr = construct_event_mgr();

    let mutator_openapi = HavocScheduledMutator::new(havoc_mutations_openapi());

    // Initialize corpus normally.
    let initial_corpus = crate::initial_corpus::initialize_corpus(
        &api,
        config.initial_corpus.as_deref(),
        &report_path.as_deref(),
    );

    let (
        mut endpoint_coverage_client,
        mut code_coverage_client,
        objective,
        mut state,
        collective_observer,
        collective_feedback,
        calibration,
    ) = fun_name(config, &report_path, &api, initial_corpus)?;

    let combined_map_observer: CombinedMapObserver<'_> =
        MultiMapObserver::new("all_maps", unsafe {
            vec![
                OwnedMutSlice::from_raw_parts_mut(
                    endpoint_coverage_client.get_coverage_ptr(),
                    endpoint_coverage_client.get_coverage_len(),
                ),
                OwnedMutSlice::from_raw_parts_mut(
                    code_coverage_client.get_coverage_ptr(),
                    code_coverage_client.get_coverage_len(),
                ),
            ]
        })
        .track_indices();

    let scheduler = construct_scheduler(config, &mut state, &combined_map_observer);

    let minimizer: MapCorpusMinimizer<_, _, _, _, _, _, CorpusPowerTestcaseScore> =
        MapCorpusMinimizer::new(&combined_map_observer);

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, collective_feedback, objective);

    // The order of the stages matter!
    let power: StdPowerMutationalStage<_, _, OpenApiInput, _, _, _> =
        StdPowerMutationalStage::new(mutator_openapi);

    let mut stages = tuple_list!(calibration, power);

    // APIs already create code coverage during boot. We check if the code coverage is non-zero. Zero coverage might indicate an issue with the coverage agent or a target that was not rebooted between fuzzing runs.
    if config.coverage_configuration != crate::configuration::CoverageConfiguration::Endpoint {
        log::debug!("Gathering initial code coverage");

        match code_coverage_client.max_coverage_ratio() {
            (0, _) => {
                log::error!(
                    "No initial code coverage detected. \
                This likely indicates an issue with instrumentation. \
                You specified {} as coverage tooling. \
                Please ensure your target was restarted and is properly instrumented.",
                    config.coverage_configuration.type_str()
                );
                std::process::exit(1);
            }
            (hit, total) => {
                log::info!(
                    "Initial code coverage: {hit}/{total} ({}%)",
                    (hit * 100 + total / 2) / total
                );
            }
        }
    }

    // Create the executor for an in-process function with just one observer
    let mut executor = SequenceExecutor::new(
        collective_observer,
        &api,
        config,
        code_coverage_client,
        endpoint_coverage_client,
    )?;

    log::info!("Start corpus minimization");
    log::info!("Size before {}", state.corpus().count());
    minimizer.minimize(&mut fuzzer, &mut executor, &mut mgr, &mut state)?;
    log::info!("Size after {}", state.corpus().count());

    // Fire an event to print the initial corpus size
    let corpus_size = state.corpus().count();
    if let Err(e) = mgr.fire(
        &mut state,
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
    ) {
        error!("Err: failed to fire event{e:?}")
    }

    log::debug!("Start fuzzing loop");
    loop {
        match fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr) {
            Ok(_) => (),
            Err(libafl_bolts::Error::ShuttingDown) => {
                log::info!("[Fuzzing campaign ended] Thanks for using WuppieFuzz!");
                break;
            }
            Err(err) => {
                return Err(err).context("Error in the fuzz loop");
            }
        };
        // send update of execution data to the monitor
        let executions = *state.executions();
        if let Err(e) = mgr.fire(
            &mut state,
            EventWithStats::new(Event::Heartbeat, ExecStats::new(current_time(), executions)),
        ) {
            error!("Err: failed to fire event{e:?}")
        }
    }

    if let Some(report_path) = report_path {
        executor.generate_coverage_report(&report_path);
    }

    Ok(())
}

type ObserversTupleType = (
    LineCovObserver<'static>,
    (
        EndpointObserver<'static>,
        (CombinedMapObserver<'static>, (TimeObserver, ())),
    ),
);

type CombinedFeedbackType<'a> = CombinedFeedback<
    EndpointFeedback<'a>,
    CombinedFeedback<LineCovFeedback<'a>, TimeFeedback, LogicEagerOr>,
    LogicEagerOr,
>;

type OpenApiFuzzerStateType = OpenApiFuzzerState<
    OpenApiInput,
    libafl::corpus::InMemoryOnDiskCorpus<OpenApiInput>,
    libafl_bolts::prelude::RomuDuoJrRand,
    OnDiskCorpus<OpenApiInput>,
>;

type CombinedMapObserver<'a> = ExplicitTracking<MultiMapObserver<'a, u8, false>, true, false>;

type SchedulerType<'a> = libafl::schedulers::MinimizerScheduler<
    PowerQueueScheduler<CombinedMapObserver<'a>, MultiMapObserver<'a, u8, false>>,
    libafl::schedulers::LenTimeMulTestcaseScore,
    OpenApiInput,
    libafl::feedbacks::MapIndexesMetadata,
    CombinedMapObserver<'a>,
>;

fn fun_name(
    config: &&'static Configuration,
    report_path: &Option<PathBuf>,
    api: &OpenAPI,
    initial_corpus: libafl::corpus::InMemoryOnDiskCorpus<OpenApiInput>,
) -> Result<
    (
        Arc<Mutex<EndpointCoverageClient>>,
        Box<dyn CoverageClient>,
        libafl::feedbacks::ExitKindFeedback<libafl::feedbacks::CrashLogic>,
        OpenApiFuzzerStateType,
        ObserversTupleType,
        CombinedFeedbackType<'static>,
        CalibrationStage<
            LineCovObserver<'static>,
            OpenApiInput,
            StdMapObserver<'static, u8, false>,
            ObserversTupleType,
            OpenApiFuzzerStateType,
        >,
    ),
    anyhow::Error,
> {
    let (
        endpoint_coverage_client,
        endpoint_coverage_observer,
        endpoint_coverage_feedback,
        code_coverage_client,
        code_coverage_observer,
        code_coverage_feedback,
        combined_map_observer,
        time_observer,
    ) = construct_observers(config, report_path, api)?;
    let calibration = CalibrationStage::new(&code_coverage_feedback);
    let (collective_feedback, objective, state) = construct_state(
        api,
        initial_corpus,
        endpoint_coverage_feedback,
        code_coverage_feedback,
        &time_observer,
    )?;
    let collective_observer = tuple_list!(
        code_coverage_observer,
        endpoint_coverage_observer,
        combined_map_observer,
        time_observer
    );
    Ok((
        endpoint_coverage_client,
        code_coverage_client,
        objective,
        state,
        collective_observer,
        collective_feedback,
        calibration,
    ))
}

fn construct_observers(
    config: &&'static Configuration,
    report_path: &Option<PathBuf>,
    api: &OpenAPI,
) -> Result<
    (
        Arc<Mutex<EndpointCoverageClient>>,
        EndpointObserver<'static>,
        EndpointFeedback<'static>,
        Box<dyn CoverageClient>,
        LineCovObserver<'static>,
        LineCovFeedback<'static>,
        ExplicitTracking<MultiMapObserver<'static, u8, false>, true, false>,
        TimeObserver,
    ),
    anyhow::Error,
> {
    let (mut endpoint_coverage_client, endpoint_coverage_observer, endpoint_coverage_feedback) =
        setup_endpoint_coverage(api.clone())?;
    let (mut code_coverage_client, code_coverage_observer, code_coverage_feedback) =
        setup_line_coverage(config, report_path)?;
    let combined_map_observer: CombinedMapObserver<'_> =
        MultiMapObserver::new("all_maps", unsafe {
            vec![
                OwnedMutSlice::from_raw_parts_mut(
                    endpoint_coverage_client.get_coverage_ptr(),
                    endpoint_coverage_client.get_coverage_len(),
                ),
                OwnedMutSlice::from_raw_parts_mut(
                    code_coverage_client.get_coverage_ptr(),
                    code_coverage_client.get_coverage_len(),
                ),
            ]
        })
        .track_indices();
    let time_observer = TimeObserver::new("time");
    Ok((
        endpoint_coverage_client,
        endpoint_coverage_observer,
        endpoint_coverage_feedback,
        code_coverage_client,
        code_coverage_observer,
        code_coverage_feedback,
        combined_map_observer,
        time_observer,
    ))
}

fn construct_state(
    api: &OpenAPI,
    initial_corpus: libafl::corpus::InMemoryOnDiskCorpus<OpenApiInput>,
    endpoint_coverage_feedback: EndpointFeedback<'static>,
    code_coverage_feedback: LineCovFeedback<'static>,
    time_observer: &TimeObserver,
) -> Result<
    (
        CombinedFeedbackType<'static>,
        libafl::feedbacks::ExitKindFeedback<libafl::feedbacks::CrashLogic>,
        OpenApiFuzzerStateType,
    ),
    anyhow::Error,
> {
    let mut collective_feedback = feedback_or!(
        endpoint_coverage_feedback,
        code_coverage_feedback,
        TimeFeedback::new(time_observer), // Time feedback, this one does not need a feedback state
    );
    let mut objective = CrashFeedback::new();
    let state: OpenApiFuzzerStateType = OpenApiFuzzerState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        initial_corpus,
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // States of the feedbacks.
        // They are the data related to the feedbacks that you want to persist in the State.
        &mut collective_feedback,
        &mut objective,
        api.clone(),
    )?;
    Ok((collective_feedback, objective, state))
}

fn construct_scheduler(
    config: &&'static Configuration,
    state: &mut OpenApiFuzzerStateType,
    combined_map_observer: &CombinedMapObserver<'static>,
) -> SchedulerType<'static> {
    IndexesLenTimeMinimizerScheduler::new(
        combined_map_observer,
        PowerQueueScheduler::new(
            state,
            combined_map_observer,
            PowerSchedule::new(config.power_schedule),
        ),
    )
}

fn parse_api_spec(config: &&'static Configuration) -> Result<OpenAPI, anyhow::Error> {
    let mut api = crate::openapi::get_api_spec(config.openapi_spec.as_ref().unwrap())?;
    if let Some(server_override) = &config.target {
        api.servers = vec![Server {
            url: server_override.as_str().trim_end_matches('/').to_string(),
            description: None,
            variables: None,
            extensions: IndexMap::new(),
        }];
    }
    Ok(*api)
}

fn construct_event_mgr<I, S>() -> SimpleEventManager<I, CoverageMonitor<impl FnMut(String)>, S>
where
    I: Debug,
    S: Stoppable,
{
    // The Monitor trait define how the fuzzer stats are reported to the user
    let mon = CoverageMonitor::new(Box::new(|s| info!("{s}")) as Box<dyn FnMut(String)>);

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    SimpleEventManager::new(mon)
}

type EndpointObserver<'a> = ExplicitTracking<StdMapObserver<'a, u8, false>, false, true>;

type EndpointFeedback<'a> = MaxMapFeedback<EndpointObserver<'a>, StdMapObserver<'a, u8, false>>;

/// Sets up the endpoint coverage client according to the configuration, and initializes it
/// and constructs a LibAFL observer and feedback
#[allow(clippy::type_complexity)]
fn setup_endpoint_coverage<'a>(
    api: OpenAPI,
) -> core::result::Result<
    (
        Arc<Mutex<EndpointCoverageClient>>,
        EndpointObserver<'a>,
        EndpointFeedback<'a>,
    ),
    anyhow::Error,
> {
    let mut endpoint_coverage_client = Arc::new(Mutex::new(EndpointCoverageClient::new(&api)));
    endpoint_coverage_client.fetch_coverage(true);
    // no-op for this particular CoverageClient
    // Safety: libafl wants to read the coverage map directly that we also update in the harness;
    // this is only possible if it does not touch the map while the harness is running. We must
    // assume they have designed their algorithms for this to work correctly.
    let endpoint_coverage_observer = unsafe {
        StdMapObserver::from_mut_ptr(
            "endpoint_coverage",
            endpoint_coverage_client.get_coverage_ptr(),
            endpoint_coverage_client.get_coverage_len(),
        )
    }
    .track_novelties();
    let endpoint_coverage_feedback: MaxMapFeedback<
        EndpointObserver,
        StdMapObserver<'_, u8, false>,
    > = MaxMapFeedback::new(&endpoint_coverage_observer);
    Ok((
        endpoint_coverage_client,
        endpoint_coverage_observer,
        endpoint_coverage_feedback,
    ))
}

type LineCovObserver<'a> = ExplicitTracking<StdMapObserver<'a, u8, false>, true, true>;

type LineCovFeedback<'a> = MaxMapFeedback<LineCovObserver<'a>, StdMapObserver<'a, u8, false>>;

type LineCovClientObserverFeedback<'a> = (
    Box<dyn CoverageClient>,
    LineCovObserver<'a>,
    LineCovFeedback<'a>,
);

/// Sets up the line coverage client according to the configuration, and initializes it
/// and constructs a LibAFL observer and feedback
fn setup_line_coverage<'a>(
    config: &'static Configuration,
    report_path: &Option<PathBuf>,
) -> Result<LineCovClientObserverFeedback<'a>, anyhow::Error> {
    let mut code_coverage_client: Box<dyn CoverageClient> =
        crate::coverage_clients::get_coverage_client(config, report_path)?;
    // This is very important, we want to fetch and reset the coverage before interacting with the target
    code_coverage_client.fetch_coverage(true);
    // Safety: libafl wants to read the coverage map directly that we also update in the harness;
    // this is only possible if it does not touch the map while the harness is running. We must
    // assume they have designed their algorithms for this to work correctly.
    let code_coverage_observer = unsafe {
        StdMapObserver::from_mut_ptr(
            "code_coverage",
            code_coverage_client.get_coverage_ptr(),
            code_coverage_client.get_coverage_len(),
        )
    }
    .track_indices()
    .track_novelties();
    let code_coverage_feedback = MaxMapFeedback::new(&code_coverage_observer);
    Ok((
        code_coverage_client,
        code_coverage_observer,
        code_coverage_feedback,
    ))
}

/// Creates and returns the report path for this run. It is typically of the form
/// `reports/2023-06-13T105302.602Z`, the filename being an ISO 8601 timestamp.
fn generate_report_path() -> PathBuf {
    let timestamp = format!(
        "{}",
        chrono::offset::Utc::now().format("%Y-%m-%dT%H%M%S%.3fZ")
    );
    let report_path = PathBuf::from("reports").join(timestamp);
    create_dir_all(&report_path).expect("unable to make reports directory");
    report_path
}
