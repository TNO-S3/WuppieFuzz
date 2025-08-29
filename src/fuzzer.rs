use core::hash::Hash;
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
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus, minimizer::MapCorpusMinimizer},
    events::{Event, EventFirer, EventWithStats, ExecStats, SimpleEventManager},
    executors::ExitKind,
    feedback_or,
    feedbacks::{
        CrashFeedback, CrashLogic, ExitKindFeedback, MaxMapFeedback, StateInitializer, TimeFeedback,
    },
    fuzzer::StdFuzzer,
    mutators::HavocScheduledMutator,
    observers::{CanTrack, MapObserver, MultiMapObserver, StdMapObserver, TimeObserver},
    schedulers::{
        IndexesLenTimeMinimizerScheduler, PowerQueueScheduler, powersched::PowerSchedule,
        testcase_score::CorpusPowerTestcaseScore,
    },
    stages::{CalibrationStage, StdPowerMutationalStage},
    state::{HasCorpus, HasExecutions},
};
use libafl_bolts::{
    AsIter, Named, current_nanos, current_time, prelude::OwnedMutSlice, rands::StdRand,
    tuples::tuple_list,
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
    types::{
        CombinedFeedbackType, CombinedMapObserverType, EndpointFeedbackType, EndpointObserverType,
        EventManagerType, ExecutorType, FuzzerType, LineCovClientObserverFeedbackType,
        ObserversTupleType, OpenApiFuzzerStateType, SchedulerType,
    },
};

/// Main fuzzer function.
///
/// Sets up the various nuts and bolts required by LibAFL and runs the fuzzer until the configured
/// timeout is reached, or until a (ctrl-c) interrupt is caught.
pub fn fuzz() -> Result<()> {
    // Preparatory stuff
    let config = &Configuration::get().map_err(anyhow::Error::msg)?;
    crate::setup_logging(config);
    let report_path = config.report.then(generate_report_path);
    let api = parse_api_spec(config)?;

    let initial_corpus = crate::initial_corpus::initialize_corpus(
        &api,
        config.initial_corpus.as_deref(),
        &report_path.as_deref(),
    );
    let mut state_uninit = construct_state_uninit(&api, initial_corpus)?;

    let mutator_openapi = HavocScheduledMutator::new(havoc_mutations_openapi());

    // Event manager
    let mut mgr = construct_event_mgr();

    // Observers & feedback initialization
    let (mut endpoint_coverage_client, endpoint_coverage_observer, endpoint_coverage_feedback) =
        setup_endpoint_coverage(api.clone())?;
    let (mut code_coverage_client, code_coverage_observer, code_coverage_feedback) =
        setup_line_coverage(config, &report_path)?;
    let (time_observer, time_feedback) = setup_time_feedback();

    // Stages
    let calibration = CalibrationStage::new(&code_coverage_feedback);
    let power: StdPowerMutationalStage<_, _, OpenApiInput, _, _, _> =
        StdPowerMutationalStage::new(mutator_openapi);
    // The order of the stages matter!
    let mut stages = tuple_list!(calibration, power);

    // Scheduler
    let (scheduler, combined_map_observer) = construct_scheduler(
        config,
        &mut state_uninit,
        &mut endpoint_coverage_client,
        &mut code_coverage_client,
    );

    // Corpus minimizer
    let minimizer: MapCorpusMinimizer<_, _, _, _, _, _, CorpusPowerTestcaseScore> =
        MapCorpusMinimizer::new(&combined_map_observer);

    // Initialize state
    let mut objective = CrashFeedback::new();
    let mut collective_feedback = feedback_or!(
        endpoint_coverage_feedback,
        code_coverage_feedback,
        time_feedback, // Time feedback, this one does not need a feedback state
    );
    let state = init_state(&mut objective, &mut collective_feedback, &mut state_uninit)?;

    // Fuzzer
    let mut fuzzer = StdFuzzer::new(scheduler, collective_feedback, objective);

    // Stop early in case something's wrong with the code instrumentation
    validate_instrumentation(config, &mut code_coverage_client);

    // Create the executor for an in-process function with just one observer
    let collective_observer: ObserversTupleType = tuple_list!(
        code_coverage_observer,
        endpoint_coverage_observer,
        combined_map_observer,
        time_observer
    );
    let mut executor = SequenceExecutor::new(
        collective_observer,
        &api,
        config,
        code_coverage_client,
        endpoint_coverage_client,
    )?;

    // Minimize corpus
    minimize_corpus(&mut mgr, minimizer, state, &mut fuzzer, &mut executor)?;

    log::debug!("Start fuzzing loop");
    loop {
        match fuzzer.fuzz_one(&mut stages, &mut executor, state, &mut mgr) {
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
            state,
            EventWithStats::new(Event::Heartbeat, ExecStats::new(current_time(), executions)),
        ) {
            error!("Err: failed to fire event{e:?}")
        }
    }

    // Coverage reporting
    generate_coverage_reports(report_path, executor);

    Ok(())
}

fn generate_coverage_reports(report_path: Option<PathBuf>, executor: ExecutorType) {
    if let Some(report_path) = report_path {
        executor.generate_coverage_report(&report_path);
    }
}

fn minimize_corpus<'a, C, O, T>(
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
) -> Result<(), anyhow::Error>
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
    let _: () = if let Err(e) = mgr.fire(
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
    ) {
        error!("Err: failed to fire event{e:?}")
    };
    Ok(())
}

fn validate_instrumentation(
    config: &&'static Configuration,
    code_coverage_client: &mut Box<dyn CoverageClient>,
) {
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
}

fn init_state<'a>(
    objective: &mut ExitKindFeedback<CrashLogic>,
    collective_feedback: &mut CombinedFeedbackType<'a>,
    state: &'a mut OpenApiFuzzerStateType,
) -> Result<&'a mut OpenApiFuzzerStateType, anyhow::Error> {
    collective_feedback.init_state(state)?;
    objective.init_state(state)?;
    Ok(state)
}

fn construct_state_uninit(
    api: &OpenAPI,
    initial_corpus: InMemoryOnDiskCorpus<OpenApiInput>,
) -> Result<OpenApiFuzzerStateType, anyhow::Error> {
    Ok(OpenApiFuzzerState::new_uninit(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        initial_corpus,
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        api.clone(),
    )?)
}

fn construct_scheduler<'a>(
    config: &&'static Configuration,
    state: &mut OpenApiFuzzerStateType,
    endpoint_coverage_client: &mut Arc<Mutex<EndpointCoverageClient>>,
    code_coverage_client: &mut Box<dyn CoverageClient>,
) -> (SchedulerType<'a>, CombinedMapObserverType<'a>) {
    let combined_map_observer: CombinedMapObserverType<'_> =
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
    let scheduler = IndexesLenTimeMinimizerScheduler::new(
        &combined_map_observer,
        PowerQueueScheduler::new(
            state,
            &combined_map_observer,
            PowerSchedule::new(config.power_schedule),
        ),
    );
    (scheduler, combined_map_observer)
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

fn construct_event_mgr() -> EventManagerType {
    // The Monitor trait define how the fuzzer stats are reported to the user
    let mon = CoverageMonitor::new(Box::new(|s| info!("{s}")) as Box<dyn FnMut(String)>);

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    SimpleEventManager::new(mon)
}

/// Sets up the endpoint coverage client according to the configuration, and initializes it
/// and constructs a LibAFL observer and feedback
#[allow(clippy::type_complexity)]
fn setup_endpoint_coverage<'a>(
    api: OpenAPI,
) -> core::result::Result<
    (
        Arc<Mutex<EndpointCoverageClient>>,
        EndpointObserverType<'a>,
        EndpointFeedbackType<'a>,
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
        EndpointObserverType,
        StdMapObserver<'_, u8, false>,
    > = MaxMapFeedback::new(&endpoint_coverage_observer);
    Ok((
        endpoint_coverage_client,
        endpoint_coverage_observer,
        endpoint_coverage_feedback,
    ))
}

fn setup_time_feedback() -> (TimeObserver, TimeFeedback) {
    let observer = TimeObserver::new("time");
    let feedback = TimeFeedback::new(&observer);
    (observer, feedback)
}

/// Sets up the line coverage client according to the configuration, and initializes it
/// and constructs a LibAFL observer and feedback
fn setup_line_coverage<'a>(
    config: &'static Configuration,
    report_path: &Option<PathBuf>,
) -> Result<LineCovClientObserverFeedbackType<'a>, anyhow::Error> {
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
