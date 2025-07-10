#[cfg(windows)]
use std::ptr::write_volatile;
use std::{
    fs::create_dir_all,
    ops::DerefMut,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use indexmap::IndexMap;
#[allow(unused_imports)]
use libafl::Fuzzer; // This may be marked unused, but will make the compiler give you crucial error messages
use libafl::{
    ExecuteInputResult, ExecutionProcessor, HasNamedMetadata,
    corpus::{Corpus, OnDiskCorpus},
    events::{Event, EventFirer, EventWithStats, ExecStats, SimpleEventManager},
    executors::{Executor, ExitKind, HasObservers},
    feedback_or,
    feedbacks::{CrashFeedback, Feedback, MaxMapFeedback, TimeFeedback},
    fuzzer::StdFuzzer,
    mutators::HavocScheduledMutator,
    observers::{CanTrack, ExplicitTracking, MultiMapObserver, StdMapObserver, TimeObserver},
    schedulers::{
        IndexesLenTimeMinimizerScheduler, PowerQueueScheduler, powersched::PowerSchedule,
    },
    stages::{CalibrationStage, StdPowerMutationalStage},
    state::{HasCorpus, HasExecutions},
};
use libafl_bolts::{
    current_nanos, current_time,
    prelude::OwnedMutSlice,
    rands::StdRand,
    tuples::{MatchName, tuple_list},
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

    // Override the `servers` field in the OpenAPI specification if a server override
    // was specified on the CLI.
    let mut api = crate::openapi::get_api_spec(config.openapi_spec.as_ref().unwrap())?;
    if let Some(server_override) = &config.target {
        api.servers = vec![Server {
            url: server_override.to_string(),
            description: None,
            variables: None,
            extensions: IndexMap::new(),
        }];
    }

    // The Monitor trait define how the fuzzer stats are reported to the user
    let mon = CoverageMonitor::new(|s| info!("{s}"));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // Set up endpoint coverage
    let (mut endpoint_coverage_client, endpoint_coverage_observer, endpoint_coverage_feedback) =
        setup_endpoint_coverage(*api.clone())?;

    let (mut code_coverage_client, code_coverage_observer, code_coverage_feedback) =
        setup_line_coverage(config, &report_path)?;

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    let calibration = CalibrationStage::new(&code_coverage_feedback);

    let mut collective_feedback = feedback_or!(
        endpoint_coverage_feedback,
        code_coverage_feedback,
        TimeFeedback::new(&time_observer), // Time feedback, this one does not need a feedback state
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // Initialize corpus normally.
    let initial_corpus = crate::initial_corpus::initialize_corpus(
        &api,
        config.initial_corpus.as_deref(),
        &report_path.as_deref(),
    );

    // Needed to force load corpus
    let initial_corpus_cloned = initial_corpus.clone();

    // Create a State from scratch
    let mut state = OpenApiFuzzerState::new(
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
        *api.clone(),
    )?;

    // Safety: libafl wants to read the coverage map directly that we also update in the harness;
    // this is only possible if it does not touch the map while the harness is running. We must
    // assume they have designed their algorithms for this to work correctly.
    let combined_map_observer = MultiMapObserver::new("all_maps", unsafe {
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

    // A minimization+queue policy to get testcases from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(
        &combined_map_observer,
        PowerQueueScheduler::new(
            &mut state,
            &combined_map_observer,
            PowerSchedule::new(config.power_schedule),
        ),
    );

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, collective_feedback, objective);

    let collective_observer = tuple_list!(
        code_coverage_observer,
        endpoint_coverage_observer,
        combined_map_observer,
        time_observer
    );

    let mutator_openapi = HavocScheduledMutator::new(havoc_mutations_openapi());

    // The order of the stages matter!
    let power = StdPowerMutationalStage::new(mutator_openapi);
    let mut stages = tuple_list!(calibration, power);

    // Create the executor for an in-process function with just one observer
    let mut executor = SequenceExecutor::new(
        collective_observer,
        &api,
        config,
        code_coverage_client,
        endpoint_coverage_client.clone(),
    )?;

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

    // Executed every corpus entry at least once for gathering a proper view on the initial coverage as mutations
    log::debug!("Start initial corpus loop");
    for input_id in initial_corpus_cloned.ids() {
        let input = initial_corpus_cloned
            .cloned_input_for_id(input_id)
            .expect("Failed to load input");
        let exit_kind = executor.run_target(&mut fuzzer, &mut state, &mut mgr, &input)?;
        let exec_input_result = ExecuteInputResult::new(true, false);
        fuzzer.process_execution(
            &mut state,
            &mut mgr,
            &input,
            &exec_input_result,
            &exit_kind,
            executor.observers_mut().deref_mut(),
        )?;
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

/// Sets up the endpoint coverage client according to the configuration, and initializes it
/// and constructs a LibAFL observer and feedback
#[allow(clippy::type_complexity)]
fn setup_endpoint_coverage<
    'a,
    S: HasNamedMetadata + HasExecutions,
    EM: EventFirer<I, S>,
    I,
    OT: MatchName,
>(
    api: OpenAPI,
) -> Result<
    (
        Arc<Mutex<EndpointCoverageClient>>,
        ExplicitTracking<StdMapObserver<'a, u8, false>, false, true>,
        impl Feedback<EM, I, OT, S>,
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
        ExplicitTracking<StdMapObserver<'_, u8, false>, false, true>,
        StdMapObserver<'_, u8, false>,
    > = MaxMapFeedback::new(&endpoint_coverage_observer);
    Ok((
        endpoint_coverage_client,
        endpoint_coverage_observer,
        endpoint_coverage_feedback,
    ))
}

type LineCovClientObserverFeedback<'a> = (
    Box<dyn CoverageClient>,
    ExplicitTracking<StdMapObserver<'a, u8, false>, true, true>,
    MaxMapFeedback<
        ExplicitTracking<StdMapObserver<'a, u8, false>, true, true>,
        StdMapObserver<'a, u8, false>,
    >,
);

/// Sets up the line coverage client according to the configuration, and initializes it
/// and constructs a LibAFL observer and feedback
fn setup_line_coverage<'a>(
    config: &'static Configuration,
    report_path: &Option<PathBuf>,
) -> Result<LineCovClientObserverFeedback<'a>, anyhow::Error> {
    let mut code_coverage_client: Box<dyn CoverageClient> =
        crate::coverage_clients::get_coverage_client(config, report_path)?;
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
