use anyhow::{Context, Result};

use libafl::corpus::Corpus;
use libafl::events::EventFirer;
use libafl::executors::hooks::inprocess::inprocess_get_event_manager;
use libafl::executors::{Executor, HasObservers};
use libafl::feedbacks::{DifferentIsNovel, Feedback, MapFeedback, MaxReducer, TimeFeedback};
use libafl::inputs::BytesInput;
use libafl::monitors::{AggregatorOps, UserStatsValue};
use libafl::mutators::StdScheduledMutator;
use libafl::observers::{CanTrack, ExplicitTracking, MapObserver, MultiMapObserver, TimeObserver};
use libafl::schedulers::{
    powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, PowerQueueScheduler,
};
use libafl::stages::{CalibrationStage, StdPowerMutationalStage};
use libafl::state::{HasCorpus, HasExecutions, NopState, State};
use libafl::{feedback_or, ExecutionProcessor};
use libafl::{ExecuteInputResult, HasNamedMetadata};

use libafl_bolts::current_time;
use libafl_bolts::prelude::OwnedMutSlice;
use openapiv3::OpenAPI;

use core::marker::PhantomData;
#[allow(unused_imports)]
use libafl::Fuzzer; // This may be marked unused, but will make the compiler give you crucial error messages
use libafl::{
    corpus::OnDiskCorpus,
    events::{Event, SimpleEventManager},
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::StdFuzzer,
    monitors::UserStats,
    observers::StdMapObserver,
};
use libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list};
use std::borrow::Cow;
use std::ops::DerefMut;

use std::fs::create_dir_all;
use std::path::PathBuf;
#[cfg(windows)]
use std::ptr::write_volatile;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use log::{debug, error, info};

use crate::coverage_clients::endpoint::EndpointCoverageClient;
use crate::{
    configuration::{Configuration, CrashCriterion},
    coverage_clients::CoverageClient,
    input::OpenApiInput,
    monitors::CoverageMonitor,
    openapi::{
        build_request::build_request_from_input,
        curl_request::CurlRequest,
        validate_response::{validate_response, Response},
    },
    openapi_mutator::havoc_mutations_openapi,
    parameter_feedback::ParameterFeedback,
    reporting::Reporting,
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

    let api = crate::openapi::get_api_spec(config.openapi_spec.as_ref().unwrap())?;

    // The Monitor trait define how the fuzzer stats are reported to the user
    let mon = CoverageMonitor::new(|s| info!("{}", s));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // Set up endpoint coverage
    let (mut endpoint_coverage, endpoint_observer, endpoint_feedback) =
        setup_endpoint_coverage(*api.clone());

    let (mut coverage_client, coverage_observer, coverage_feedback) =
        setup_line_coverage(config, &report_path)?;

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    let calibration = CalibrationStage::new(&coverage_feedback);

    let mut collective_feedback = feedback_or!(
        endpoint_feedback,
        coverage_feedback, // Time feedback, this one does not need a feedback state
        TimeFeedback::new(&time_observer)
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

    let combined_map_observer =
        combined_observer(&mut endpoint_coverage, coverage_client.as_mut()).track_indices();

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(
        &combined_map_observer,
        PowerQueueScheduler::new(&mut state, &combined_map_observer, PowerSchedule::FAST),
    );

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, collective_feedback, objective);

    let collective_observer = tuple_list!(endpoint_observer, coverage_observer, time_observer);

    let mutator_openapi = StdScheduledMutator::new(havoc_mutations_openapi());

    // The order of the stages matter!
    let power = StdPowerMutationalStage::new(mutator_openapi);
    let mut stages = tuple_list!(calibration, power);

    let (authentication, cookie_store, client) = crate::build_http_client()?;

    let reporter = crate::reporting::sqlite::get_reporter(config)?;

    // Keep track of the number of inputs
    let mut inputs_tested = 0;
    // Logging the number of executed requests
    let mut stats = LoggingStats::new();

    // The closure that we want to fuzz
    let mut harness = |inputs: &OpenApiInput| {
        let mut exit_kind = ExitKind::Ok;
        inputs_tested += 1;

        let mut parameter_feedback = ParameterFeedback::new(inputs.0.len());
        log::debug!("Sending {} requests", inputs.0.len());
        'chain: for (request_index, request) in inputs.0.iter().enumerate() {
            let mut request = request.clone();
            log::trace!("OpenAPI request:\n{:#?}", request);
            if let Err(error) = request.resolve_parameter_references(&parameter_feedback) {
                debug!(
                        "Cannot instantiate request: missing value for backreferenced parameter: {}. Maybe the earlier request crashed?",
                        error
                    );
                break 'chain;
            };
            let request_builder =
                match build_request_from_input(&client, &cookie_store, &api, &request) {
                    None => continue,
                    Some(r) => r.timeout(Duration::from_millis(config.request_timeout)),
                };

            let request_built = match request_builder.build() {
                Ok(request) => request,
                Err(err) => {
                    // We don't expect errors to occur in the reqwest builder. If one occurs,
                    // it's not the target's fault, so we don't set ExitKind::Crash or Timeout.
                    error!("Error building request: {err}");
                    break;
                }
            };

            let curl_request = CurlRequest(&request_built, &authentication);
            let reporter_request_id =
                reporter.report_request(&request, &curl_request, inputs_tested);
            let curl_request = curl_request.to_string();

            match client.execute(request_built) {
                Ok(response) => {
                    stats.performed_requests += 1;
                    let response: Response = response.into();

                    endpoint_coverage.lock().unwrap().cover(
                        request.method,
                        request.path.clone(),
                        response.status(),
                        curl_request,
                        response.text().unwrap_or_else(|_| {
                            String::from("Unable to decode the response to UTF-8")
                        }),
                    );
                    reporter.report_response(&response, reporter_request_id);
                    log::trace!("Got response {}", response.status());

                    if response.status() == 429 {
                        log::warn!("HTTP status 429 'Too Many Requests' encountered!");
                        log::warn!("Rate limiting is likely active on the program under test.");
                        log::warn!("This hinders fuzz testing. Consider disabling it.");
                    }

                    if response.status().is_server_error() {
                        exit_kind = ExitKind::Crash;
                        log::debug!("OpenAPI-input resulted in server error response, ignoring rest of request chain.");
                        break 'chain;
                    } else {
                        if config.crash_criterion == CrashCriterion::AllErrors {
                            if let Err(validation_err) =
                                validate_response(&api, &request, &response)
                            {
                                log::debug!("OpenAPI-input resulted in validation error: {validation_err}, ignoring rest of request chain.");
                                exit_kind = ExitKind::Crash;
                                break 'chain;
                            }
                        }
                        if response.status().is_success() {
                            parameter_feedback.process_response(request_index, response);
                        }
                    }
                }
                Err(e) => {
                    reporter.report_response_error(&e.to_string(), reporter_request_id);
                    error!("{}", e);
                    exit_kind = ExitKind::Timeout;
                    log::debug!(
                        "OpenAPI-request resulted in timeout, ignoring rest of request chain."
                    );
                    break;
                }
            }
            parameter_feedback.process_post_request(request_index, request);
        }
        update_coverage(
            &mut coverage_client,
            &mut endpoint_coverage,
            &reporter,
            &mut stats,
            |s: String| info!("{}", s),
        );

        exit_kind
    };

    // Create the executor for an in-process function with just one observer
    let mut executor = InProcessExecutor::with_timeout(
        &mut harness,
        collective_observer,
        &mut fuzzer,
        &mut state,
        &mut mgr,
        Duration::from_millis(0), // disable the timeout
    )
    .context("Failed to create the Executor")?;

    let manual_interrupt = setup_interrupt()?;

    // Fire an event to print the initial corpus size
    let corpus_size = state.corpus().count();
    let executions = *state.executions();
    if let Err(e) = mgr.fire(
        &mut state,
        Event::NewTestcase {
            input: OpenApiInput(vec![]),
            observers_buf: None,
            exit_kind: ExitKind::Ok,
            corpus_size,
            client_config: mgr.configuration(),
            time: current_time(),
            executions,
            forward_id: None,
        },
    ) {
        error!("Err: failed to fire event{:?}", e)
    }

    // Executed every corpus entry at least once for gathering a proper view on the initial coverage as mutations
    log::debug!("Start initial corpus loop");
    for input_id in initial_corpus_cloned.ids() {
        let input = initial_corpus_cloned
            .cloned_input_for_id(input_id)
            .expect("Failed to load input");
        executor.run_target(&mut fuzzer, &mut state, &mut mgr, &input)?;
        fuzzer.process_execution(
            &mut state,
            &mut mgr,
            &input,
            &ExecuteInputResult::None,
            executor.observers_mut().deref_mut(),
        )?;
    }

    log::debug!("Start fuzzing loop");
    let maybe_timeout_secs = config.timeout.map(|t| Duration::from_secs(t.get()));
    let starting_time = Instant::now();
    // check for timeout if applicable
    while maybe_timeout_secs
        .map(|timeout| Instant::now() - starting_time < timeout)
        .unwrap_or(true)
    {
        fuzzer
            .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
            .context("Error in the fuzzing loop")?;
        // send update of execution data to the monitor
        let executions = *state.executions();
        if let Err(e) = mgr.fire(
            &mut state,
            Event::UpdateExecStats {
                time: current_time(),
                executions,
                phantom: PhantomData,
            },
        ) {
            error!("Err: failed to fire event{:?}", e)
        }
        if manual_interrupt.load(Ordering::Relaxed) {
            if let Err(e) = mgr.fire(&mut state, Event::Stop) {
                error!("Err: failed to fire event{:?}", e);
                break;
            }
        }
    }

    if let Some(report_path) = report_path {
        endpoint_coverage.generate_coverage_report(&report_path);
        coverage_client.generate_coverage_report(&report_path);
    }

    Ok(())
}

/// Sets up the endpoint coverage client according to the configuration, and initializes it
/// and constructs a LibAFL observer and feedback
fn setup_endpoint_coverage<'a, S: State + HasNamedMetadata>(
    api: OpenAPI,
) -> (
    Arc<Mutex<EndpointCoverageClient>>,
    ExplicitTracking<StdMapObserver<'a, u8, false>, false, true>,
    impl Feedback<S>,
) {
    let mut endpoint_coverage = Arc::new(Mutex::new(EndpointCoverageClient::new(&api)));
    endpoint_coverage.fetch_coverage(true);
    // no-op for this particular CoverageClient
    // Safety: libafl wants to read the coverage map directly that we also update in the harness;
    // this is only possible if it does not touch the map while the harness is running. We must
    // assume they have designed their algorithms for this to work correctly.
    let endpoint_observer = unsafe {
        StdMapObserver::from_mut_ptr(
            "endpoint_coverage",
            endpoint_coverage.get_coverage_ptr(),
            endpoint_coverage.get_coverage_len(),
        )
    }
    .track_novelties();
    let endpoint_feedback = MaxMapFeedback::new(&endpoint_observer);
    (endpoint_coverage, endpoint_observer, endpoint_feedback)
}

type LineCovClientObserverFeedback<'a> = (
    Box<dyn CoverageClient>,
    ExplicitTracking<StdMapObserver<'a, u8, false>, true, true>,
    MapFeedback<
        ExplicitTracking<StdMapObserver<'a, u8, false>, true, true>,
        DifferentIsNovel,
        StdMapObserver<'a, u8, false>,
        MaxReducer,
        u8,
    >,
);

/// Sets up the line coverage client according to the configuration, and initializes it
/// and constructs a LibAFL observer and feedback
fn setup_line_coverage<'a>(
    config: &'static Configuration,
    report_path: &Option<PathBuf>,
) -> Result<LineCovClientObserverFeedback<'a>, anyhow::Error> {
    let mut coverage_client: Box<dyn CoverageClient> =
        crate::coverage_clients::get_coverage_client(config, report_path)?;
    coverage_client.fetch_coverage(true);
    // Safety: libafl wants to read the coverage map directly that we also update in the harness;
    // this is only possible if it does not touch the map while the harness is running. We must
    // assume they have designed their algorithms for this to work correctly.
    let coverage_observer = unsafe {
        StdMapObserver::from_mut_ptr(
            "code_coverage",
            coverage_client.get_coverage_ptr(),
            coverage_client.get_coverage_len(),
        )
    }
    .track_indices()
    .track_novelties();
    let coverage_feedback = MaxMapFeedback::new(&coverage_observer);
    Ok((coverage_client, coverage_observer, coverage_feedback))
}

/// Creates a combined observer from the two coverage streams
fn combined_observer<T: CoverageClient, U: CoverageClient + ?Sized>(
    obs1: &mut T,
    obs2: &mut U,
) -> impl MapObserver {
    // Safety: libafl wants to read the coverage map directly that we also update in the harness;
    // this is only possible if it does not touch the map while the harness is running. We must
    // assume they have designed their algorithms for this to work correctly.
    MultiMapObserver::new("all_maps", unsafe {
        vec![
            OwnedMutSlice::from_raw_parts_mut(obs1.get_coverage_ptr(), obs1.get_coverage_len()),
            OwnedMutSlice::from_raw_parts_mut(obs2.get_coverage_ptr(), obs2.get_coverage_len()),
        ]
    })
}

/// Installs the Ctrl-C interrupt handler
fn setup_interrupt() -> Result<Arc<AtomicBool>, anyhow::Error> {
    let manual_interrupt = Arc::new(AtomicBool::new(false));
    {
        let manual_interrupt = Arc::clone(&manual_interrupt);
        ctrlc::set_handler(move || {
            let second_time_pressed = manual_interrupt.swap(true, Ordering::Relaxed);
            if second_time_pressed {
                info!("Ctrl + c pressed, again - exiting forcefully!");
                std::process::exit(0);
            } else {
                info!("Ctrl + c pressed, starting graceful shutdown.");
            }
        })?;
    }
    Ok(manual_interrupt)
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

/// How often to print a new log line
const CLIENT_STATS_TIME_WINDOW_SECS: u64 = 5;

#[derive(Clone, Copy)]
struct LoggingStats {
    performed_requests: u64,
    last_window_time: Instant,
    last_covered: u64,
    last_endpoint_covered: u64,
}

impl LoggingStats {
    fn new() -> Self {
        Self {
            performed_requests: 0,
            last_window_time: Instant::now(),
            last_covered: 0,
            last_endpoint_covered: 0,
        }
    }
}

/// Updates the LibAFL event manager with coverage information fetched from the
/// endpoint coverage monitor and any line coverage client. Also updates the given
/// (MySqLite) reporter
fn update_coverage<F: FnMut(String)>(
    coverage_client: &mut Box<dyn CoverageClient>,
    endpoint_coverage: &mut Arc<Mutex<EndpointCoverageClient>>,
    reporter: &dyn Reporting<i64>,
    stats: &mut LoggingStats,
    _print_fn: F,
) {
    coverage_client.fetch_coverage(true);
    let (covered, total) = coverage_client.max_coverage_ratio();
    endpoint_coverage.fetch_coverage(true);
    let (e_covered, e_total) = endpoint_coverage.max_coverage_ratio();

    // This input is needed for event_manager.fire, but it doesn't seem to make
    // a difference whether it is meaningful or not, and cloning the entire thing
    // in the harness (because it's immutable there and we need it to be mutable)
    // seems wasteful.
    let mut state = NopState::new();

    // Add own user stats
    let cov_stats = UserStatsValue::Ratio(covered, total);
    let end_cov_stats = UserStatsValue::Ratio(e_covered, e_total);

    let req_stats = UserStatsValue::Number(stats.performed_requests);

    let event_manager = inprocess_get_event_manager::<
        SimpleEventManager<CoverageMonitor<F>, NopState<BytesInput>>,
    >()
    .expect("Can not load the event manager");

    if covered != stats.last_covered {
        stats.last_covered = covered;
        // send the coverage stats to the event manager for use in the monitor
        if let Err(e) = event_manager.fire(
            &mut state,
            Event::UpdateUserStats {
                name: Cow::Borrowed("wuppiefuzz_code_coverage"),
                value: UserStats::new(cov_stats, AggregatorOps::None),
                phantom: PhantomData,
            },
        ) {
            error!("Err: failed to fire event{:?}", e)
        }
    }

    if e_covered != stats.last_endpoint_covered {
        stats.last_endpoint_covered = e_covered;
        // send the coverage stats to the event manager for use in the monitor
        if let Err(e) = event_manager.fire(
            &mut state,
            Event::UpdateUserStats {
                name: Cow::Borrowed("wuppiefuzz_endpoint_coverage"),
                value: UserStats::new(end_cov_stats, AggregatorOps::None),
                phantom: PhantomData,
            },
        ) {
            error!("Err: failed to fire event{:?}", e)
        }
    }

    let current_time = Instant::now();
    let diff = current_time
        .duration_since(stats.last_window_time)
        .as_secs();
    if diff > CLIENT_STATS_TIME_WINDOW_SECS {
        stats.last_window_time = current_time;
        // send the request stats to the event manager for use in the monitor
        if let Err(e) = event_manager.fire(
            &mut state,
            Event::UpdateUserStats {
                name: Cow::Borrowed("requests"),
                value: UserStats::new(req_stats, AggregatorOps::None),
                phantom: PhantomData,
            },
        ) {
            error!("Err: failed to fire event{:?}", e)
        }
    }

    reporter.report_coverage(covered, total, e_covered, e_total)
}
