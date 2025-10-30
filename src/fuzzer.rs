#[cfg(windows)]
use std::ptr::write_volatile;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
#[allow(unused_imports)]
use libafl::Fuzzer; // This may be marked unused, but will make the compiler give you crucial error messages
use libafl::{
    corpus::minimizer::MapCorpusMinimizer,
    events::{Event, EventFirer, EventWithStats, ExecStats},
    feedback_or,
    feedbacks::{CrashFeedback, TimeFeedback},
    fuzzer::StdFuzzer,
    mutators::HavocScheduledMutator,
    observers::{CanTrack, MultiMapObserver, TimeObserver},
    schedulers::{
        IndexesLenTimeMinimizerScheduler, PowerQueueScheduler, powersched::PowerSchedule,
        testcase_score::LenTimeMulTestcasePenalty,
    },
    stages::{CalibrationStage, StdPowerMutationalStage},
    state::HasExecutions,
};
use libafl_bolts::{current_time, prelude::OwnedMutSlice, tuples::tuple_list};
use log::error;

use crate::{
    configuration::Configuration,
    coverage_clients::{
        CoverageClient,
        endpoint::{EndpointCoverageClient, setup_endpoint_coverage},
        setup_line_coverage, validate_instrumentation,
    },
    executor::SequenceExecutor,
    initial_corpus::minimize_corpus,
    input::OpenApiInput,
    monitors::construct_event_mgr,
    openapi::parse_api_spec,
    openapi_mutator::havoc_mutations_openapi,
    reporting::generate_report_path,
    state::OpenApiFuzzerState,
    types::{CombinedMapObserverType, ObserversTupleType, OpenApiFuzzerStateType, SchedulerType},
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
    let mut state_uninit = OpenApiFuzzerState::new_uninit(initial_corpus, api.clone())?;

    let mutator_openapi = HavocScheduledMutator::new(havoc_mutations_openapi());

    // Event manager
    let mut mgr = construct_event_mgr();

    // Observers & feedback initialization
    let (mut endpoint_coverage_client, endpoint_coverage_observer, endpoint_coverage_feedback) =
        setup_endpoint_coverage(api.clone())?;
    let (mut code_coverage_client, code_coverage_observer, code_coverage_feedback) =
        setup_line_coverage(config, &report_path)?;
    let time_observer = TimeObserver::new("time");
    let time_feedback = TimeFeedback::new(&time_observer);

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
    let minimizer: MapCorpusMinimizer<_, _, _, _, _, _, LenTimeMulTestcasePenalty> =
        MapCorpusMinimizer::new(&combined_map_observer);

    // Initialize state
    let mut objective = CrashFeedback::new();
    let mut collective_feedback = feedback_or!(
        endpoint_coverage_feedback,
        code_coverage_feedback,
        time_feedback, // Time feedback, this one does not need a feedback state
    );
    let mut state = state_uninit.initialize(&mut objective, &mut collective_feedback)?;

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
    minimize_corpus(&mut mgr, minimizer, &mut state, &mut fuzzer, &mut executor)
        .context("Error during corpus minimization")?;

    log::debug!("Start fuzzing loop");
    executor.start_timer();
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

    // Coverage reporting
    executor.generate_coverage_report_if_path(report_path.as_deref());

    Ok(())
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
