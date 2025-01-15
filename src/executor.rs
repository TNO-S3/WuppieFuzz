//! The executor module contains our custom executor, which implements the harness (for sending
//! OpenAPI-based requests to the target) and statistics tracking (mainly coverage).

use std::{
    borrow::Cow,
    marker::PhantomData,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use libafl::{
    events::{Event, EventFirer, EventProcessor, EventRestarter},
    executors::{Executor, ExitKind, HasObservers},
    monitors::{AggregatorOps, UserStats, UserStatsValue},
    observers::ObserversTuple,
    state::{HasExecutions, Stoppable, UsesState},
    Error,
};
use libafl_bolts::prelude::RefIndexable;
use log::{debug, error};
use openapiv3::OpenAPI;
use reqwest::blocking::Client;
use reqwest_cookie_store::CookieStoreMutex;

use crate::{
    authentication::Authentication,
    configuration::{Configuration, CrashCriterion},
    coverage_clients::{endpoint::EndpointCoverageClient, CoverageClient},
    input::OpenApiInput,
    openapi::{
        build_request::build_request_from_input,
        curl_request::CurlRequest,
        validate_response::{validate_response, Response},
    },
    parameter_feedback::ParameterFeedback,
    reporting::{sqlite::MySqLite, Reporting},
};

/// How often to print a new log line
const CLIENT_STATS_TIME_WINDOW_SECS: u64 = 5;

type FuzzerState = crate::state::OpenApiFuzzerState<
    OpenApiInput,
    libafl::corpus::InMemoryOnDiskCorpus<OpenApiInput>,
    libafl_bolts::rands::RomuDuoJrRand,
    libafl::corpus::OnDiskCorpus<OpenApiInput>,
>;

/// The Executor for sending Sequences of OpenAPI requests to the target.
/// It is responsible for executing inputs chosen by the fuzzer, and tracking
/// statistics about coverage and errors.
pub struct SequenceExecutor<'h, OT>
where
    OT: ObserversTuple<OpenApiInput, FuzzerState>,
{
    observers: OT,

    api: &'h OpenAPI,
    config: &'h Configuration,
    authentication: Authentication,
    cookie_store: Arc<CookieStoreMutex>,

    http_client: Client,

    coverage_client: Box<dyn CoverageClient>,
    endpoint_client: Arc<Mutex<EndpointCoverageClient>>,
    reporter: Option<MySqLite>,

    manual_interrupt: Arc<AtomicBool>,
    maybe_timeout_secs: Option<Duration>,
    starting_time: Instant,

    // Logging stats
    inputs_tested: usize,
    performed_requests: u64,
    last_window_time: Instant,
    last_covered: u64,
    last_endpoint_covered: u64,
}

impl<'h, OT> SequenceExecutor<'h, OT>
where
    OT: ObserversTuple<OpenApiInput, FuzzerState>,
{
    /// Create a new SequenceExecutor.
    pub fn new(
        observers: OT,
        api: &'h OpenAPI,
        config: &'h Configuration,
        coverage_client: Box<dyn CoverageClient>,
        endpoint_client: Arc<Mutex<EndpointCoverageClient>>,
    ) -> anyhow::Result<Self> {
        let (authentication, cookie_store, http_client) = crate::build_http_client()?;

        Ok(Self {
            observers,

            api,
            config,

            http_client,
            authentication,
            cookie_store,

            coverage_client,
            endpoint_client,
            reporter: crate::reporting::sqlite::get_reporter(config)?,

            manual_interrupt: setup_interrupt()?,
            maybe_timeout_secs: config.timeout.map(|t| Duration::from_secs(t.get())),
            starting_time: Instant::now(),

            inputs_tested: 0,
            performed_requests: 0,
            last_window_time: Instant::now(),
            last_covered: 0,
            last_endpoint_covered: 0,
        })
    }

    /// Executes the given input, tracking and using response parameters and verifying responses.
    /// Returns the target's performance as ExitKind, and the number of requests successfully
    /// executed (i.e. before an error occurred).
    fn harness(&mut self, inputs: &OpenApiInput) -> (ExitKind, u64) {
        let mut exit_kind = ExitKind::Ok;
        self.inputs_tested += 1;
        let mut performed_requests = 0;

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
            let request_builder = match build_request_from_input(
                &self.http_client,
                &self.cookie_store,
                self.api,
                &request,
            ) {
                None => continue,
                Some(r) => r.timeout(Duration::from_millis(self.config.request_timeout)),
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

            let curl_request = CurlRequest(&request_built, &self.authentication);
            let reporter_request_id =
                self.reporter
                    .report_request(&request, &curl_request, self.inputs_tested);
            let curl_request = curl_request.to_string();

            match self.http_client.execute(request_built) {
                Ok(response) => {
                    performed_requests += 1;
                    let response: Response = response.into();

                    self.endpoint_client.lock().unwrap().cover(
                        request.method,
                        request.path.clone(),
                        response.status(),
                        curl_request,
                        response.text().unwrap_or_else(|_| {
                            String::from("Unable to decode the response to UTF-8")
                        }),
                    );
                    self.reporter
                        .report_response(&response, reporter_request_id);
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
                        if self.config.crash_criterion == CrashCriterion::AllErrors {
                            if let Err(validation_err) =
                                validate_response(self.api, &request, &response)
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
                Err(transport_error) => {
                    self.reporter
                        .report_response_error(&transport_error.to_string(), reporter_request_id);
                    error!("{}", transport_error);
                    exit_kind = ExitKind::Timeout;
                    break;
                }
            }
            parameter_feedback.process_post_request(request_index, request);
        }

        (exit_kind, performed_requests)
    }

    fn pre_exec<EM, FZ>(
        &mut self,
        state: &mut FuzzerState,
        _input: &OpenApiInput,
        event_manager: &mut EM,
    ) -> Result<(), Error>
    where
        EM: UsesState<State = FuzzerState>
            + EventFirer<State = FuzzerState>
            + EventProcessor<EM, FZ>,
    {
        if state.stop_requested() {
            state.discard_stop_request();
            event_manager.on_shutdown()?;
            return Err(Error::shutting_down());
        }
        Ok(())
    }

    fn post_exec<EM>(
        &mut self,
        state: &mut FuzzerState,
        _input: &OpenApiInput,
        event_manager: &mut EM,
    ) where
        EM: UsesState<State = FuzzerState> + EventFirer<State = FuzzerState> + EventRestarter,
    {
        self.coverage_client.fetch_coverage(true);
        let (covered, total) = self.coverage_client.max_coverage_ratio();
        self.endpoint_client.fetch_coverage(true);
        let (e_covered, e_total) = self.endpoint_client.max_coverage_ratio();

        // Add own user stats
        if covered != self.last_covered {
            self.last_covered = covered;
            // send the coverage stats to the event manager for use in the monitor
            update_stats(
                state,
                event_manager,
                "wuppiefuzz_code_coverage",
                UserStatsValue::Ratio(covered, total),
            );
        }

        if e_covered != self.last_endpoint_covered {
            self.last_endpoint_covered = e_covered;
            // send the coverage stats to the event manager for use in the monitor
            update_stats(
                state,
                event_manager,
                "wuppiefuzz_endpoint_coverage",
                UserStatsValue::Ratio(e_covered, e_total),
            );
        }

        let current_time = Instant::now();
        let diff = current_time.duration_since(self.last_window_time).as_secs();
        if diff > CLIENT_STATS_TIME_WINDOW_SECS {
            self.last_window_time = current_time;
            // send the request stats to the event manager for use in the monitor
            update_stats(
                state,
                event_manager,
                "requests",
                UserStatsValue::Number(self.performed_requests),
            );
        }

        self.reporter
            .report_coverage(covered, total, e_covered, e_total);

        // If we interrupt using ctrl+c or the timeout is over, request stop!
        if self.manual_interrupt.load(Ordering::Relaxed)
            | self
                .maybe_timeout_secs
                .map(|timeout| Instant::now() - self.starting_time > timeout)
                .unwrap_or(false)
        {
            if let Err(e) = event_manager.fire(state, Event::Stop) {
                error!("Err: failed to fire event{:?}", e);
            }
            state.request_stop();
        }
    }

    /// Uses the embedded coverage clients to generate a coverage report
    pub fn generate_coverage_report(&self, report_path: &std::path::Path) {
        self.endpoint_client.generate_coverage_report(report_path);
        self.coverage_client.generate_coverage_report(report_path);
    }
}

impl<EM, FZ, OT> Executor<EM, FZ> for SequenceExecutor<'_, OT>
where
    FZ: UsesState<State = FuzzerState>,
    EM: UsesState<State = FuzzerState>
        + EventFirer<State = FuzzerState>
        + EventRestarter
        + EventProcessor<EM, FZ>,
    OT: ObserversTuple<OpenApiInput, FuzzerState>,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut FZ,
        state: &mut <Self as UsesState>::State,
        event_manager: &mut EM,
        input: &<Self as libafl::inputs::UsesInput>::Input,
    ) -> Result<ExitKind, libafl::Error> {
        *state.executions_mut() += 1;

        if let Err(Error::ShuttingDown) = self.pre_exec(state, input, event_manager) {
            return Err(Error::ShuttingDown);
        }

        let (ret, performed_requests) = self.harness(input);
        self.performed_requests += performed_requests;

        self.post_exec(state, input, event_manager);
        Ok(ret)
    }
}

/// Installs the Ctrl-C interrupt handler
fn setup_interrupt() -> Result<Arc<AtomicBool>, anyhow::Error> {
    let manual_interrupt = Arc::new(AtomicBool::new(false));
    {
        let manual_interrupt = Arc::clone(&manual_interrupt);
        ctrlc::set_handler(move || {
            let second_time_pressed = manual_interrupt.swap(true, Ordering::Relaxed);
            if second_time_pressed {
                log::info!("[User input] Ctrl + c pressed, again - exiting forcefully!");
                std::process::exit(0);
            } else {
                log::info!("[User input] Ctrl + c pressed, starting graceful shutdown.");
            }
        })?;
    }
    Ok(manual_interrupt)
}

/// Uses the given event manager to log an event with the given name and value
fn update_stats<EM>(
    state: &mut FuzzerState,
    event_manager: &mut EM,
    name: &'static str,
    value: UserStatsValue,
) where
    EM: UsesState<State = FuzzerState> + EventFirer<State = FuzzerState> + EventRestarter,
{
    if let Err(e) = event_manager.fire(
        state,
        Event::UpdateUserStats {
            name: Cow::Borrowed(name),
            value: UserStats::new(value, AggregatorOps::None),
            phantom: PhantomData,
        },
    ) {
        error!("Err: failed to fire event {name}: {:?}", e)
    }
}

impl<OT> UsesState for SequenceExecutor<'_, OT>
where
    OT: ObserversTuple<OpenApiInput, FuzzerState>,
{
    type State = FuzzerState;
}

impl<OT> HasObservers for SequenceExecutor<'_, OT>
where
    OT: ObserversTuple<OpenApiInput, FuzzerState>,
{
    type Observers = OT;

    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}
