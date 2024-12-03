//! The executor module contains our custom executor, which implements the harness (for sending
//! OpenAPI-based requests to the target) and statistics tracking (mainly coverage).

use std::{
    borrow::Cow,
    marker::PhantomData,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use libafl::{
    events::{Event, EventFirer, EventRestarter},
    prelude::{
        AggregatorOps, Executor, ExitKind, HasObservers, ObserversTuple, UserStats, UserStatsValue,
        UsesObservers,
    },
    state::{HasExecutions, UsesState},
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
pub struct SequenceExecutor<'h, OT>
where
    OT: ObserversTuple<FuzzerState>,
{
    observers: OT,

    api: &'h OpenAPI,
    config: &'h Configuration,
    authentication: Authentication,
    cookie_store: Arc<CookieStoreMutex>,

    http_client: Client,

    coverage_client: Box<dyn CoverageClient>,
    endpoint_client: Arc<Mutex<EndpointCoverageClient>>,
    reporter: &'h Option<MySqLite>,

    // Logging stats
    inputs_tested: usize,
    performed_requests: u64,
    last_window_time: Instant,
    last_covered: u64,
    last_endpoint_covered: u64,
}

impl<'h, EM, Z, OT> Executor<EM, Z> for SequenceExecutor<'h, OT>
where
    Z: UsesState<State = FuzzerState>,
    EM: UsesState<State = FuzzerState> + EventFirer<State = FuzzerState> + EventRestarter,
    OT: ObserversTuple<FuzzerState>,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut Self::State,
        event_manager: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, libafl::Error> {
        *state.executions_mut() += 1;

        self.pre_exec(state, input);

        let (ret, performed_requests) = self.harness(input);
        self.performed_requests += performed_requests;

        self.post_exec(state, input, event_manager);
        ret
    }
}

impl<'h, OT> SequenceExecutor<'h, OT>
where
    OT: ObserversTuple<FuzzerState>,
{
    /// Create a new SequenceExecutor.
    pub fn new(
        observers: OT,
        api: &'h OpenAPI,
        config: &'h Configuration,
        coverage_client: Box<dyn CoverageClient>,
        endpoint_client: Arc<Mutex<EndpointCoverageClient>>,
        reporter: &'h Option<MySqLite>,
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
            reporter,

            inputs_tested: 0,
            performed_requests: 0,
            last_window_time: Instant::now(),
            last_covered: 0,
            last_endpoint_covered: 0,
        })
    }
    fn pre_exec(&mut self, _state: &mut FuzzerState, _input: &OpenApiInput) {}

    fn harness(&mut self, inputs: &OpenApiInput) -> (Result<ExitKind, libafl::Error>, u64) {
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
                Err(e) => {
                    self.reporter
                        .report_response_error(&e.to_string(), reporter_request_id);
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

        (Ok(exit_kind), performed_requests)
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
        let cov_stats = UserStatsValue::Ratio(covered, total);
        let end_cov_stats = UserStatsValue::Ratio(e_covered, e_total);

        let req_stats = UserStatsValue::Number(self.performed_requests);

        if covered != self.last_covered {
            self.last_covered = covered;
            // send the coverage stats to the event manager for use in the monitor
            if let Err(e) = event_manager.fire(
                state,
                Event::UpdateUserStats {
                    name: Cow::Borrowed("wuppiefuzz_code_coverage"),
                    value: UserStats::new(cov_stats, AggregatorOps::None),
                    phantom: PhantomData,
                },
            ) {
                error!("Err: failed to fire event{:?}", e)
            }
        }

        if e_covered != self.last_endpoint_covered {
            self.last_endpoint_covered = e_covered;
            // send the coverage stats to the event manager for use in the monitor
            if let Err(e) = event_manager.fire(
                state,
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
        let diff = current_time.duration_since(self.last_window_time).as_secs();
        if diff > CLIENT_STATS_TIME_WINDOW_SECS {
            self.last_window_time = current_time;
            // send the request stats to the event manager for use in the monitor
            if let Err(e) = event_manager.fire(
                state,
                Event::UpdateUserStats {
                    name: Cow::Borrowed("requests"),
                    value: UserStats::new(req_stats, AggregatorOps::None),
                    phantom: PhantomData,
                },
            ) {
                error!("Err: failed to fire event{:?}", e)
            }
        }

        self.reporter
            .report_coverage(covered, total, e_covered, e_total)
    }

    /// Uses the embedded coverage clients to generate a coverage report
    pub fn generate_coverage_report(&self, report_path: &std::path::Path) {
        self.endpoint_client.generate_coverage_report(report_path);
        self.coverage_client.generate_coverage_report(report_path);
    }
}

impl<'h, OT> UsesState for SequenceExecutor<'h, OT>
where
    OT: ObserversTuple<FuzzerState>,
{
    type State = FuzzerState;
}

impl<'h, OT> UsesObservers for SequenceExecutor<'h, OT>
where
    OT: ObserversTuple<FuzzerState>,
{
    type Observers = OT;
}

impl<'h, OT> HasObservers for SequenceExecutor<'h, OT>
where
    OT: ObserversTuple<FuzzerState>,
{
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}
