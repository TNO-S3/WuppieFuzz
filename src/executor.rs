use std::{
    borrow::{BorrowMut, Cow},
    marker::PhantomData,
    sync::{Arc, Mutex},
    time::Instant,
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
use log::error;

use crate::{
    coverage_clients::{endpoint::EndpointCoverageClient, CoverageClient},
    input::OpenApiInput,
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

pub struct SequenceExecutor<'h, H, OT>
where
    H: FnMut(&OpenApiInput) -> (Result<ExitKind, libafl::Error>, u64) + ?Sized,
    OT: ObserversTuple<FuzzerState>,
{
    harness_fn: &'h mut H,
    observers: OT,
    phantom: PhantomData<H>,

    coverage_client: Box<dyn CoverageClient>,
    endpoint_client: Arc<Mutex<EndpointCoverageClient>>,
    reporter: &'h Option<MySqLite>,

    // Logging stats
    performed_requests: u64,
    last_window_time: Instant,
    last_covered: u64,
    last_endpoint_covered: u64,
}

impl<'h, EM, Z, H, OT> Executor<EM, Z> for SequenceExecutor<'h, H, OT>
where
    H: FnMut(&OpenApiInput) -> (Result<ExitKind, libafl::Error>, u64) + ?Sized,
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

        let (ret, performed_requests) = self.harness_fn.borrow_mut()(input);
        self.performed_requests += performed_requests;

        self.post_exec(state, input, event_manager);
        ret
    }
}

impl<'h, H, OT> SequenceExecutor<'h, H, OT>
where
    H: FnMut(&OpenApiInput) -> (Result<ExitKind, libafl::Error>, u64) + ?Sized,
    OT: ObserversTuple<FuzzerState>,
{
    pub fn new(
        harness_fn: &'h mut H,
        observers: OT,
        coverage_client: Box<dyn CoverageClient>,
        endpoint_client: Arc<Mutex<EndpointCoverageClient>>,
        reporter: &'h Option<MySqLite>,
    ) -> Self {
        Self {
            harness_fn,
            observers,
            phantom: PhantomData,

            coverage_client,
            endpoint_client,
            reporter,

            performed_requests: 0,
            last_window_time: Instant::now(),
            last_covered: 0,
            last_endpoint_covered: 0,
        }
    }
    fn pre_exec(&mut self, state: &mut FuzzerState, input: &OpenApiInput) {}

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

impl<'h, H, OT> UsesState for SequenceExecutor<'h, H, OT>
where
    H: FnMut(&OpenApiInput) -> (Result<ExitKind, libafl::Error>, u64) + ?Sized,
    OT: ObserversTuple<FuzzerState>,
{
    type State = FuzzerState;
}

impl<'h, H, OT> UsesObservers for SequenceExecutor<'h, H, OT>
where
    H: FnMut(&OpenApiInput) -> (Result<ExitKind, libafl::Error>, u64) + ?Sized,
    OT: ObserversTuple<FuzzerState>,
{
    type Observers = OT;
}

impl<'h, H, OT> HasObservers for SequenceExecutor<'h, H, OT>
where
    H: FnMut(&OpenApiInput) -> (Result<ExitKind, libafl::Error>, u64) + ?Sized,
    OT: ObserversTuple<FuzzerState>,
{
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}
