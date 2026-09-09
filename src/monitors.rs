//! Coverage monitor for Wuppiefuzz. It defines how statistics are printed to the terminal
//! while fuzzing, and tracks the time consumed.

use std::{borrow::Cow, fmt, time::Instant};

use libafl::{
    alloc::fmt::Debug,
    events::SimpleEventManager,
    monitors::{
        Monitor,
        stats::{AggregatorOps, ClientStats, ClientStatsManager, UserStats, UserStatsValue},
    },
};
use libafl_bolts::{ClientId, Error, format_duration};
use serde_json::json;

use crate::{
    configuration::{Configuration, OutputFormat},
    types::EventManagerType,
};

/// Constructs an event manager
pub fn construct_event_mgr() -> EventManagerType {
    // The Monitor trait define how the fuzzer stats are reported to the user
    let mon = CoverageMonitor::new(Box::new(|s| log::info!("{s}")) as Box<dyn FnMut(String)>);

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    SimpleEventManager::new(mon)
}

/// Tracking monitor during fuzzing.
#[derive(Clone)]
pub struct CoverageMonitor<F>
where
    F: FnMut(String),
{
    print_fn: F,
    start_time: Instant,
    client_stats: Vec<ClientStats>,
    observed_crashes: u64,
}

impl<F> Debug for CoverageMonitor<F>
where
    F: FnMut(String),
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SimpleMonitor")
            .field("start_time", &self.start_time)
            .field("client_stats", &self.client_stats)
            .finish()
    }
}

impl<F> Monitor for CoverageMonitor<F>
where
    F: FnMut(String),
{
    fn display(
        &mut self,
        client_stats_mgr: &mut ClientStatsManager,
        event_msg: &str,
        _sender_id: ClientId,
    ) -> Result<(), Error> {
        let config = Configuration::must_get();
        // `Instant` is monotonic, so it won't go backwards relative to `start_time`.
        let total_time = Instant::now().duration_since(self.start_time);

        let global_stats = client_stats_mgr.global_stats();
        let objective_size = global_stats.objective_size;
        let total_execs = global_stats.total_execs;
        let corpus_size = global_stats.corpus_size;

        let client_stats = &client_stats_mgr.client_stats()[&ClientId(0)];
        if event_msg == "Objective" {
            self.observed_crashes += 1;
            return Ok(());
        }
        let observed_crashes = self.observed_crashes;
        let default_sequences = UserStats::new(UserStatsValue::Number(0), AggregatorOps::None);
        let executed_sequences = Self::seq_stats(client_stats, &default_sequences);

        let output_string = match config.output_format {
            OutputFormat::Json => json!({
                "event_msg": event_msg,
                "run_time": format_duration(&total_time),
                "objectives": objective_size,
                "observed_crashes": observed_crashes,
                "executed_sequences": executed_sequences,
                "sequences_per_sec": Self::seq_sec_stats(client_stats, total_time.as_secs().try_into().unwrap()),
                "requests": Self::req_stats(client_stats, &UserStats::new(UserStatsValue::String(Cow::Borrowed("unknown")), AggregatorOps::None)),
                "requests_per_sec": Self::req_sec_stats(client_stats, &UserStats::new(UserStatsValue::Number(0), AggregatorOps::None), total_time.as_secs().try_into().unwrap()),
                "coverage": Self::cov_stats(client_stats, &UserStats::new(UserStatsValue::String(Cow::Borrowed("unknown")), AggregatorOps::None)),
                "endpoint_coverage": Self::end_cov_stats(client_stats, &UserStats::new(UserStatsValue::String(Cow::Borrowed("unknown")), AggregatorOps::None)),
                "current_sequence": Self::current_sequence_stats(client_stats, &UserStats::new(UserStatsValue::String(Cow::Borrowed("unknown")), AggregatorOps::None)),
            })
            .to_string(),
            OutputFormat::HumanReadable => {
            if event_msg == "Testcase" {
                match total_execs {
                    0 => format!(
                            "[{event_msg}] Starting corpus loaded! Initial corpus size: {corpus_size}"
                        ),
                    _ => format!(
                            "[{event_msg}] The testing corpus expanded! After run time: {}, total corpus size: {corpus_size}",
                            format_duration(&total_time),
                        ),
                }
            } else if event_msg == "UserStats" {
                return Ok(())
            } else {
                format!(
                    "[{}] run time: {}, corpus: {}, objectives: {}, observed crashes: {}, executed sequences: {}, seq/sec: {}, requests: {}, req/sec: {}, coverage: {}, endpoint coverage: {}, current sequence: {}",
                    event_msg,
                    format_duration(&total_time),
                    corpus_size,
                    objective_size,
                    observed_crashes,
                    executed_sequences,
                    Self::seq_sec_stats(client_stats, total_time.as_secs().try_into().unwrap()),
                    Self::req_stats(client_stats, &UserStats::new(UserStatsValue::Number(0), AggregatorOps::None)),
                    Self::req_sec_stats(client_stats, &UserStats::new(UserStatsValue::Number(0), AggregatorOps::None), total_time.as_secs().try_into().unwrap()),
                    Self::cov_stats(client_stats, &UserStats::new(UserStatsValue::String(Cow::Borrowed("unknown")), AggregatorOps::None)),
                    Self::end_cov_stats(client_stats, &UserStats::new(UserStatsValue::String(Cow::Borrowed("unknown")), AggregatorOps::None)),
                    Self::current_sequence_stats(client_stats, &UserStats::new(UserStatsValue::String(Cow::Borrowed("unknown")), AggregatorOps::None)),
                )
            }
        }};
        (self.print_fn)(output_string);
        Ok(())
    }
}

impl<F> CoverageMonitor<F>
where
    F: FnMut(String),
{
    /// Creates the monitor, using the `current_time` as `start_time`.
    pub fn new(print_fn: F) -> Self {
        Self {
            print_fn,
            start_time: Instant::now(),
            client_stats: vec![],
            observed_crashes: 0,
        }
    }

    /// Creates the monitor with a given `start_time`.
    pub fn with_time(print_fn: F, start_time: Instant) -> Self {
        Self {
            print_fn,
            start_time,
            client_stats: vec![],
            observed_crashes: 0,
        }
    }

    fn req_stats<'a>(client_stats: &'a ClientStats, default: &'a UserStats) -> &'a UserStats {
        client_stats.get_user_stats("requests").unwrap_or(default)
    }

    fn seq_stats<'a>(client_stats: &'a ClientStats, default: &'a UserStats) -> &'a UserStats {
        client_stats.get_user_stats("sequences").unwrap_or(default)
    }

    fn seq_sec_stats(client_stats: &ClientStats, secs: usize) -> UserStats {
        UserStats::new(
            Self::seq_stats(
                client_stats,
                &UserStats::new(UserStatsValue::Number(0), AggregatorOps::None),
            )
            .value()
            .clone()
            .stats_div(secs)
            .expect("Something went wrong"),
            AggregatorOps::None,
        )
    }

    fn req_sec_stats<'a>(
        client_stats: &'a ClientStats,
        default: &'a UserStats,
        secs: usize,
    ) -> UserStats {
        UserStats::new(
            client_stats
                .get_user_stats("requests")
                .unwrap_or(default)
                .value()
                .clone()
                .stats_div(secs)
                .expect("Something went wrong"),
            AggregatorOps::None,
        )
    }

    fn cov_stats<'a>(client_stats: &'a ClientStats, default: &'a UserStats) -> &'a UserStats {
        client_stats
            .get_user_stats("wuppiefuzz_code_coverage")
            .unwrap_or(default)
    }

    fn end_cov_stats<'a>(client_stats: &'a ClientStats, default: &'a UserStats) -> &'a UserStats {
        client_stats
            .get_user_stats("wuppiefuzz_endpoint_coverage")
            .unwrap_or(default)
    }

    fn current_sequence_stats<'a>(
        client_stats: &'a ClientStats,
        default: &'a UserStats,
    ) -> &'a UserStats {
        client_stats
            .get_user_stats("current_sequence")
            .unwrap_or(default)
    }
}
