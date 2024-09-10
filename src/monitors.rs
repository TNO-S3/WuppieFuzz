//! Coverage monitor for Wuppiefuzz. It defines how statistics are printed to the terminal
//! while fuzzing, and tracks the time consumed.

use core::{time, time::Duration};

use crate::configuration::{Configuration, OutputFormat};

use libafl::{
    alloc::fmt::Debug,
    monitors::{AggregatorOps, ClientStats, Monitor, UserStats, UserStatsValue},
};
use libafl_bolts::{current_time, format_duration_hms, ClientId};
use serde_json::json;
use std::{borrow::Cow, fmt};

/// Tracking monitor during fuzzing.
#[derive(Clone)]
pub struct CoverageMonitor<F>
where
    F: FnMut(String),
{
    print_fn: F,
    start_time: Duration,
    client_stats: Vec<ClientStats>,
    execs_per_sec: String,
    last_execs: u64,
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
    /// the client monitor, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    /// the client monitor
    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    /// Time this fuzzing run stated
    fn start_time(&self) -> time::Duration {
        self.start_time
    }

    /// Set the time this fuzzing run stated
    fn set_start_time(&mut self, time: time::Duration) {
        self.start_time = time
    }

    fn display(&mut self, event_msg: &str, _sender_id: ClientId) {
        let config = Configuration::must_get();
        let total_time = current_time() - self.start_time;
        let output_string = match config.output_format {
            OutputFormat::Json => json!({
                "event_msg": event_msg,
                "run_time": format_duration_hms(&(current_time() - self.start_time)),
                "objectives": self.objective_size(),
                "executed_sequences": self.total_execs(),
                "sequences_per_sec": self.req_execs_per_sec(self.total_execs()),
                "requests": Self::req_stats(&self.client_stats()[0], &UserStats::new(UserStatsValue::String(Cow::Borrowed("unknown")), AggregatorOps::None)),
                "requests_per_sec": Self::req_sec_stats(&self.client_stats()[0], &UserStats::new(UserStatsValue::Number(0), AggregatorOps::None), total_time.as_secs().try_into().unwrap()),
                "coverage": Self::cov_stats(&self.client_stats()[0], &UserStats::new(UserStatsValue::String(Cow::Borrowed("unknown")), AggregatorOps::None)),
                "endpoint_coverage": Self::cov_stats(&self.client_stats()[0], &UserStats::new(UserStatsValue::String(Cow::Borrowed("unknown")), AggregatorOps::None)),
            })
            .to_string(),
            OutputFormat::HumanReadable => {
            if event_msg == "Objective" {
                format!(
                    "[{}] New 'crash' observed! After run time: {}, total number of objectives reached: {}",
                    event_msg,
                    format_duration_hms(&(current_time() - self.start_time)),
                    self.objective_size(),
                )
            } else if event_msg == "Testcase" {
                match self.total_execs() {
                    0 => format!(
                            "[{}] Starting corpus loaded! Initial corpus size: {}",
                            event_msg,
                            self.corpus_size(),
                        ),
                    _ => format!(
                            "[{}] The testing corpus expanded! After run time: {}, total corpus size: {}",
                            event_msg,
                            format_duration_hms(&(current_time() - self.start_time)),
                            self.corpus_size(),
                        ),
                }
            } else {
                format!(
                    "[{}] run time: {}, corpus: {}, objectives: {}, executed sequences: {}, seq/sec: {}, requests: {}, req/sec: {}, coverage: {}, endpoint coverage: {}",
                    event_msg,
                    format_duration_hms(&total_time),
                    self.corpus_size(),
                    self.objective_size(),
                    self.total_execs(),
                    self.req_execs_per_sec(self.total_execs()),
                    Self::req_stats(&self.client_stats()[0], &UserStats::new(UserStatsValue::Number(0), AggregatorOps::None)),
                    Self::req_sec_stats(&self.client_stats()[0], &UserStats::new(UserStatsValue::Number(0), AggregatorOps::None), total_time.as_secs().try_into().unwrap()),
                    Self::cov_stats(&self.client_stats()[0], &UserStats::new(UserStatsValue::String(Cow::Borrowed("unknown")), AggregatorOps::None)),
                    Self::end_cov_stats(&self.client_stats()[0], &UserStats::new(UserStatsValue::String(Cow::Borrowed("unknown")), AggregatorOps::None)),
                )
            }
        }};
        (self.print_fn)(output_string);
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
            start_time: current_time(),
            client_stats: vec![],
            execs_per_sec: "NaN".to_string(),
            last_execs: 0,
        }
    }

    /// Creates the monitor with a given `start_time`.
    pub fn with_time(print_fn: F, start_time: time::Duration) -> Self {
        Self {
            print_fn,
            start_time,
            client_stats: vec![],
            execs_per_sec: "NaN".to_string(),
            last_execs: 0,
        }
    }

    fn req_stats<'a>(client_stats: &'a ClientStats, default: &'a UserStats) -> &'a UserStats {
        client_stats.get_user_stats("requests").unwrap_or(default)
    }

    fn req_execs_per_sec(&mut self, execs: u64) -> String {
        if self.last_execs < execs {
            self.execs_per_sec = self.execs_per_sec_pretty();
            self.last_execs = execs;
        }
        self.execs_per_sec.clone()
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
        client_stats.get_user_stats("coverage").unwrap_or(default)
    }

    fn end_cov_stats<'a>(client_stats: &'a ClientStats, default: &'a UserStats) -> &'a UserStats {
        client_stats
            .get_user_stats("endpoint_coverage")
            .unwrap_or(default)
    }
}
