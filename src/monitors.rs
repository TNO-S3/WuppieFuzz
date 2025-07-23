//! Coverage monitor for Wuppiefuzz. It defines how statistics are printed to the terminal
//! while fuzzing, and tracks the time consumed.

use core::{time, time::Duration};
use std::{borrow::Cow, fmt};

use libafl::{
    alloc::fmt::Debug,
    monitors::{
        Monitor,
        stats::{AggregatorOps, ClientStats, ClientStatsManager, UserStats, UserStatsValue},
    },
};
use libafl_bolts::{ClientId, Error, current_time, format_duration};
use serde_json::json;

use crate::configuration::{Configuration, OutputFormat};

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
    fn display(
        &mut self,
        client_stats_mgr: &mut ClientStatsManager,
        event_msg: &str,
        _sender_id: ClientId,
    ) -> Result<(), Error> {
        let config = Configuration::must_get();
        let total_time = current_time() - self.start_time;

        let global_stats = client_stats_mgr.global_stats();
        let objective_size = global_stats.objective_size;
        let total_execs = global_stats.total_execs;
        let corpus_size = global_stats.corpus_size;
        let execs_per_sec_pretty = global_stats.execs_per_sec_pretty.to_owned();

        let client_stats = &client_stats_mgr.client_stats()[&ClientId(0)];
        let output_string = match config.output_format {
            OutputFormat::Json => json!({
                "event_msg": event_msg,
                "run_time": format_duration(&(current_time() - self.start_time)),
                "objectives": objective_size,
                "executed_sequences": total_execs,
                "sequences_per_sec": self.req_execs_per_sec(total_execs, execs_per_sec_pretty),
                "requests": Self::req_stats(client_stats, &UserStats::new(UserStatsValue::String(Cow::Borrowed("unknown")), AggregatorOps::None)),
                "requests_per_sec": Self::req_sec_stats(client_stats, &UserStats::new(UserStatsValue::Number(0), AggregatorOps::None), total_time.as_secs().try_into().unwrap()),
                "coverage": Self::cov_stats(client_stats, &UserStats::new(UserStatsValue::String(Cow::Borrowed("unknown")), AggregatorOps::None)),
                "endpoint_coverage": Self::end_cov_stats(client_stats, &UserStats::new(UserStatsValue::String(Cow::Borrowed("unknown")), AggregatorOps::None)),
            })
            .to_string(),
            OutputFormat::HumanReadable => {
            if event_msg == "Objective" {
                format!(
                    "[{}] New 'crash' observed! After run time: {}, total number of objectives reached: {}",
                    event_msg,
                    format_duration(&(current_time() - self.start_time)),
                    objective_size,
                )
            } else if event_msg == "Testcase" {
                match total_execs {
                    0 => format!(
                            "[{event_msg}] Starting corpus loaded! Initial corpus size: {corpus_size}"
                        ),
                    _ => format!(
                            "[{event_msg}] The testing corpus expanded! After run time: {}, total corpus size: {corpus_size}",
                            format_duration(&(current_time() - self.start_time)),
                        ),
                }
            } else {
                format!(
                    "[{}] run time: {}, corpus: {}, objectives: {}, executed sequences: {}, seq/sec: {}, requests: {}, req/sec: {}, coverage: {}, endpoint coverage: {}",
                    event_msg,
                    format_duration(&total_time),
                    corpus_size,
                    objective_size,
                    total_execs,
                    self.req_execs_per_sec(total_execs, execs_per_sec_pretty),
                    Self::req_stats(client_stats, &UserStats::new(UserStatsValue::Number(0), AggregatorOps::None)),
                    Self::req_sec_stats(client_stats, &UserStats::new(UserStatsValue::Number(0), AggregatorOps::None), total_time.as_secs().try_into().unwrap()),
                    Self::cov_stats(client_stats, &UserStats::new(UserStatsValue::String(Cow::Borrowed("unknown")), AggregatorOps::None)),
                    Self::end_cov_stats(client_stats, &UserStats::new(UserStatsValue::String(Cow::Borrowed("unknown")), AggregatorOps::None)),
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

    fn req_execs_per_sec(&mut self, execs: u64, execs_per_sec_pretty: String) -> String {
        if self.last_execs < execs {
            self.execs_per_sec = execs_per_sec_pretty;
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
        client_stats
            .get_user_stats("wuppiefuzz_code_coverage")
            .unwrap_or(default)
    }

    fn end_cov_stats<'a>(client_stats: &'a ClientStats, default: &'a UserStats) -> &'a UserStats {
        client_stats
            .get_user_stats("wuppiefuzz_endpoint_coverage")
            .unwrap_or(default)
    }
}
