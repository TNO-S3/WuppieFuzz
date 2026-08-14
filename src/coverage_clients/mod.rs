//! Collection of coverage clients. Each coverage communication protocol needs its own client.
//! These protocols are loosely connected to the programming language of the program under
//! test; Java targets for instance use Jacoco as its coverage agent, which has its own output
//! format. Our JacocoClient is designed to communicate with Jacoco.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::Context;

use crate::{
    configuration::{self, Configuration},
    input::OpenApiInput,
};

/// Size of the coverage map. This is a bitmap containing a bit for each line in the target
/// (or each endpoint, if using endpoint coverage as the guidance). The fuzzer will crash if
/// it is too small, so we choose a rather large value. Might need tweaking if your target
/// is larger or your memory is not large enough.
pub const MAP_SIZE: usize = 4 * 8192;

pub mod read_utilities;

pub mod coverband;
pub mod dummy;
pub mod endpoint;
pub mod jacoco;
pub mod lcov_client;
pub mod otel;

/// Sets up the line coverage client according to the configuration, and initializes it
/// and constructs a LibAFL observer and feedback
pub fn setup_line_coverage(
    config: &'static Configuration,
    report_path: &Option<PathBuf>,
) -> Result<
    (
        Box<dyn CoverageClient>,
        Option<otel::SharedOtelTraceProcessingMetrics>,
    ),
    anyhow::Error,
> {
    let (mut code_coverage_client, otel_trace_processing_metrics) =
        crate::coverage_clients::get_coverage_client(config, report_path)?;
    // This is very important, we want to fetch and reset the coverage before interacting with the target.
    code_coverage_client.fetch_coverage(true);

    Ok((code_coverage_client, otel_trace_processing_metrics))
}

/// APIs already create code coverage during boot. We check if the code coverage is non-zero.
/// Zero coverage might indicate an issue with the coverage agent or a target that was not rebooted between fuzzing runs.
pub fn validate_instrumentation(
    config: &'static Configuration,
    code_coverage_client: &mut Box<dyn CoverageClient>,
) {
    if !matches!(
        config.coverage_configuration,
        crate::configuration::CoverageConfiguration::Endpoint
            | crate::configuration::CoverageConfiguration::Otel { .. }
    ) {
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

/// Guidance that can promote inputs after the synchronous HTTP execution has returned.
///
/// OpenTelemetry spans are exported asynchronously, so the corresponding input can become
/// interesting after normal LibAFL feedback has already been evaluated.
pub trait DelayedGuidance {
    /// Register that a new request sequence is about to be executed.
    fn start_request_sequence(&mut self, input: &OpenApiInput);

    /// Return the W3C trace context header value for the next outgoing HTTP request.
    fn traceparent_for_request(&mut self) -> Option<String>;

    /// Register that the current request sequence has finished executing.
    fn finish_request_sequence(&mut self, input: &OpenApiInput);

    /// Drain inputs that became interesting after asynchronous guidance arrived.
    fn drain_promoted_inputs(&mut self) -> Vec<OpenApiInput>;

    /// Enable or disable replay mode while delayed promotions are evaluated.
    fn set_replaying_promotion(&mut self, replaying: bool);

    /// Backwards-compatible spelling for callers that refer to replay promotion.
    fn set_replay_promotion(&mut self, replaying: bool) {
        self.set_replaying_promotion(replaying);
    }
}

/// CoverageClient is a client (on the fuzzer side) responsible for communicating with the
/// (coverage agent attached to the) program under test. It can be used to fetch the current
/// code coverage bitmap.
pub trait CoverageClient {
    /// Fetch and process the current coverage. If `reset` is true, tells the remote
    /// coverage agent to reset its coverage map.
    fn fetch_coverage(&mut self, reset: bool);

    /// Finish a request sequence. Synchronous coverage clients fetch coverage here;
    /// asynchronous clients can override this to close their attribution window.
    fn finish_request_sequence(&mut self, input: &OpenApiInput) {
        let _ = input;
        self.fetch_coverage(true);
    }

    /// Retrieve a pointer to the coverage bitmap (this is used by LibAFL).
    fn get_coverage_ptr(&mut self) -> *mut u8;

    /// Retrieve the length of the array pointed to by `get_coverage_pointer`
    fn get_coverage_len(&self) -> usize {
        MAP_SIZE
    }

    /// Retrieve the coverage ratio: nodes hit and total number of nodes.
    fn max_coverage_ratio(&mut self) -> (u64, u64);

    /// Write a format-dependent report to disk
    fn generate_coverage_report(&self, report_path: &Path);

    /// Optional hook for delayed, asynchronous guidance sources such as OpenTelemetry.
    fn delayed_guidance(&mut self) -> Option<&mut dyn DelayedGuidance> {
        None
    }
}

/// Returns the effective coverage host for the configured coverage format,
/// including the default fallback when `coverage_host` is not explicitly set.
pub fn effective_coverage_host(config: &Configuration) -> Option<SocketAddr> {
    match config.coverage_configuration {
        configuration::CoverageConfiguration::Jacoco { .. } => Some(
            config
                .coverage_host
                .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6300)),
        ),
        configuration::CoverageConfiguration::Lcov { .. }
        | configuration::CoverageConfiguration::Coverband { .. } => Some(
            config
                .coverage_host
                .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3001)),
        ),
        configuration::CoverageConfiguration::Endpoint
        | configuration::CoverageConfiguration::Otel { .. } => None,
    }
}

/// Produces a coverage client corresponding to the given configuration
pub fn get_coverage_client<'c>(
    clargs: &'c Configuration,
    report_path: &Option<PathBuf>,
) -> Result<
    (
        Box<dyn CoverageClient + 'c>,
        Option<otel::SharedOtelTraceProcessingMetrics>,
    ),
    anyhow::Error,
> {
    let coverage_host = effective_coverage_host(clargs);

    Ok(match clargs.coverage_configuration {
        configuration::CoverageConfiguration::Jacoco {
            ref jacoco_class_prefix,
            ..
        } => (
            Box::new(
                jacoco::JacocoCoverageClient::new(
                    // effective_coverage_host always returns Some for Jacoco
                    &coverage_host.unwrap(),
                    report_path
                        .clone()
                        .map(|report_path| report_path.as_path().join("jacoco_exec")),
                    jacoco_class_prefix,
                )
                .context("Could not construct JacocoCoverageClient")?,
            ),
            None,
        ),
        configuration::CoverageConfiguration::Lcov { .. } => (
            Box::new(
                lcov_client::LcovCoverageClient::new(
                    // effective_coverage_host always returns Some for Lcov
                    &coverage_host.unwrap(),
                    report_path
                        .clone()
                        .map(|report_path| report_path.as_path().join("lcov_exec")),
                )
                .context("Could not construct LcovCoverageClient")?,
            ),
            None,
        ),
        configuration::CoverageConfiguration::Coverband { .. } => {
            // effective_coverage_host always returns Some for Coverband
            let mut url = coverage_host.unwrap().to_string();
            url.insert_str(0, "https://");
            (
                Box::new(coverband::CoverbandCoverageClient::new(
                    url.as_str()
                        .try_into()
                        .with_context(|| format!("Failed to parse the coverage_host URL: {url}"))
                        .context("Could not construct CoverbandCoverageClient")?,
                )),
                None,
            )
        }
        configuration::CoverageConfiguration::Endpoint => {
            (Box::new(dummy::DummyCoverageClient::new()), None)
        }
        configuration::CoverageConfiguration::Otel {
            otel_http_receiver_bind,
            otel_grpc_receiver_bind,
        } => {
            let otel_trace_processing_metrics = otel::new_otel_trace_processing_metrics();
            (
                Box::new(otel::OtelCoverageClient::new(
                    otel_http_receiver_bind,
                    otel_grpc_receiver_bind,
                    otel_trace_processing_metrics.clone(),
                )?),
                Some(otel_trace_processing_metrics),
            )
        }
    })
}
