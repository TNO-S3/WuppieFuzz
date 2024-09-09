//! Collection of coverage clients. Each coverage communication protocol needs its own client.
//! These protocols are loosely connected to the programming language of the program under
//! test; Java targets for instance use Jacoco as its coverage agent, which has its own output
//! format. Our JacocoClient is designed to communicate with Jacoco.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::Context;

use crate::configuration::{self, Configuration};

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

/// CoverageClient is a client (on the fuzzer side) responsible for communicating with the
/// (coverage agent attached to the) program under test. It can be used to fetch the current
/// code coverage bitmap.
pub trait CoverageClient {
    /// Fetch and process the current coverage. If `reset` is true, tells the remote
    /// coverage agent to reset its coverage map.
    fn fetch_coverage(&mut self, reset: bool);

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
}

/// Produces a coverage client corresponding to the given configuration
pub fn get_coverage_client<'c>(
    clargs: &'c Configuration,
    report_path: &Option<PathBuf>,
    endpoint_cov_map_pointer: *mut u8,
) -> Result<Box<dyn CoverageClient + 'c>, anyhow::Error> {
    Ok(match clargs.coverage_configuration {
        configuration::CoverageConfiguration::Jacoco {
            ref jacoco_class_prefix,
            ..
        } => Box::new(
            jacoco::JacocoCoverageClient::new(
                &clargs
                    .coverage_host
                    .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6300)),
                report_path
                    .clone()
                    .map(|report_path| report_path.as_path().join("jacoco_exec")),
                jacoco_class_prefix,
            )
            .context("Could not construct JacocoCoverageClient")?,
        ),
        configuration::CoverageConfiguration::Lcov { .. } => Box::new(
            lcov_client::LcovCoverageClient::new(
                &clargs
                    .coverage_host
                    .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3001)),
                report_path
                    .clone()
                    .map(|report_path| report_path.as_path().join("lcov_exec")),
            )
            .context("Could not construct LcovCoverageClient")?,
        ),
        configuration::CoverageConfiguration::Coverband { .. } => {
            let mut url = clargs
                .coverage_host
                .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3001))
                .to_string();
            url.insert_str(0, "https://");
            Box::new(coverband::CoverbandCoverageClient::new(
                url.as_str()
                    .try_into()
                    .with_context(|| format!("Failed to parse the coverage_host URL: {url}"))
                    .context("Could not construct CoverbandCoverageClient")?,
            ))
        }
        configuration::CoverageConfiguration::Endpoint => {
            Box::new(dummy::DummyCoverageClient::new(endpoint_cov_map_pointer))
        }
    })
}
