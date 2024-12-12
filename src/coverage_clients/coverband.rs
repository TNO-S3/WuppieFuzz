//! Coverage client for agents that communicate using Coverband. Coverband can be used to
//! collect coverage on Ruby targets.

use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::Debug,
    path::Path,
};

use reqwest::{
    blocking::{Client, Response},
    Url,
};

use super::CoverageClient;
use crate::coverage_clients::MAP_SIZE;

#[derive(Debug, serde::Deserialize)]
struct CoverbandSegment {
    filename: String,
    coverage: Vec<Option<u32>>,
    never_loaded: bool,
}

/// Coverband coverage client.
pub struct CoverbandCoverageClient {
    /// The current coverage map
    cov_map: [u8; MAP_SIZE],
    /// Baseline number of times each line has been covered. This is the last
    /// coverage array we received from the Coverband endpoint. If we receive a
    /// new one, this allows us to see whether there is new coverage.
    cov_map_baseline: [u32; 32 * MAP_SIZE],
    /// Mapping from filename to spot in the coverage maps
    bit_idx_mapping: HashMap<String, usize>,
    /// First unused index in the coverage maps
    first_unused_idx: usize,

    url: Url,
    client: Client,
    max_ratio: (u64, u64),
    latest_coverage_information: Vec<u8>,
}

impl CoverbandCoverageClient {
    /// Creates a mew Coverband coverage client, given an URL at which the coverage agent
    /// can be reached.
    pub fn new(url: Url) -> Self {
        Self {
            cov_map: [0; MAP_SIZE],
            cov_map_baseline: [0; 32 * MAP_SIZE],
            bit_idx_mapping: HashMap::new(),
            first_unused_idx: 0,
            url,
            client: Client::new(),
            max_ratio: (0, 0),
            latest_coverage_information: Vec::new(),
        }
    }

    fn get_map_index(&mut self, file: String, length: usize) -> Result<usize, libafl::Error> {
        match self.bit_idx_mapping.entry(file) {
            Entry::Occupied(entry) => Ok(*entry.get()),
            Entry::Vacant(entry) => {
                // store the index of where the probe list of this class is stored
                let stored_index = self.first_unused_idx;
                self.first_unused_idx += length;
                if self.first_unused_idx > MAP_SIZE {
                    return Err(libafl::Error::unknown("The map size is not large enough to hold all the probes from the coverage stream. The current size is ".to_string()));
                }
                log::info!(
                    "New file found with name {} containing {} probes",
                    entry.key(),
                    length
                );
                Ok(*entry.insert(stored_index))
            }
        }
    }

    fn process_coverage_bytes(&mut self, coverage_info: Vec<CoverbandSegment>) {
        if coverage_info.is_empty() {
            return;
        }
        for CoverbandSegment {
            filename, coverage, ..
        } in coverage_info.into_iter().filter(|s| !s.never_loaded)
        {
            let length = coverage.iter().filter(|o| o.is_some()).count();
            let start_idx = self
                .get_map_index(filename, length)
                .expect("Coverage map is full");

            for (idx, hits) in coverage.into_iter().flatten().enumerate() {
                let idx = start_idx + idx;
                if hits > self.cov_map_baseline[idx] {
                    self.cov_map[idx / 8] |= 0b_1000_0000 >> (idx % 8);
                    self.cov_map_baseline[idx] = hits;
                }
            }
        }
    }
}

impl CoverageClient for CoverbandCoverageClient {
    fn fetch_coverage(&mut self, _reset: bool) {
        match self
            .client
            .get(self.url.clone())
            .send()
            .and_then(Response::json)
        {
            Ok(cov_bytes) => self.process_coverage_bytes(cov_bytes),
            Err(err) => log::error!("{err}"),
        }
    }

    fn get_coverage_ptr(&mut self) -> *mut u8 {
        self.cov_map.as_mut_ptr()
    }

    fn max_coverage_ratio(&mut self) -> (u64, u64) {
        let count = self
            .cov_map
            .iter()
            .map(|byte: &u8| byte.count_ones() as u64)
            .sum();
        let total = self.first_unused_idx as u64;

        // update the max coverage ratio
        self.max_ratio.0 = std::cmp::max(self.max_ratio.0, count);
        self.max_ratio.1 = std::cmp::max(self.max_ratio.1, total);
        self.max_ratio
    }

    fn generate_coverage_report(&self, _report_dir: &Path) {
        let _ = self.latest_coverage_information;
        unimplemented!()
    }
}
