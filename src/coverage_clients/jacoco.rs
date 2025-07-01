//! Coverage client for agents that communicate using Jacoco. Jacoco is the supported way
//! to collect coverage from Java targets.

use std::{
    collections::{HashMap, hash_map::Entry},
    fs::{DirBuilder, OpenOptions, create_dir_all, read_dir, remove_file},
    io::prelude::*,
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    slice,
};

extern crate num;

use libafl::Error;
use log::trace;

use crate::{
    configuration::{Configuration, CoverageConfiguration},
    coverage_clients::{
        CoverageClient, MAP_SIZE,
        read_utilities::{read_bool_array, read_cesu8, read_char, read_u64be},
    },
};

const REQUEST_HEADER: [u8; 5] = [0x01, 0xc0, 0xc0, 0x10, 0x07];
const BLOCK_CMD_DUMP: u8 = 0x40;
const JACOCO_HEADER: [u8; 2] = [0xc0, 0xc0];
const FORMAT_VERSION: [u8; 2] = [0x10, 0x07];

#[derive(FromPrimitive, Debug, PartialEq)]
enum BlockType {
    Header = 0x01,
    SessionInfo = 0x10,
    CoverageInfo = 0x11,
    CmdOk = 0x20,
    CmdDump = 0x40,
}

enum Block<T> {
    /// Coverage information as a Vec of bytes
    Coverage(T),
    /// Block denoting the end of the transmission
    EndOfTransmission,
    /// Block with no interesting information
    Empty,
}

/// Jacoco coverage client.
#[allow(dead_code)]
#[derive(Debug)]
pub struct JacocoCoverageClient<'a> {
    cov_map: [u8; MAP_SIZE],
    cov_map_total: [u8; MAP_SIZE],
    bit_idx_mapping: HashMap<u64, usize>,
    first_unused_idx: usize,

    stream: TeeStream,
    max_ratio: (u64, u64),
    done: bool,
    latest_coverage_information: Vec<u8>,
    jacoco_dump_output_dir: Option<PathBuf>,
    jacoco_prefix_filter: &'a Option<String>,
    dump_index: usize,
}

struct JacocoCoverageSegment {
    id: u64,
    name: String,
    probe_bytes: Vec<u8>,
}

/// TeeStream is a wrapper for a TcpStream that caches all bytes received from the
/// inner stream.
#[derive(Debug)]
pub struct TeeStream {
    stream: TcpStream,
    bytes: Vec<u8>,
}

impl TeeStream {
    /// This function returns the data cached so far by the TeeStream, and then
    /// erases the cache.
    fn get_and_erase_bytes(&mut self) -> Vec<u8> {
        self.bytes.drain(..).collect()
    }
}

impl Read for TeeStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes_read = self.stream.read(buf)?;
        self.bytes.extend(buf[..bytes_read].iter());
        Ok(bytes_read)
    }
}

impl Write for TeeStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl<'a> JacocoCoverageClient<'a> {
    /// Creates a new JacocoCoverageClient given an IP and port at which the coverage agent
    /// can be reached.
    /// A (temporary) directory is needed for the intermediate files generated for the report;
    /// these are recombined to an HTML report by the Jacoco application and therefore need
    /// to be in the filesystem.
    /// Optionally, a prefix can be given; it's used to filter the coverage information so it
    /// only includes classes with a name that starts with the given prefix.
    pub fn new<'c: 'a>(
        socket_address: &SocketAddr,
        jacoco_dump_output_dir: Option<PathBuf>,
        jacoco_prefix: &'c Option<String>,
    ) -> Result<Self, Error> {
        let conn = TeeStream {
            stream: TcpStream::connect(socket_address)?,
            bytes: Vec::new(),
        };

        create_or_clear_dump_directory(jacoco_dump_output_dir.as_ref())?;

        let result = Self {
            cov_map: [0; MAP_SIZE],
            cov_map_total: [0; MAP_SIZE],
            bit_idx_mapping: HashMap::new(),
            first_unused_idx: 0,
            stream: conn,
            max_ratio: (0, 0),
            done: false,
            latest_coverage_information: Vec::new(),
            jacoco_dump_output_dir,
            jacoco_prefix_filter: jacoco_prefix,
            dump_index: 0,
        };
        Ok(result)
    }

    /// Sends a request for coverage to the coverage agent in the PUT.
    ///
    /// # Parameter
    /// * `reset` - Boolean indicating if the coverage map should be reset (needs to happen only on PUT side, LibAFL handles internal coverage).
    ///
    /// # Return
    /// Returns a `Vec<u8>` containing the bytes that represent the coverage information.
    fn fetch_coverage_internal(&mut self, reset: bool) -> Vec<JacocoCoverageSegment> {
        let mut coverage_request: Vec<u8> = Vec::new();
        coverage_request.extend_from_slice(&REQUEST_HEADER);
        coverage_request.extend_from_slice(&[BLOCK_CMD_DUMP]);
        coverage_request.extend_from_slice(&[true as u8]);
        coverage_request.extend_from_slice(&[reset as u8]);
        self.stream
            .write_all(&coverage_request)
            .expect("Error writing coverage request");
        self.stream.flush().expect("Error flushing coverage stream");
        let coverage_collection = self
            .process_coverage_response()
            .expect("Error processing response from coverage agent");
        self.latest_coverage_information = self.stream.get_and_erase_bytes();

        self.dump_jacoco_coverage_to_file();
        coverage_collection
    }

    fn dump_jacoco_coverage_to_file(&mut self) {
        if let Some(ref output_dir) = self.jacoco_dump_output_dir {
            let file_path = output_dir.join(format!("jacoco_{}.exec", self.dump_index));
            self.dump_index += 1;

            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&file_path)
                .unwrap_or_else(|err| panic!("Could not create file {file_path:?}: {err}"));

            let bytes = self.latest_coverage_information.as_slice();
            // remove the block CmdOk
            let bytes_without_cmdok_block = bytes.split_last().unwrap().1;
            let header_buf = [0x01, 0xc0, 0xc0, 0x10, 0x07];
            // check if the header block is included
            if bytes_without_cmdok_block[0..4] != header_buf {
                // if not included add the header block to the file
                file.write_all(&header_buf)
                    .expect("Could not write to file that was just created.");
            }
            // write the coverage information
            file.write_all(bytes_without_cmdok_block)
                .expect("Could not write to file that was just created.");
        }
    }

    fn process_coverage_response(&mut self) -> Result<Vec<JacocoCoverageSegment>, Error> {
        let mut aggregated_coverage_result = Vec::new();
        loop {
            match self.read_block()? {
                Block::Coverage(data) => aggregated_coverage_result.push(data),
                Block::EndOfTransmission => break,
                Block::Empty => (),
            }
        }
        Ok(aggregated_coverage_result)
    }

    /// Reads away a single block from the stream.
    /// Most interesting is the CoverageInfo block, this holds coverage information
    /// which may be concatenated with other CoverageInfo blocks later on.
    fn read_block(&mut self) -> Result<Block<JacocoCoverageSegment>, Error> {
        let mut block_type_byte: u8 = 0;
        self.stream
            .read_exact(slice::from_mut(&mut block_type_byte))?;
        let block_type: BlockType =
            num::FromPrimitive::from_u8(block_type_byte).ok_or_else(|| {
                Error::illegal_argument(format!(
                "incorrect block type byte {block_type_byte} encountered in TCP connection with coverage agent"
            ))
            })?;
        Ok(match block_type {
            BlockType::Header => {
                self.read_header()?;
                Block::Empty
            }
            BlockType::CoverageInfo => Block::Coverage(self.read_coverage()?),
            BlockType::SessionInfo => {
                let _ = self.read_session();
                Block::Empty
            }
            BlockType::CmdOk => {
                self.done = true;
                Block::EndOfTransmission
            }
            _ => {
                return Err(Error::unknown(format!(
                    "Invalid or unsupported type: {block_type:?}"
                )));
            }
        })
    }

    fn read_header(&mut self) -> Result<(), Error> {
        log::debug!("Reading header");
        let response_header = read_char(&mut self.stream)?;
        if JACOCO_HEADER != response_header {
            return Err(Error::unknown(format!(
                "Invalid header byte in Jacoco stream: {response_header:?}"
            )));
        }
        let format_version = read_char(&mut self.stream)?;
        if format_version != FORMAT_VERSION {
            return Err(Error::unknown(format!(
                "Invalid format version: {format_version:?}",
            )));
        }
        log::debug!("Jacoco TCP server verified");
        Ok(())
    }

    fn read_session(&mut self) -> Result<(), Error> {
        let _id = read_cesu8(&mut self.stream)?;
        let _start = read_u64be(&mut self.stream)?; // starttime of the jacoco agent
        let _dump = read_u64be(&mut self.stream)?; // timestamp of the last dump from the jacoco agent
        Ok(())
    }

    /// Read the probe list returned from jacoco
    fn read_coverage(&mut self) -> Result<JacocoCoverageSegment, Error> {
        Ok(JacocoCoverageSegment {
            id: read_u64be(&mut self.stream)?,
            name: read_cesu8(&mut self.stream)?.1,
            probe_bytes: read_bool_array(&mut self.stream)?,
        })
    }

    fn coverage_ratio(&mut self) -> (u64, u64) {
        let ones_count = self
            .cov_map_total
            .iter()
            .fold(0u64, |sum, val| sum + u64::from(val.count_ones()));
        let total_bits = self.first_unused_idx as u64 * 8;
        (ones_count, total_bits)
    }

    fn get_map_index(&mut self, segment: &JacocoCoverageSegment) -> Result<usize, libafl::Error> {
        match self.bit_idx_mapping.entry(segment.id) {
            Entry::Occupied(entry) => Ok(*entry.get()),
            Entry::Vacant(entry) => {
                // store the index of where the probe list of this class is stored
                let stored_index = self.first_unused_idx;
                self.first_unused_idx += segment.probe_bytes.len();
                if self.first_unused_idx > MAP_SIZE {
                    return Err(libafl::Error::unknown("The map size is not large enough to hold all the probes from the coverage stream. The current size is ".to_string()));
                }
                log::debug!(
                    "New file found with name {} containing {} probes",
                    segment.name,
                    segment.probe_bytes.len()
                );
                Ok(*entry.insert(stored_index))
            }
        }
    }
}

fn create_or_clear_dump_directory(jacoco_dump_output_dir: Option<&PathBuf>) -> Result<(), Error> {
    if let Some(dir_path) = jacoco_dump_output_dir {
        let mut dir_builder = DirBuilder::new();
        // create directory
        dir_builder.recursive(true).create(dir_path)?;
        // check if directory contains files of the form r"jacoco_d+.exec"
        let entries = read_dir(dir_path)?;
        for entry in entries.flatten() {
            if let Some(file_name) = entry.file_name().to_str() {
                if file_name.starts_with("jacoco") {
                    let mut path = PathBuf::new();
                    path.push(dir_path);
                    path.push(entry.path());
                    remove_file(path)?;
                }
            }
        }
    }
    Ok(())
}

impl CoverageClient for JacocoCoverageClient<'_> {
    fn fetch_coverage(&mut self, reset: bool) {
        let cov_bytes = self.fetch_coverage_internal(reset);
        if cov_bytes.is_empty() {
            return;
        }
        for segment in cov_bytes.into_iter() {
            if !segment_matches_prefix(self.jacoco_prefix_filter, &segment) {
                continue;
            }

            // The number of probes in this class
            let idx = self.get_map_index(&segment).unwrap();

            for (dst, src) in self.cov_map[idx..(idx + segment.probe_bytes.len())]
                .iter_mut()
                .zip(&segment.probe_bytes)
            {
                *dst |= src;
            }
        }
        // Then merge map with the total coverage map
        for (dst, src) in self.cov_map_total.iter_mut().zip(self.cov_map.iter()) {
            *dst |= src
        }
    }

    fn get_coverage_ptr(&mut self) -> *mut u8 {
        self.cov_map.as_mut_ptr()
    }

    fn max_coverage_ratio(&mut self) -> (u64, u64) {
        let (count, total) = self.coverage_ratio();
        // update the max coverage ratio
        self.max_ratio.0 = std::cmp::max(self.max_ratio.0, count);
        self.max_ratio.1 = std::cmp::max(self.max_ratio.1, total);
        self.max_ratio
    }

    fn generate_coverage_report(&self, report_path: &Path) {
        let (source_dir, jacoco_class_dir) = match &Configuration::must_get().coverage_configuration
        {
            CoverageConfiguration::Jacoco {
                source_dir: Some(source_dir),
                jacoco_class_dir: Some(jacoco_class_dir),
                ..
            } => (source_dir, jacoco_class_dir),
            _ => {
                unreachable!(
                    "Coverage client is Jacoco, but there is no configuration for Jacoco or the source and class dir are missing"
                )
            }
        };

        let jacoco_dump_dir = match &self.jacoco_dump_output_dir {
            Some(path) => path,
            None => unreachable!(
                "Trying to generate a Jacoco report, but there is no directory with Jacoco dump files"
            ),
        };

        let jacoco_exec_path = jacoco_dump_dir.join("jacoco_report.exec");

        std::process::Command::new("java")
            .args(["-jar", "coverage_agents/java/jacococli.jar"])
            .arg("merge")
            .args(
                std::fs::read_dir(jacoco_dump_dir)
                    .expect("Unable to read jacoco dump directory")
                    .filter_map(Result::ok)
                    .map(|entry| entry.path()),
            )
            .arg("--destfile")
            .arg(&jacoco_exec_path)
            .status()
            .expect("Could not generate jacoco report, merge command of the jacococli.jar failed.");

        let jacoco_html_path = report_path.join("jacoco");
        create_dir_all(&jacoco_html_path).expect("unable to create report dir for jacoco");

        std::process::Command::new("java")
            .args(["-jar", "coverage_agents/java/jacococli.jar"])
            .arg("report")
            .arg("--classfiles")
            .arg(jacoco_class_dir)
            .arg("--sourcefiles")
            .arg(source_dir)
            .arg("--html")
            .arg(jacoco_html_path)
            .arg(jacoco_exec_path)
            .status()
            .expect(
                "Could not generate jacoco report, report command of the jacococli.jar failed.",
            );
    }
}

fn segment_matches_prefix(prefix_filter: &Option<String>, segment: &JacocoCoverageSegment) -> bool {
    match prefix_filter {
        // if no filter is set all segments match
        None => true,
        Some(prefix) => {
            if segment.name.starts_with(prefix) {
                return true;
            }
            trace!("Skipping segment {}", segment.name);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{JacocoCoverageSegment, segment_matches_prefix};

    #[test]
    fn filter_test_success() {
        let segment = JacocoCoverageSegment {
            id: 10,
            name: "some/prefix/class/name".to_owned(),
            probe_bytes: vec![],
        };
        assert!(segment_matches_prefix(
            &Some("some/prefix".to_owned()),
            &segment
        ));
    }

    #[test]
    fn filter_test_failure() {
        let segment = JacocoCoverageSegment {
            id: 10,
            name: "some/prefix/class/name".to_owned(),
            probe_bytes: vec![],
        };
        assert!(!segment_matches_prefix(
            &Some("some.prefix".to_owned()),
            &segment
        ));
    }
}
