//! Coverage client for agents that communicate using LCOV. This is a generic protocol,
//! and we can use it to get coverage from targets written in Python and Javascript.

use std::{
    cmp,
    collections::HashMap,
    fs::{File, create_dir_all, read_dir},
    io::prelude::*,
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    slice,
};

use lcov::{Reader, Record};
use libafl::Error;

use crate::{
    configuration::{Configuration, CoverageConfiguration},
    coverage_clients::{
        CoverageClient, MAP_SIZE,
        read_utilities::{read_byte_vec, read_char},
    },
};
extern crate num;

const REQUEST_HEADER: [u8; 5] = [0x01, 0xc0, 0xc0, 0x10, 0x07];
const BLOCK_CMD_DUMP: u8 = 0x40;
const LCOV_HEADER: [u8; 2] = [0xc1, 0xc0];

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

/// LCOV Coverage client.
#[allow(dead_code)]
#[derive(Debug)]
pub struct LcovCoverageClient {
    cov_map: [u8; MAP_SIZE],
    cov_map_total: [u8; MAP_SIZE],
    bit_idx_mapping: HashMap<SourceFileAndLineNum, usize>,
    first_unused_idx: usize,

    stream: TeeStream,
    max_ratio: (u64, u64),
    done: bool,
    latest_coverage_information: Vec<u8>,
    lcov_dump_dir: Option<PathBuf>,
    nth_coverage_dump: usize,
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

impl LcovCoverageClient {
    /// Creates a new LCOV coverage client given an IP address and port at which the agent
    /// can be reached.
    pub fn new(socket_address: &SocketAddr, report_path: Option<PathBuf>) -> Result<Self, Error> {
        let conn = TeeStream {
            stream: TcpStream::connect(socket_address).map_err(|err| {
                Error::unknown(format!(
                    "Failed to connect LcovCoverageClient to {socket_address}: {err}"
                ))
            })?,
            bytes: Vec::new(),
        };
        let result = Self {
            cov_map: [0; MAP_SIZE],
            cov_map_total: [0; MAP_SIZE],
            bit_idx_mapping: HashMap::new(),
            first_unused_idx: 0,
            stream: conn,
            max_ratio: (0, 0),
            done: false,
            latest_coverage_information: Vec::new(),
            lcov_dump_dir: report_path,
            nth_coverage_dump: 0,
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
    fn fetch_coverage_internal(&mut self, reset: bool) -> LcovCollection {
        let mut coverage_request: Vec<u8> = Vec::new();
        coverage_request.extend_from_slice(&REQUEST_HEADER);
        coverage_request.extend_from_slice(&[BLOCK_CMD_DUMP]);
        coverage_request.extend_from_slice(&[true as u8]);
        coverage_request.extend_from_slice(&[reset as u8]);
        self.stream
            .write_all(&coverage_request)
            .expect("Error writing coverage request");
        self.stream.flush().expect("Error flushing coverage stream");
        // Reads but does not erase bytes from self.stream
        let coverage_collection = self
            .process_coverage_response()
            .expect("Error processing response from coverage agent");
        // The stream contains extra signaling bytes that we do not want or need for generating a coverage report
        // Just read them away, we get the coverage information from the coverage_collection we just created
        self.stream.get_and_erase_bytes();
        self.latest_coverage_information
            .clone_from(&coverage_collection.0);
        coverage_collection
    }

    fn process_coverage_response(&mut self) -> Result<LcovCollection, Error> {
        let mut aggregated_coverage_result = LcovCollection::new();
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
    fn read_block(&mut self) -> Result<Block<Vec<u8>>, Error> {
        let mut block_type_byte: u8 = 0;
        self.stream
            .read_exact(slice::from_mut(&mut block_type_byte))
            .expect("No data from coverage client - it may not have started");
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

    fn set_cov_bit(&mut self, path: &Path, line: u32, val: u8) {
        let bit_idx_key = SourceFileAndLineNum {
            file: path.to_path_buf(),
            linenum: line,
        };
        let bit_idx: usize = match self.bit_idx_mapping.get(&bit_idx_key) {
            Some(existing_idx) => *existing_idx,
            None => {
                let new_idx = self.first_unused_idx;
                self.bit_idx_mapping.insert(bit_idx_key, new_idx);
                self.first_unused_idx += 1;
                new_idx
            }
        };
        match bit_idx.cmp(&MAP_SIZE) {
            cmp::Ordering::Less => {
                self.cov_map[bit_idx] = val;
                self.cov_map_total[bit_idx] = val;
            }
            cmp::Ordering::Equal => {
                log::debug!(
                    "Reached map size limit ({MAP_SIZE} bytes), remaining coverage will be ignored."
                );
            }
            _ => (),
        }
    }

    fn process_coverage_bytes(
        &mut self,
        coverage_bytes: LcovCollection,
        lcov_dump_dir: &Option<PathBuf>,
    ) -> Result<(), anyhow::Error> {
        let mut coverage_slice = coverage_bytes.0.as_slice();
        let latest_coverage_str = std::str::from_utf8(coverage_slice)?;
        // If a dump dir is given, write the LCOV-coverage to a file that we can create a report from at the end of the run.
        if let Some(lcov_dump_dir) = lcov_dump_dir {
            create_dir_all(lcov_dump_dir)?;
            let lcov_dump_path = lcov_dump_dir.join(self.nth_coverage_dump.to_string());
            let mut lcov_file = File::create(lcov_dump_path)?;
            write!(lcov_file, "{}", latest_coverage_str)?;
        }
        let mut source_path: PathBuf = PathBuf::new();
        let records = Reader::new(&mut coverage_slice).collect::<Result<Vec<_>, _>>();
        for rec in records.expect("LCOV coverage collection contained invalid records") {
            match rec {
                Record::SourceFile { path } => source_path = path,
                Record::LineData {
                    line,
                    count,
                    checksum: _,
                } => {
                    if count != 0 {
                        self.set_cov_bit(&source_path, line, 1);
                    }
                }
                _ => (),
            }
        }
        // merge map with the total coverage map
        for (dst, src) in self.cov_map_total.iter_mut().zip(self.cov_map.iter()) {
            *dst |= src
        }
        Ok(())
    }

    /// Reads a header.
    fn read_header(&mut self) -> Result<(), Error> {
        log::debug!("Reading header");
        let response_header = read_char(&mut self.stream)?;
        if LCOV_HEADER != response_header {
            return Err(Error::unknown(format!(
                "Invalid header byte in LCOV stream: {response_header:?}"
            )));
        }
        log::debug!("LCOV TCP server verified");
        Ok(())
    }

    /// Reads session info. Since the lcov format does not have this, this is unimplemented.
    fn read_session(&mut self) -> Result<(), Error> {
        unimplemented!(
            "Should never be called because the LCOV format does not have session blocks"
        )
    }

    fn read_coverage(&mut self) -> Result<Vec<u8>, Error> {
        read_byte_vec(&mut self.stream).map_err(core::convert::Into::into)
    }

    fn generate_report(&self, report_path: &Path) -> Result<(), anyhow::Error> {
        let lcov_dump_dir = self.lcov_dump_dir.as_ref().ok_or(anyhow!("Trying to generate an LCOV coverage report, but I have no lcov_dump_dir to get coverage files from."))?;

        let source_dir = match &Configuration::must_get().coverage_configuration {
            CoverageConfiguration::Lcov {
                source_dir: Some(source_dir),
            } => source_dir,
            _ => {
                unreachable!(
                    "Coverage client is Lcov, but the configuration specifies a different format or does not specify a source directory."
                )
            }
        };
        let lcov_html_path = report_path.join("lcov");
        create_dir_all(&lcov_html_path)?;
        // Now that the directory has been created, canonicalize the path for later use.
        let lcov_html_path = lcov_html_path.canonicalize()?;

        // Combine the dumped LCOV-files of this run into a single file
        let mut combine_cmd = std::process::Command::new("lcov");
        let dump_files = read_dir(lcov_dump_dir)?;
        for path in dump_files {
            let path = path?;
            combine_cmd.args([
                "-a",
                &path.path().clone().into_os_string().into_string().unwrap(),
            ]);
        }
        let combined_lcov_file_path = lcov_dump_dir.join("combined");
        File::create(&combined_lcov_file_path)?;
        // Now that the file has been created, canonicalize the path for later use.
        let combined_lcov_file_path = combined_lcov_file_path.canonicalize()?;
        combine_cmd
            .args([
                "-o",
                combined_lcov_file_path
                    .clone()
                    .into_os_string()
                    .to_str()
                    .unwrap(),
            ])
            .status()?;

        // Create an HTML-report from the combined coverage
        log::debug!("Generating html report");
        std::process::Command::new("genhtml")
            .arg("-o")
            .arg(&lcov_html_path)
            .arg(combined_lcov_file_path.into_os_string().to_str().unwrap())
            .current_dir(source_dir)
            .status()?;
        Ok(())
    }
}

impl CoverageClient for LcovCoverageClient {
    fn fetch_coverage(&mut self, reset: bool) {
        let cov_bytes = self.fetch_coverage_internal(reset);
        if let Err(err) = self.process_coverage_bytes(cov_bytes, &self.lcov_dump_dir.clone()) {
            panic!("Error processing coverage bytes: {}", err);
        }
        self.nth_coverage_dump += 1;
    }

    fn get_coverage_ptr(&mut self) -> *mut u8 {
        self.cov_map.as_mut_ptr()
    }

    fn max_coverage_ratio(&mut self) -> (u64, u64) {
        let count = self
            .cov_map_total
            .iter()
            .fold(0u64, |sum, val| sum + u64::from(val.count_ones()));
        let total = self.first_unused_idx as u64 * 8;
        // update the max coverage ratio
        self.max_ratio.0 = std::cmp::max(self.max_ratio.0, count);
        self.max_ratio.1 = std::cmp::max(self.max_ratio.1, total);
        self.max_ratio
    }

    fn generate_coverage_report(&self, report_path: &Path) {
        if let Err(err) = self.generate_report(report_path) {
            log::error!("{err}");
        }
    }
}

#[derive(Eq, PartialEq, Debug, Hash, Clone)]
struct SourceFileAndLineNum {
    file: PathBuf,
    linenum: u32,
}

/// LcovCollection is an alias for `Vec<u8>`.
///
/// When receiving more coverage (in the form of another `Vec<u8>`), LcovCollection
/// will append the new information to its current contents. This is valid since
/// the LCOV coverage information is typically a continuous file, possibly sent in
/// multiple parts.
#[derive(Debug)]
pub struct LcovCollection(Vec<u8>);

impl LcovCollection {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn push(&mut self, item: Vec<u8>) {
        self.0.extend(item)
    }
}

impl IntoIterator for LcovCollection {
    type Item = u8;
    type IntoIter = <Vec<u8> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
