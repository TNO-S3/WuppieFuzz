//! Coverage client for the TraceGeneric coverage agent, which speaks the WuppieFuzz
//! The protocol is a generic AFL-like bitmap coverage transport, not tied to any
//! specific instrumentation or target language.

use std::{
    io::prelude::*,
    net::{SocketAddr, TcpStream},
    path::Path,
};

use libafl::Error;

use crate::coverage_clients::CoverageClient;

const MAGIC: [u8; 4] = *b"WGCA";
const VERSION: u8 = 0x01;
const TYPE_REQUEST_DUMP: u8 = 0x01;
const TYPE_RESPONSE_DUMP: u8 = 0x02;
const HEADER_LEN: usize = 10;

/// TraceGeneric coverage client. Communicates with a TraceGeneric coverage agent over a
/// persistent TCP connection using the wire protocol, receiving a raw 8-bit AFL-like
/// coverage bitmap whose size is reported by the agent.
#[derive(Debug)]
pub struct TraceGenericCoverageClient {
    cov_map: Vec<u8>,
    cov_map_total: Vec<u8>,
    max_ratio: (u64, u64),
    stream: TcpStream,
}

impl TraceGenericCoverageClient {
    /// Creates a new TraceGeneric coverage client connected to the coverage agent at
    /// `socket_address`.
    pub fn new(socket_address: &SocketAddr) -> Result<Self, Error> {
        let stream = TcpStream::connect(socket_address).map_err(|err| {
            Error::unknown(format!(
                "Failed to connect TraceGenericCoverageClient to {socket_address}: {err}"
            ))
        })?;
        Ok(Self {
            cov_map: Vec::new(),
            cov_map_total: Vec::new(),
            max_ratio: (0, 0),
            stream,
        })
    }

    /// Sends a `REQUEST_DUMP` and reads back the agent's `RESPONSE_DUMP`, returning the
    /// raw coverage-map bytes.
    fn fetch_coverage_internal(&mut self, reset: bool) -> Vec<u8> {
        let mut request = [0u8; HEADER_LEN + 1];
        request[0..4].copy_from_slice(&MAGIC);
        request[4] = VERSION;
        request[5] = TYPE_REQUEST_DUMP;
        request[6..10].copy_from_slice(&1u32.to_le_bytes());
        request[10] = u8::from(reset);
        self.stream
            .write_all(&request)
            .expect("Error writing coverage request");
        self.stream.flush().expect("Error flushing coverage stream");

        let mut header = [0u8; HEADER_LEN];
        self.stream
            .read_exact(&mut header)
            .expect("No data from coverage client - it may not have started");
        verify_response_header(&header).expect("Error processing response from coverage agent");
        let length = u32::from_le_bytes([header[6], header[7], header[8], header[9]]) as usize;

        let mut payload = vec![0u8; length];
        self.stream
            .read_exact(&mut payload)
            .expect("Error reading coverage map");
        payload
    }
}

/// Validates a `RESPONSE_DUMP` header: magic, version, and message type
fn verify_response_header(header: &[u8; HEADER_LEN]) -> Result<(), Error> {
    if header[0..4] != MAGIC {
        return Err(Error::unknown(format!(
            "Invalid protocol magic in response: {:?}",
            &header[0..4]
        )));
    }
    if header[4] != VERSION {
        return Err(Error::unknown(format!(
            "Unsupported protocol version in response: {}",
            header[4]
        )));
    }
    if header[5] != TYPE_RESPONSE_DUMP {
        return Err(Error::unknown(format!(
            "Unexpected protocol message type in response: {}",
            header[5]
        )));
    }
    Ok(())
}

impl CoverageClient for TraceGenericCoverageClient {
    fn fetch_coverage(&mut self, reset: bool) {
        let payload = self.fetch_coverage_internal(reset);

        // The coverage-map size is reported by the agent. Allocate the maps once, on the
        // first non-empty dump; the bitmap size is fixed after initialisation.
        if !payload.is_empty() && self.cov_map.is_empty() {
            self.cov_map = vec![0u8; payload.len()];
            self.cov_map_total = vec![0u8; payload.len()];
        }

        let n = payload.len().min(self.cov_map.len());
        for (dst, src) in self.cov_map[..n].iter_mut().zip(payload[..n].iter()) {
            *dst = u8::from(*src != 0);
        }

        // merge map with the total coverage map
        for (dst, src) in self.cov_map_total[..n]
            .iter_mut()
            .zip(self.cov_map[..n].iter())
        {
            *dst |= src;
        }
    }

    fn get_coverage_ptr(&mut self) -> *mut u8 {
        self.cov_map.as_mut_ptr()
    }

    /// Returns the coverage-map length reported by the agent, rather than a fixed size.
    fn get_coverage_len(&self) -> usize {
        self.cov_map.len()
    }

    fn max_coverage_ratio(&mut self) -> (u64, u64) {
        let count = self
            .cov_map_total
            .iter()
            .fold(0u64, |sum, val| sum + u64::from(val.count_ones()));
        let total = self.cov_map_total.len() as u64;
        // update the max coverage ratio
        self.max_ratio.0 = std::cmp::max(self.max_ratio.0, count);
        self.max_ratio.1 = std::cmp::max(self.max_ratio.1, total);
        self.max_ratio
    }

    /// The TraceGeneric payload is a raw coverage bitmap with no edge-to-source mapping,
    /// so no coverage report can be generated. This is a no-op, matching
    /// `DummyCoverageClient`.
    fn generate_coverage_report(&self, _report_path: &Path) {}
}
