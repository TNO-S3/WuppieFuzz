//! Coverage client for .NET targets using the WuppieFuzz dotnet coverage agent.
//!
//! The agent wraps the `dotnet-coverage` tool to provide on-demand coverage snapshots
//! with reset support, which is required for iterative fuzzing guidance.
//! See `coverage_agents/dotnet/` for the agent that must run alongside the target.

use std::{
    collections::{HashMap, hash_map::Entry},
    fs,
    io::Cursor,
    path::Path,
};

use log::trace;
use quick_xml::de as xml_de;
use reqwest::{
    Url,
    blocking::{Client, Response},
};
use serde::Deserialize;
use zip::ZipArchive;

use super::CoverageClient;
use crate::coverage_clients::MAP_SIZE;

// --- Cobertura XML deserialization ---

#[derive(Debug, Deserialize)]
#[serde(rename = "coverage")]
struct CoberturaCoverage {
    packages: CoberturaPackages,
}

#[derive(Debug, Default, Deserialize)]
struct CoberturaPackages {
    #[serde(rename = "package", default)]
    items: Vec<CoberturaPackage>,
}

#[derive(Debug, Deserialize)]
struct CoberturaPackage {
    classes: CoberturaClasses,
}

#[derive(Debug, Default, Deserialize)]
struct CoberturaClasses {
    #[serde(rename = "class", default)]
    items: Vec<CoberturaClass>,
}

#[derive(Debug, Deserialize)]
struct CoberturaClass {
    #[serde(rename = "@filename")]
    filename: String,
    #[serde(default)]
    lines: Option<CoberturaLines>,
}

#[derive(Debug, Default, Deserialize)]
struct CoberturaLines {
    #[serde(rename = "line", default)]
    items: Vec<CoberturaLine>,
}

#[derive(Debug, Deserialize)]
struct CoberturaLine {
    #[serde(rename = "@number")]
    number: u32,
    #[serde(rename = "@hits")]
    hits: u64,
}

// --- Coverage client ---

/// Coverage client for .NET targets, communicating with the WuppieFuzz dotnet coverage agent.
pub struct DotnetCoverageClient {
    /// Coverage bitmap for the current fuzzing iteration.
    cov_map: [u8; MAP_SIZE],
    /// Cumulative coverage bitmap across all iterations (OR of all cov_maps).
    cov_map_total: [u8; MAP_SIZE],
    /// Maps (filename, line_number) to a bit index in cov_map.
    bit_idx_mapping: HashMap<(String, u32), usize>,
    /// Number of bits allocated in the coverage map (one per unique source line seen).
    first_unused_idx: usize,
    max_ratio: (u64, u64),
    url: Url,
    client: Client,
    /// Only include classes whose filename contains this string. `None` means include all.
    namespace_filter: Option<String>,
}

impl DotnetCoverageClient {
    /// Create a new DotnetCoverageClient with the given agent URL and optional namespace filter.
    pub fn new(url: Url, namespace_filter: Option<String>) -> Self {
        Self {
            cov_map: [0; MAP_SIZE],
            cov_map_total: [0; MAP_SIZE],
            bit_idx_mapping: HashMap::new(),
            first_unused_idx: 0,
            max_ratio: (0, 0),
            url,
            client: Client::new(),
            namespace_filter,
        }
    }

    /// Returns (or allocates) the bit index for a `(filename, line_number)` pair.
    fn get_bit_index(&mut self, filename: &str, line: u32) -> Option<usize> {
        match self.bit_idx_mapping.entry((filename.to_owned(), line)) {
            Entry::Occupied(e) => Some(*e.get()),
            Entry::Vacant(e) => {
                let idx = self.first_unused_idx;
                if idx >= MAP_SIZE * 8 {
                    log::warn!("Coverage map full, cannot track line {line} in {filename}");
                    return None;
                }
                self.first_unused_idx += 1;
                Some(*e.insert(idx))
            }
        }
    }

    fn class_matches_filter(&self, filename: &str) -> bool {
        match &self.namespace_filter {
            None => true,
            Some(filter) => {
                if filename.contains(filter.as_str()) {
                    return true;
                }
                trace!("Skipping class {filename}");
                false
            }
        }
    }

    fn process_coverage(&mut self, report: CoberturaCoverage) {
        self.cov_map = [0; MAP_SIZE];
        for package in report.packages.items {
            for class in package.classes.items {
                if !self.class_matches_filter(&class.filename) {
                    continue;
                }
                let Some(lines) = class.lines else { continue };
                for line in lines.items {
                    // Allocate a bit for every source line we see, hit or not,
                    // so the coverage ratio reflects uncovered lines correctly.
                    let Some(bit_idx) = self.get_bit_index(&class.filename, line.number) else {
                        continue;
                    };
                    if line.hits > 0 {
                        let byte_idx = bit_idx / 8;
                        let bit_offset = bit_idx % 8;
                        self.cov_map[byte_idx] |= 0b_1000_0000 >> bit_offset;
                    }
                }
            }
        }
        for (dst, src) in self.cov_map_total.iter_mut().zip(self.cov_map.iter()) {
            *dst |= src;
        }
    }

    fn coverage_ratio(&self) -> (u64, u64) {
        let total = self.first_unused_idx as u64;
        let full_bytes = self.first_unused_idx / 8;
        let partial_bits = self.first_unused_idx % 8;
        let mut ones = self.cov_map_total[..full_bytes]
            .iter()
            .fold(0u64, |sum, b| sum + u64::from(b.count_ones()));
        if partial_bits > 0 && full_bytes < MAP_SIZE {
            let mask = 0xFFu8 << (8 - partial_bits);
            ones += u64::from((self.cov_map_total[full_bytes] & mask).count_ones());
        }
        (ones, total)
    }
}

impl CoverageClient for DotnetCoverageClient {
    fn fetch_coverage(&mut self, reset: bool) {
        let mut url = self.url.clone();
        url.set_path("/coverage");
        if reset {
            url.set_query(Some("reset=true"));
        }
        match self.client.get(url).send().and_then(Response::text) {
            Ok(xml) => match xml_de::from_str::<CoberturaCoverage>(&xml) {
                Ok(report) => self.process_coverage(report),
                Err(err) => log::error!("Failed to parse cobertura XML from dotnet agent: {err}"),
            },
            Err(err) => log::error!("Failed to fetch coverage from dotnet agent: {err}"),
        }
    }

    fn get_coverage_ptr(&mut self) -> *mut u8 {
        self.cov_map.as_mut_ptr()
    }

    fn max_coverage_ratio(&mut self) -> (u64, u64) {
        let (count, total) = self.coverage_ratio();
        self.max_ratio.0 = self.max_ratio.0.max(count);
        self.max_ratio.1 = self.max_ratio.1.max(total);
        self.max_ratio
    }

    fn generate_coverage_report(&self, report_path: &Path) {
        let mut url = self.url.clone();
        url.set_path("/report");
        let response = match self.client.get(url).send() {
            Ok(r) => r,
            Err(err) => {
                log::error!("Failed to request report from dotnet agent: {err}");
                return;
            }
        };

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();

        match response.bytes() {
            Err(err) => log::error!("Failed to read report response from dotnet agent: {err}"),
            Ok(bytes) => {
                if content_type.contains("zip") {
                    unpack_report_zip(&bytes, report_path);
                } else {
                    // Fallback: agent returned cobertura XML (no reportgenerator installed)
                    let dest = report_path.join("dotnet");
                    let xml_path = dest.join("coverage.xml");
                    if let Err(err) = fs::create_dir_all(&dest) {
                        log::error!("Cannot create dotnet report dir: {err}");
                        return;
                    }
                    match fs::write(&xml_path, &bytes) {
                        Ok(()) => log::info!("Dotnet coverage XML written to {xml_path:?}"),
                        Err(err) => log::error!("Failed to write coverage XML: {err}"),
                    }
                }
            }
        }
    }
}

/// Unpacks the ZIP archive received from the agent into `report_path/dotnet/`.
fn unpack_report_zip(bytes: &[u8], report_path: &Path) {
    let dest = report_path.join("dotnet");
    if let Err(err) = fs::create_dir_all(&dest) {
        log::error!("Cannot create dotnet report dir: {err}");
        return;
    }
    let mut archive = match ZipArchive::new(Cursor::new(bytes)) {
        Ok(a) => a,
        Err(err) => {
            log::error!("Failed to open report ZIP from dotnet agent: {err}");
            return;
        }
    };
    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(err) => {
                log::warn!("Skipping zip entry {i}: {err}");
                continue;
            }
        };
        let out_path = dest.join(entry.name());
        // Protect against zip-slip path traversal attacks
        if !out_path.starts_with(&dest) {
            log::warn!("Skipping zip entry with suspicious path: {}", entry.name());
            continue;
        }
        if entry.is_dir() {
            let _ = fs::create_dir_all(&out_path);
        } else {
            if let Some(parent) = out_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            match fs::File::create(&out_path) {
                Err(err) => log::warn!("Cannot create {out_path:?}: {err}"),
                Ok(mut out_file) => {
                    if let Err(err) = std::io::copy(&mut entry, &mut out_file) {
                        log::warn!("Failed to write {out_path:?}: {err}");
                    }
                }
            }
        }
    }
    log::info!("Dotnet coverage report extracted to {dest:?}");
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_COBERTURA: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<coverage version="1" timestamp="0" lines-valid="4" lines-covered="2" line-rate="0.5">
  <packages>
    <package name="MyApp" line-rate="0.5">
      <classes>
        <class name="MyApp.Controllers.HomeController" filename="Controllers/HomeController.cs" line-rate="0.5">
          <methods/>
          <lines>
            <line number="10" hits="2" branch="False"/>
            <line number="11" hits="0" branch="False"/>
            <line number="15" hits="1" branch="False"/>
          </lines>
        </class>
        <class name="MyApp.Other.Helper" filename="Other/Helper.cs" line-rate="0.0">
          <methods/>
          <lines>
            <line number="5" hits="0" branch="False"/>
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>"#;

    #[test]
    fn parse_cobertura_xml() {
        let report: CoberturaCoverage = xml_de::from_str(SAMPLE_COBERTURA).unwrap();
        let classes = &report.packages.items[0].classes.items;
        assert_eq!(classes.len(), 2);
        assert_eq!(classes[0].filename, "Controllers/HomeController.cs");
        let lines = classes[0].lines.as_ref().unwrap();
        assert_eq!(lines.items.len(), 3);
        assert_eq!(lines.items[0].number, 10);
        assert_eq!(lines.items[0].hits, 2);
    }

    #[test]
    fn namespace_filter_match() {
        let client = DotnetCoverageClient::new(
            "http://localhost:6302".parse().unwrap(),
            Some("Controllers".to_owned()),
        );
        assert!(client.class_matches_filter("Controllers/HomeController.cs"));
        assert!(!client.class_matches_filter("Other/Helper.cs"));
    }

    #[test]
    fn namespace_filter_none_matches_all() {
        let client = DotnetCoverageClient::new("http://localhost:6302".parse().unwrap(), None);
        assert!(client.class_matches_filter("Controllers/HomeController.cs"));
        assert!(client.class_matches_filter("Other/Helper.cs"));
    }

    #[test]
    fn bitmap_set_correct_bits() {
        let mut client = DotnetCoverageClient::new("http://localhost:6302".parse().unwrap(), None);
        let report: CoberturaCoverage = xml_de::from_str(SAMPLE_COBERTURA).unwrap();
        client.process_coverage(report);

        // 4 lines total -> 4 bits allocated (insertion order: 10, 11, 15, 5)
        assert_eq!(client.first_unused_idx, 4);

        // bit 0 -> line 10 (hits=2) -> byte 0, mask 0b_1000_0000  -> SET
        // bit 1 -> line 11 (hits=0) -> byte 0, mask 0b_0100_0000  -> unset
        // bit 2 -> line 15 (hits=1) -> byte 0, mask 0b_0010_0000  -> SET
        // bit 3 -> line  5 (hits=0) -> byte 0, mask 0b_0001_0000  -> unset
        assert_ne!(
            client.cov_map[0] & 0b_1000_0000,
            0,
            "line 10 (hits=2) must be set"
        );
        assert_eq!(
            client.cov_map[0] & 0b_0100_0000,
            0,
            "line 11 (hits=0) must not be set"
        );
        assert_ne!(
            client.cov_map[0] & 0b_0010_0000,
            0,
            "line 15 (hits=1) must be set"
        );
        assert_eq!(
            client.cov_map[0] & 0b_0001_0000,
            0,
            "line  5 (hits=0) must not be set"
        );

        // coverage_ratio: 2 set bits out of 4 total
        let (ones, total) = client.coverage_ratio();
        assert_eq!(total, 4);
        assert_eq!(ones, 2);
    }
}
