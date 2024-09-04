//! This module loads and prepares default headers. Users can optionally
//! specify headers that should be sent with every request the fuzzer makes,
//! and this module parses those into a Reqwest HeaderMap.

use crate::configuration::Configuration;
use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::collections::HashMap;
use std::fs::File;
use std::str::FromStr;

/// Load default headers from a file specified in configuration and apply
/// them to the given ClientBuilder
pub fn get_default_headers() -> Result<HeaderMap> {
    let clargs = Configuration::must_get();

    // Add custom default headers from file
    let custom_header: HashMap<String, String> = match clargs.header.as_deref() {
        Some(header_path) => {
            serde_yaml::from_reader(File::open(header_path).with_context(|| {
                format!(
                    "Failed to open default header file {}",
                    header_path.to_string_lossy()
                )
            })?)
            .with_context(|| "Failed to parse default header file as YAML")?
        }
        None => HashMap::new(),
    };

    // Create the actual map of HeaderKeys and Values
    let mut default_headers = HeaderMap::new();

    // Insert default headers
    default_headers.insert(
        HeaderName::from_static("user-agent"),
        HeaderValue::from_static("wuppiefuzz/0.1.0"),
    );

    // Insert custom headers from file
    for (key, value) in custom_header {
        default_headers.insert(
            HeaderName::from_str(&key)
                .with_context(|| format!("Can't parse {key} as header name"))?,
            HeaderValue::from_str(&value)
                .with_context(|| format!("Can't parse {value} as header value"))?,
        );
    }

    Ok(default_headers)
}
