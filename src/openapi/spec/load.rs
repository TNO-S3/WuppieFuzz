//! Loads an OpenAPI specification from a file, and converts it to the format we use.

use std::path::Path;

use anyhow::{Context, Result};
use openapiv3::VersionedOpenAPI;

use super::Spec;

/// AttemptsFailed records a parallel set of errors, that result from multiple
/// strategies failing. When Displayed, it prints all error chains that resulted
/// from the different attempts, so the user can find the strategy they wanted
/// to use and fix the errors that resulted in that attempt.
#[derive(Debug)]
struct AttemptsFailed {
    errors: Vec<anyhow::Error>,
}

impl std::fmt::Display for AttemptsFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, err) in self.errors.iter().enumerate() {
            writeln!(f, "{i}. {err}")?;
            for cause in err.chain().skip(1) {
                writeln!(f, "     because: {cause}")?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for AttemptsFailed {}

pub fn openapi_from_file(filename: &Path) -> Result<Spec> {
    let file_contents = std::fs::read_to_string(filename)?;
    let mut errors = Vec::new();

    match oas3::from_yaml(&file_contents).context("Failed to parse as YAML OpenAPI v3.1") {
        Ok(spec) => {
            return Ok(spec.into());
        }
        Err(err) => errors.push(err),
    };
    match oas3::from_json(&file_contents).context("Failed to parse as JSON OpenAPI v3.1") {
        Ok(spec) => return Ok(spec.into()),
        Err(err) => errors.push(err),
    };

    match serde_yaml::from_str::<VersionedOpenAPI>(&file_contents)
        .context("Failed to parse as YAML OpenAPI v2/v3.0")
    {
        Ok(spec) => {
            return Ok(spec.upgrade().into());
        }
        Err(err) => errors.push(err),
    };

    match serde_json::from_str::<VersionedOpenAPI>(&file_contents)
        .context("Failed to parse as JSON OpenAPI v2/v3.0")
    {
        Ok(spec) => return Ok(spec.upgrade().into()),
        Err(err) => errors.push(err),
    };
    Err(AttemptsFailed { errors }.into())
}

/// Loads the OpenAPI specification from the given path
pub fn get_api_spec(path: &Path) -> Result<Box<Spec>, anyhow::Error> {
    openapi_from_file(path)
        .map(Box::new)
        .with_context(|| format!("Error parsing OpenAPI-file at {}", path.to_string_lossy()))
}
