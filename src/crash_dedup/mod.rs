mod identity;
pub mod replay;

use std::path::Path;

use anyhow::Result;

use crate::configuration::Configuration;

pub fn dedup_crashes(crash_directory: &Path, output_directory: &Path) -> Result<()> {
    let config = Configuration::get().map_err(anyhow::Error::msg)?;
    crate::setup_logging(config);

    bail!(
        "Crash deduplication not yet implemented (input: {}, output: {})",
        crash_directory.display(),
        output_directory.display()
    )
}
