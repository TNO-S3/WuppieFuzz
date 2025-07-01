#![allow(dead_code)]

/// Helper type to allow components to write to the debug log using the Write
/// interface. Only outputs its data when it is dropped, since the debug log
/// inserts decoration at the start of each line, and users of `write` are not
/// obliged to write entire lines.
pub struct DebugWriter {
    buf: String,
}

impl DebugWriter {
    pub fn new() -> Self {
        Self { buf: String::new() }
    }
}

impl Default for DebugWriter {
    fn default() -> Self {
        DebugWriter::new()
    }
}

impl std::io::Write for DebugWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf += &String::from_utf8_lossy(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for DebugWriter {
    fn drop(&mut self) {
        for line in self.buf.lines() {
            log::debug!("{line}");
        }
    }
}
