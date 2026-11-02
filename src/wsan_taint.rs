//! Which parameters of each request path reach a sink, learned while fuzzing.
//! The executor fills it: when a value it sent shows up in the sink SQL of the
//! `X-WSan-Sinks` header, that parameter reaches the sink.
//! SqlBreakTargetedMutator reads it to break only those parameters.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// For each path, the parameters that reach a sink and that sink's CWE.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct WsanTaintMap {
    /// path -> (parameter name -> CWE of the sink it reaches).
    paths: HashMap<String, HashMap<String, u32>>,
}

libafl_bolts::impl_serdeany!(WsanTaintMap);

impl WsanTaintMap {
    /// Record that `name`, sent to `path`, reached a sink with CWE `cwe`.
    /// Returns true the first time this (path, name, cwe) is learned.
    pub fn mark(&mut self, path: &str, name: &str, cwe: u32) -> bool {
        self.paths
            .entry(path.to_owned())
            .or_default()
            .insert(name.to_owned(), cwe)
            .is_none()
    }

    /// The tainted parameters for `path` (name -> CWE), if any.
    pub fn tainted(&self, path: &str) -> Option<&HashMap<String, u32>> {
        self.paths.get(path)
    }
}

#[cfg(test)]
mod tests {
    use super::WsanTaintMap;

    #[test]
    fn mark_reports_only_new_taint() {
        let mut m = WsanTaintMap::default();
        assert!(m.mark("/p", "foo", 89));
        assert!(!m.mark("/p", "foo", 89));
        assert_eq!(m.tainted("/p").unwrap().get("foo"), Some(&89));
        assert!(m.tainted("/q").is_none());
    }
}
