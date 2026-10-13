//! Translates OTel spans into the shared coverage bitmap: distinct span types and
//! parent/child span edges are each assigned a bit, discovered on first sight.

use std::{
    collections::{HashMap, hash_map::Entry},
    sync::{Arc, Mutex},
};

use super::types::{OtelSpanKind, ParsedSpan};
use crate::coverage_clients::MAP_SIZE;

pub(crate) type SharedCoverageState = Arc<Mutex<OtelCoverageState>>;

pub(crate) fn new_shared_coverage_state() -> SharedCoverageState {
    Arc::new(Mutex::new(OtelCoverageState::default()))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SpanKey {
    pub(crate) service_namespace: Option<String>,
    pub(crate) service: String,
    pub(crate) kind: OtelSpanKind,
    pub(crate) operation: String,
}

impl SpanKey {
    pub(crate) fn from_span(span: &ParsedSpan) -> Self {
        Self {
            service_namespace: span.service_namespace.clone(),
            service: span.service.clone(),
            kind: span.kind,
            operation: normalized_operation(span),
        }
    }

    pub(crate) fn display(&self) -> String {
        let service = match &self.service_namespace {
            Some(namespace) if !namespace.is_empty() => {
                format!("{namespace}/{}", self.service)
            }
            _ => self.service.clone(),
        };
        format!("{} [{}] {}", service, self.kind.as_str(), self.operation)
    }
}

fn normalized_operation(span: &ParsedSpan) -> String {
    if let Some(method) = span
        .rpc_method
        .as_deref()
        .filter(|method| !method.is_empty())
    {
        return match span
            .rpc_system_name
            .as_deref()
            .filter(|system| !system.is_empty())
        {
            Some(system) => format!("RPC {system} {method}"),
            None => format!("RPC {method}"),
        };
    }

    if let Some(method) = span
        .http_request_method
        .as_deref()
        .filter(|method| !method.is_empty())
    {
        if span.kind == OtelSpanKind::Server {
            return match span.http_route.as_deref().filter(|route| !route.is_empty()) {
                Some(route) => format!("HTTP {method} {route}"),
                None => format!("HTTP {method}"),
            };
        }

        if span.kind == OtelSpanKind::Client {
            return match span
                .url_template
                .as_deref()
                .filter(|template| !template.is_empty())
            {
                Some(template) => format!("HTTP {method} {template}"),
                None => format!("HTTP {method}"),
            };
        }

        if let Some(route) = span.http_route.as_deref().filter(|route| !route.is_empty()) {
            return format!("HTTP {method} {route}");
        }

        if let Some(template) = span
            .url_template
            .as_deref()
            .filter(|template| !template.is_empty())
        {
            return format!("HTTP {method} {template}");
        }

        return format!("HTTP {method}");
    }

    if span.name.is_empty() {
        "unknown_operation".to_owned()
    } else {
        span.name.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct EdgeKey {
    pub(crate) parent: SpanKey,
    pub(crate) child: SpanKey,
}

impl EdgeKey {
    pub(crate) fn new(parent: SpanKey, child: SpanKey) -> Self {
        Self { parent, child }
    }
}

#[derive(Debug)]
pub(crate) struct OtelCoverageState {
    cov_map: Box<[u8; 2 * MAP_SIZE]>,
    span_index: HashMap<SpanKey, usize>,
    first_unused_span_idx: usize,
    pub(crate) span_names: Vec<SpanKey>,
    edge_index: HashMap<EdgeKey, usize>,
    first_unused_edge_idx: usize,
    pub(crate) edge_names: Vec<EdgeKey>,
}

impl Default for OtelCoverageState {
    fn default() -> Self {
        Self {
            cov_map: Box::new([0u8; 2 * MAP_SIZE]),
            span_index: HashMap::new(),
            first_unused_span_idx: 0,
            span_names: Vec::new(),
            edge_index: HashMap::new(),
            first_unused_edge_idx: 0,
            edge_names: Vec::new(),
        }
    }
}

impl OtelCoverageState {
    fn get_or_assign_span_idx(&mut self, key: SpanKey) -> (Option<usize>, bool) {
        match self.span_index.entry(key.clone()) {
            Entry::Occupied(entry) => (Some(*entry.get()), false),
            Entry::Vacant(entry) => {
                if self.first_unused_span_idx >= MAP_SIZE {
                    log::warn!(
                        "OTel span bitmap overflow: more than {MAP_SIZE} unique span types seen; consider increasing MAP_SIZE"
                    );
                    return (None, false);
                }

                let idx = self.first_unused_span_idx;
                self.first_unused_span_idx += 1;
                self.span_names.push(key);
                entry.insert(idx);
                (Some(idx), true)
            }
        }
    }

    fn get_or_assign_edge_idx(&mut self, key: EdgeKey) -> (Option<usize>, bool) {
        match self.edge_index.entry(key.clone()) {
            Entry::Occupied(entry) => (Some(*entry.get()), false),
            Entry::Vacant(entry) => {
                if self.first_unused_edge_idx >= MAP_SIZE {
                    log::warn!(
                        "OTel edge bitmap overflow: more than {MAP_SIZE} unique span edges seen; consider increasing MAP_SIZE"
                    );
                    return (None, false);
                }

                let idx = self.first_unused_edge_idx;
                self.first_unused_edge_idx += 1;
                self.edge_names.push(key);
                entry.insert(idx);
                (Some(idx), true)
            }
        }
    }

    pub(crate) fn span_key_count(&self) -> usize {
        self.span_names.len()
    }

    pub(crate) fn edge_key_count(&self) -> usize {
        self.edge_names.len()
    }

    pub(crate) fn apply_span_key(&mut self, key: SpanKey) -> bool {
        let (maybe_idx, was_new) = self.get_or_assign_span_idx(key);
        if let Some(idx) = maybe_idx {
            self.cov_map[idx] = 1;
        }
        was_new
    }

    pub(crate) fn apply_edge_key(&mut self, key: EdgeKey) -> bool {
        let (maybe_idx, was_new) = self.get_or_assign_edge_idx(key);
        if let Some(idx) = maybe_idx {
            self.cov_map[MAP_SIZE + idx] = 1;
        }
        was_new
    }

    #[cfg(test)]
    pub(crate) fn apply_spans(&mut self, spans: Vec<ParsedSpan>) -> bool {
        let mut novel = false;
        let span_id_map: HashMap<&str, SpanKey> = spans
            .iter()
            .map(|span| (span.span_id.as_str(), SpanKey::from_span(span)))
            .collect();

        for span in &spans {
            let span_key = SpanKey::from_span(span);
            novel |= self.apply_span_key(span_key.clone());

            if span.parent_span_id.is_empty() {
                continue;
            }

            if let Some(parent_key) = span_id_map.get(span.parent_span_id.as_str()) {
                novel |= self.apply_edge_key(EdgeKey::new(parent_key.clone(), span_key));
            }
        }

        novel
    }

    pub(crate) fn coverage_ratio(&self) -> (u64, u64) {
        ((self.span_index.len() + self.edge_index.len()) as u64, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(service: &str, name: &str, span_id: &str, parent_span_id: &str) -> ParsedSpan {
        ParsedSpan {
            service_namespace: None,
            service: service.to_owned(),
            name: name.to_owned(),
            kind: OtelSpanKind::Internal,
            http_request_method: None,
            http_route: None,
            url_template: None,
            rpc_system_name: None,
            rpc_method: None,
            trace_id: "trace".to_owned(),
            span_id: span_id.to_owned(),
            parent_span_id: parent_span_id.to_owned(),
            start_time_unix_nano: 0,
            end_time_unix_nano: 1,
        }
    }

    #[test]
    fn apply_spans_sets_span_byte_to_one() {
        let mut state = OtelCoverageState::default();
        state.apply_spans(vec![span("webgoat", "GET /login", "s1", "")]);

        let idx = state.span_index[&span_key("webgoat", OtelSpanKind::Internal, "GET /login")];
        assert_eq!(state.cov_map[idx], 1);
    }

    #[test]
    fn apply_spans_different_operations_get_different_byte_indices() {
        let mut state = OtelCoverageState::default();
        state.apply_spans(vec![
            span("webgoat", "GET /login", "s1", ""),
            span("webgoat", "POST /api/user", "s2", ""),
        ]);

        let idx_a = state.span_index[&span_key("webgoat", OtelSpanKind::Internal, "GET /login")];
        let idx_b =
            state.span_index[&span_key("webgoat", OtelSpanKind::Internal, "POST /api/user")];
        assert_ne!(idx_a, idx_b);
    }

    #[test]
    fn apply_spans_sets_edge_byte_for_known_parent() {
        let mut state = OtelCoverageState::default();
        state.apply_spans(vec![
            span("webgoat", "root-op", "s1", ""),
            span("webgoat", "child-op", "s2", "s1"),
        ]);

        let edge_idx = state.edge_index[&EdgeKey::new(
            span_key("webgoat", OtelSpanKind::Internal, "root-op"),
            span_key("webgoat", OtelSpanKind::Internal, "child-op"),
        )];
        assert_eq!(state.cov_map[MAP_SIZE + edge_idx], 1);
    }

    #[test]
    fn server_http_route_defines_operation_instead_of_raw_span_name() {
        let mut state = OtelCoverageState::default();
        let mut first = span("svc", "GET /users/123", "s1", "");
        first.kind = OtelSpanKind::Server;
        first.http_request_method = Some("GET".to_owned());
        first.http_route = Some("/users/{id}".to_owned());

        let mut second = span("svc", "GET /users/456", "s2", "");
        second.kind = OtelSpanKind::Server;
        second.http_request_method = Some("GET".to_owned());
        second.http_route = Some("/users/{id}".to_owned());

        assert!(state.apply_spans(vec![first]));
        assert!(!state.apply_spans(vec![second]));
        assert!(state.span_index.contains_key(&span_key(
            "svc",
            OtelSpanKind::Server,
            "HTTP GET /users/{id}"
        )));
    }

    #[test]
    fn span_kind_distinguishes_same_operation_name() {
        let mut state = OtelCoverageState::default();
        let mut server = span("svc", "GET /users", "s1", "");
        server.kind = OtelSpanKind::Server;
        let mut client = span("svc", "GET /users", "s2", "");
        client.kind = OtelSpanKind::Client;

        assert!(state.apply_spans(vec![server]));
        assert!(state.apply_spans(vec![client]));
        assert_eq!(state.coverage_ratio(), (2, 0));
    }

    #[test]
    fn apply_spans_returns_true_only_for_new_coverage() {
        let mut state = OtelCoverageState::default();
        assert!(state.apply_spans(vec![span("svc", "op", "s1", "")]));
        assert!(!state.apply_spans(vec![span("svc", "op", "s2", "")]));
    }

    #[test]
    fn max_coverage_ratio_counts_spans_and_edges() {
        let mut state = OtelCoverageState::default();
        state.apply_spans(vec![
            span("svc", "op-a", "s1", ""),
            span("svc", "op-b", "s2", "s1"),
        ]);
        let (covered, total) = state.coverage_ratio();
        assert_eq!(covered, 3);
        assert_eq!(total, 0);
    }

    fn span_key(service: &str, kind: OtelSpanKind, operation: &str) -> SpanKey {
        SpanKey {
            service_namespace: None,
            service: service.to_owned(),
            kind,
            operation: operation.to_owned(),
        }
    }
}
