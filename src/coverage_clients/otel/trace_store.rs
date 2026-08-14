use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use crate::input::OpenApiInput;

use super::{
    coverage::{EdgeKey, OtelCoverageState, SpanKey},
    types::{ParsedSpan, PromotionCandidate},
};

const MAX_BUFFERED_ORPHAN_TRACES: usize = 10_000;
const MAX_BUFFERED_ORPHAN_SPANS: usize = 50_000;

#[derive(Debug)]
struct SequenceState {
    trace_id: String,
    expected_parent_ids: HashSet<String>,
    seen_parent_ids: HashSet<String>,
    observed_parent_ids: HashSet<String>,
    spans_by_id: HashMap<String, SpanKey>,
    pending_children_by_parent_id: HashMap<String, Vec<SpanKey>>,
    started_at: Instant,
    finished_at: Option<Instant>,
    last_update: Instant,
    last_span_at: Option<Instant>,
    input: OpenApiInput,
    submission_id: u64,
    spans_seen: usize,
    novelty_seen: bool,
    promotion_emitted: bool,
}

impl SequenceState {
    fn new(trace_id: String, submission_id: u64, input: OpenApiInput, started_at: Instant) -> Self {
        Self {
            trace_id,
            expected_parent_ids: HashSet::new(),
            seen_parent_ids: HashSet::new(),
            observed_parent_ids: HashSet::new(),
            spans_by_id: HashMap::new(),
            pending_children_by_parent_id: HashMap::new(),
            started_at,
            finished_at: None,
            last_update: started_at,
            last_span_at: None,
            input,
            submission_id,
            spans_seen: 0,
            novelty_seen: false,
            promotion_emitted: false,
        }
    }

    fn register_parent_id(&mut self, parent_id: String, now: Instant) -> RootRegistrationResult {
        self.last_update = now;
        if !self.expected_parent_ids.insert(parent_id.clone()) {
            return RootRegistrationResult::Duplicate;
        }

        if self.observed_parent_ids.contains(&parent_id) && self.seen_parent_ids.insert(parent_id) {
            RootRegistrationResult::RegisteredAfterSpan
        } else {
            RootRegistrationResult::Registered
        }
    }

    fn finish(&mut self, now: Instant) {
        self.finished_at = Some(now);
        self.last_update = now;
    }

    fn process_span(
        &mut self,
        span: ParsedSpan,
        coverage_state: &mut OtelCoverageState,
        now: Instant,
    ) -> SpanProcessResult {
        self.last_update = now;
        self.last_span_at = Some(now);
        self.spans_seen += 1;

        if !span.parent_span_id.is_empty() {
            self.observed_parent_ids.insert(span.parent_span_id.clone());
        }

        let newly_seen_root = self.expected_parent_ids.contains(&span.parent_span_id)
            && self.seen_parent_ids.insert(span.parent_span_id.clone());

        if self.spans_by_id.contains_key(&span.span_id) {
            return SpanProcessResult { newly_seen_root };
        }

        let span_key = SpanKey::from_span(&span);
        let mut novelty_events = 0;
        if coverage_state.apply_span_key(span_key.clone()) {
            novelty_events += 1;
        }

        if !span.parent_span_id.is_empty() {
            if let Some(parent_key) = self.spans_by_id.get(&span.parent_span_id) {
                if coverage_state.apply_edge_key(EdgeKey::new(parent_key.clone(), span_key.clone()))
                {
                    novelty_events += 1;
                }
            } else {
                self.pending_children_by_parent_id
                    .entry(span.parent_span_id.clone())
                    .or_default()
                    .push(span_key.clone());
            }
        }

        self.spans_by_id
            .insert(span.span_id.clone(), span_key.clone());

        if let Some(children) = self.pending_children_by_parent_id.remove(&span.span_id) {
            for child_key in children {
                if coverage_state.apply_edge_key(EdgeKey::new(span_key.clone(), child_key)) {
                    novelty_events += 1;
                }
            }
        }

        if novelty_events > 0 {
            self.novelty_seen = true;
        }

        SpanProcessResult { newly_seen_root }
    }

    fn maybe_promotion(&mut self, _now: Instant) -> Option<PromotionCandidate> {
        if !self.novelty_seen || self.promotion_emitted {
            return None;
        }

        self.promotion_emitted = true;
        Some(PromotionCandidate {
            submission_id: self.submission_id,
            input: self.input.clone(),
        })
    }

    fn expected_parent_count(&self) -> usize {
        self.expected_parent_ids.len()
    }

    fn seen_parent_count(&self) -> usize {
        self.seen_parent_ids.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootRegistrationResult {
    Registered,
    RegisteredAfterSpan,
    Duplicate,
}

#[derive(Default)]
struct SpanProcessResult {
    newly_seen_root: bool,
}

pub(crate) enum TraceStoreEvent {
    SequenceStarted,
    DuplicateSequenceStart,
    RequestRootRegistered,
    RequestRootRegisteredAfterSpan,
    RequestRootUnknownTrace,
    SequenceFinished,
    SequenceFinishUnknownTrace,
    OrphanSpan,
    OrphanSpanBuffered,
    OrphanSpanReassociated,
    OrphanSpanExpired,
    OrphanSpanCapacityDropped,
    LateAfterEviction,
    RootSeen,
    Evicted {
        trace_id: String,
        expected_parent_ids: usize,
        seen_parent_ids: usize,
        lifetime: Duration,
        was_novel: bool,
        reason: EvictionReason,
    },
    Promotion {
        trace_id: String,
        candidate: PromotionCandidate,
    },
    NonNovel {
        trace_id: String,
        expected_parent_ids: usize,
        seen_parent_ids: usize,
    },
    Dropped {
        trace_id: String,
        expected_parent_ids: usize,
        seen_parent_ids: usize,
        waited: Duration,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvictionReason {
    Age,
    Capacity,
}

struct OrphanTrace {
    spans: Vec<ParsedSpan>,
    first_seen: Instant,
    last_update: Instant,
}

#[derive(Default)]
pub(crate) struct TraceStore {
    sequences: HashMap<String, SequenceState>,
    seen_trace_ids: HashSet<String>,
    evicted_trace_ids: HashMap<String, EvictionReason>,
    orphan_traces: HashMap<String, OrphanTrace>,
    buffered_orphan_spans: usize,
}

impl TraceStore {
    pub(crate) fn start_sequence(
        &mut self,
        trace_id: String,
        submission_id: u64,
        input: OpenApiInput,
        coverage_state: &mut OtelCoverageState,
    ) -> Vec<TraceStoreEvent> {
        let now = Instant::now();
        self.seen_trace_ids.insert(trace_id.clone());

        let mut events = Vec::new();
        if let Some(replaced) = self.sequences.remove(&trace_id) {
            log::warn!("Replacing active OTel sequence state for duplicate trace {trace_id}");
            events.push(TraceStoreEvent::DuplicateSequenceStart);
            events.extend(self.evict_state(replaced, now, EvictionReason::Capacity));
        }

        let mut state = SequenceState::new(trace_id.clone(), submission_id, input, now);
        events.push(TraceStoreEvent::SequenceStarted);

        if let Some(orphan_trace) = self.orphan_traces.remove(&trace_id) {
            self.buffered_orphan_spans = self
                .buffered_orphan_spans
                .saturating_sub(orphan_trace.spans.len());
            for span in orphan_trace.spans {
                events.push(TraceStoreEvent::OrphanSpanReassociated);
                let result = state.process_span(span, coverage_state, now);
                Self::push_span_events(&mut events, result);
                if let Some(candidate) = state.maybe_promotion(now) {
                    events.push(TraceStoreEvent::Promotion {
                        trace_id: trace_id.clone(),
                        candidate,
                    });
                }
            }
        }

        self.sequences.insert(trace_id, state);
        events
    }

    pub(crate) fn register_request_root(
        &mut self,
        trace_id: String,
        parent_id: String,
    ) -> Vec<TraceStoreEvent> {
        let now = Instant::now();
        self.seen_trace_ids.insert(trace_id.clone());

        let Some(state) = self.sequences.get_mut(&trace_id) else {
            log::debug!(
                "Ignoring OTel request root registration for unknown trace {trace_id}; sequence was not active"
            );
            return vec![TraceStoreEvent::RequestRootUnknownTrace];
        };

        match state.register_parent_id(parent_id, now) {
            RootRegistrationResult::Registered => vec![TraceStoreEvent::RequestRootRegistered],
            RootRegistrationResult::RegisteredAfterSpan => vec![
                TraceStoreEvent::RequestRootRegistered,
                TraceStoreEvent::RequestRootRegisteredAfterSpan,
                TraceStoreEvent::RootSeen,
            ],
            RootRegistrationResult::Duplicate => Vec::new(),
        }
    }

    pub(crate) fn finish_sequence(&mut self, trace_id: String) -> Vec<TraceStoreEvent> {
        let now = Instant::now();
        self.seen_trace_ids.insert(trace_id.clone());

        let Some(state) = self.sequences.get_mut(&trace_id) else {
            log::debug!(
                "Ignoring OTel sequence finish for unknown trace {trace_id}; sequence was not active"
            );
            return vec![TraceStoreEvent::SequenceFinishUnknownTrace];
        };

        state.finish(now);
        vec![TraceStoreEvent::SequenceFinished]
    }

    pub(crate) fn ingest_spans(
        &mut self,
        spans: Vec<ParsedSpan>,
        coverage_state: &mut OtelCoverageState,
    ) -> Vec<TraceStoreEvent> {
        let mut events = Vec::new();
        let now = Instant::now();

        for span in spans {
            let trace_id = span.trace_id.clone();
            self.seen_trace_ids.insert(trace_id.clone());

            if let Some(state) = self.sequences.get_mut(&trace_id) {
                let result = state.process_span(span, coverage_state, now);
                Self::push_span_events(&mut events, result);
                if let Some(candidate) = state.maybe_promotion(now) {
                    events.push(TraceStoreEvent::Promotion {
                        trace_id,
                        candidate,
                    });
                }
                continue;
            }

            if self.evicted_trace_ids.contains_key(&trace_id) {
                events.push(TraceStoreEvent::LateAfterEviction);
            } else {
                self.buffer_orphan_span(trace_id, span, now, &mut events);
            }
        }

        events
    }

    pub(crate) fn drain_timeouts(
        &mut self,
        retention_window: Duration,
        max_active_sequences: usize,
    ) -> Vec<TraceStoreEvent> {
        let now = Instant::now();
        let mut expired_orphan_trace_ids = Vec::new();
        for (trace_id, orphan_trace) in &self.orphan_traces {
            if now.duration_since(orphan_trace.last_update) >= retention_window {
                expired_orphan_trace_ids.push(trace_id.clone());
            }
        }

        let mut events = Vec::new();
        for trace_id in expired_orphan_trace_ids {
            if let Some(orphan_trace) = self.orphan_traces.remove(&trace_id) {
                self.buffered_orphan_spans = self
                    .buffered_orphan_spans
                    .saturating_sub(orphan_trace.spans.len());
                for _ in orphan_trace.spans {
                    events.push(TraceStoreEvent::OrphanSpan);
                    events.push(TraceStoreEvent::OrphanSpanExpired);
                }
            }
        }

        let mut evict_trace_ids = Vec::new();

        for (trace_id, state) in &self.sequences {
            let should_evict = if let Some(finished_at) = state.finished_at {
                now.duration_since(finished_at) >= retention_window
            } else {
                now.duration_since(state.started_at) >= retention_window
            };

            if should_evict {
                evict_trace_ids.push(trace_id.clone());
            }
        }

        for trace_id in evict_trace_ids {
            let Some(state) = self.sequences.remove(&trace_id) else {
                continue;
            };
            events.extend(self.evict_state(state, now, EvictionReason::Age));
        }

        if self.sequences.len() > max_active_sequences {
            let overflow = self.sequences.len() - max_active_sequences;
            let mut candidates: Vec<_> = self
                .sequences
                .iter()
                .map(|(trace_id, state)| {
                    let priority = match (state.finished_at.is_some(), state.promotion_emitted) {
                        (true, false) => 0,
                        (true, true) => 1,
                        (false, _) => 2,
                    };
                    (trace_id.clone(), priority, state.last_update)
                })
                .collect();
            candidates.sort_by_key(|(_, priority, last_update)| (*priority, *last_update));

            for (trace_id, _, _) in candidates.into_iter().take(overflow) {
                let Some(state) = self.sequences.remove(&trace_id) else {
                    continue;
                };
                events.extend(self.evict_state(state, now, EvictionReason::Capacity));
            }
        }

        events
    }

    #[cfg(test)]
    pub(crate) fn pending_count(&self) -> usize {
        self.sequences.len()
    }

    #[cfg(test)]
    pub(crate) fn active_open_count(&self) -> usize {
        self.sequences
            .values()
            .filter(|state| state.finished_at.is_none())
            .count()
    }

    #[cfg(test)]
    pub(crate) fn buffered_orphan_span_count(&self) -> usize {
        self.buffered_orphan_spans
    }

    fn buffer_orphan_span(
        &mut self,
        trace_id: String,
        span: ParsedSpan,
        now: Instant,
        events: &mut Vec<TraceStoreEvent>,
    ) {
        while self.buffered_orphan_spans >= MAX_BUFFERED_ORPHAN_SPANS
            || (!self.orphan_traces.contains_key(&trace_id)
                && self.orphan_traces.len() >= MAX_BUFFERED_ORPHAN_TRACES)
        {
            let Some(oldest_trace_id) = self.oldest_orphan_trace_id() else {
                break;
            };
            if let Some(orphan_trace) = self.orphan_traces.remove(&oldest_trace_id) {
                self.buffered_orphan_spans = self
                    .buffered_orphan_spans
                    .saturating_sub(orphan_trace.spans.len());
                for _ in orphan_trace.spans {
                    events.push(TraceStoreEvent::OrphanSpan);
                    events.push(TraceStoreEvent::OrphanSpanCapacityDropped);
                }
            }
        }

        let orphan_trace = self
            .orphan_traces
            .entry(trace_id)
            .or_insert_with(|| OrphanTrace {
                spans: Vec::new(),
                first_seen: now,
                last_update: now,
            });
        orphan_trace.last_update = now;
        orphan_trace.spans.push(span);
        self.buffered_orphan_spans = self.buffered_orphan_spans.saturating_add(1);
        events.push(TraceStoreEvent::OrphanSpanBuffered);
    }

    fn oldest_orphan_trace_id(&self) -> Option<String> {
        self.orphan_traces
            .iter()
            .min_by_key(|(_, orphan_trace)| orphan_trace.first_seen)
            .map(|(trace_id, _)| trace_id.clone())
    }

    fn evict_state(
        &mut self,
        state: SequenceState,
        now: Instant,
        reason: EvictionReason,
    ) -> Vec<TraceStoreEvent> {
        let trace_id = state.trace_id.clone();
        self.evicted_trace_ids.insert(trace_id.clone(), reason);

        let expected_parent_ids = state.expected_parent_count();
        let seen_parent_ids = state.seen_parent_count();
        let lifetime = now.duration_since(state.started_at);
        let mut events = vec![TraceStoreEvent::Evicted {
            trace_id: trace_id.clone(),
            expected_parent_ids,
            seen_parent_ids,
            lifetime,
            was_novel: state.novelty_seen,
            reason,
        }];

        if state.novelty_seen {
            return events;
        }

        if state.spans_seen == 0 {
            events.push(TraceStoreEvent::Dropped {
                trace_id,
                expected_parent_ids,
                seen_parent_ids,
                waited: lifetime,
            });
        } else {
            events.push(TraceStoreEvent::NonNovel {
                trace_id,
                expected_parent_ids,
                seen_parent_ids,
            });
        }

        events
    }

    fn push_span_events(events: &mut Vec<TraceStoreEvent>, result: SpanProcessResult) {
        if result.newly_seen_root {
            events.push(TraceStoreEvent::RootSeen);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage_clients::otel::{coverage::OtelCoverageState, types::OtelSpanKind};

    fn span(
        trace_id: &str,
        service: &str,
        name: &str,
        span_id: &str,
        parent_span_id: &str,
    ) -> ParsedSpan {
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
            trace_id: trace_id.to_owned(),
            span_id: span_id.to_owned(),
            parent_span_id: parent_span_id.to_owned(),
            start_time_unix_nano: 0,
            end_time_unix_nano: 1,
        }
    }

    fn start(
        store: &mut TraceStore,
        coverage: &mut OtelCoverageState,
        trace_id: &str,
    ) -> Vec<TraceStoreEvent> {
        store.start_sequence(trace_id.to_owned(), 1, OpenApiInput(vec![]), coverage)
    }

    fn register(store: &mut TraceStore, trace_id: &str, parent_id: &str) -> Vec<TraceStoreEvent> {
        store.register_request_root(trace_id.to_owned(), parent_id.to_owned())
    }

    fn finish(store: &mut TraceStore, trace_id: &str) -> Vec<TraceStoreEvent> {
        store.finish_sequence(trace_id.to_owned())
    }

    fn has_promotion(events: &[TraceStoreEvent]) -> bool {
        events
            .iter()
            .any(|event| matches!(event, TraceStoreEvent::Promotion { .. }))
    }

    #[test]
    fn started_sequence_processes_spans_before_finish() {
        let mut store = TraceStore::default();
        let mut coverage = OtelCoverageState::default();

        start(&mut store, &mut coverage, "trace-1");
        register(&mut store, "trace-1", "parent-1");
        let events = store.ingest_spans(
            vec![span("trace-1", "svc", "root", "child", "parent-1")],
            &mut coverage,
        );

        assert!(has_promotion(&events));
        assert_eq!(store.active_open_count(), 1);
    }

    #[test]
    fn closed_sequence_evicts_after_retention_window() {
        let mut store = TraceStore::default();
        let mut coverage = OtelCoverageState::default();

        start(&mut store, &mut coverage, "trace-1");
        store.ingest_spans(
            vec![span("trace-1", "svc", "root", "root-span", "parent-1")],
            &mut coverage,
        );
        finish(&mut store, "trace-1");
        std::thread::sleep(Duration::from_millis(5));

        assert!(
            store
                .drain_timeouts(Duration::from_millis(1), 100)
                .into_iter()
                .any(|event| matches!(
                    event,
                    TraceStoreEvent::Evicted {
                        reason: EvictionReason::Age,
                        ..
                    }
                ))
        );
        assert_eq!(store.pending_count(), 0);
    }

    #[test]
    fn closed_sequence_stays_active_before_retention_window() {
        let mut store = TraceStore::default();
        let mut coverage = OtelCoverageState::default();

        start(&mut store, &mut coverage, "trace-1");
        store.ingest_spans(
            vec![span("trace-1", "svc", "root", "root-span", "parent-1")],
            &mut coverage,
        );
        finish(&mut store, "trace-1");
        std::thread::sleep(Duration::from_millis(5));

        assert!(
            store
                .drain_timeouts(Duration::from_secs(60), 100)
                .is_empty()
        );
        assert_eq!(store.pending_count(), 1);
    }

    #[test]
    fn capacity_eviction_drops_oldest_closed_sequence_first() {
        let mut store = TraceStore::default();
        let mut coverage = OtelCoverageState::default();

        start(&mut store, &mut coverage, "trace-1");
        finish(&mut store, "trace-1");
        std::thread::sleep(Duration::from_millis(1));
        start(&mut store, &mut coverage, "trace-2");
        finish(&mut store, "trace-2");
        start(&mut store, &mut coverage, "trace-3");

        let events = store.drain_timeouts(Duration::from_secs(60), 2);

        assert!(
            events
                .iter()
                .any(|event| matches!(event, TraceStoreEvent::Evicted { trace_id, reason: EvictionReason::Capacity, .. } if trace_id == "trace-1"))
        );
        assert_eq!(store.pending_count(), 2);
    }

    #[test]
    fn late_span_after_eviction_is_counted_and_ignored_for_guidance() {
        let mut store = TraceStore::default();
        let mut coverage = OtelCoverageState::default();

        start(&mut store, &mut coverage, "trace-1");
        finish(&mut store, "trace-1");
        std::thread::sleep(Duration::from_millis(5));
        store.drain_timeouts(Duration::from_millis(1), 100);

        let events = store.ingest_spans(
            vec![span("trace-1", "svc", "late", "late-span", "parent-1")],
            &mut coverage,
        );

        assert!(
            events
                .iter()
                .any(|event| matches!(event, TraceStoreEvent::LateAfterEviction))
        );
        assert!(!has_promotion(&events));
        assert_eq!(coverage.coverage_ratio(), (0, 0));
    }

    #[test]
    fn orphan_span_is_buffered_before_sequence_start() {
        let mut store = TraceStore::default();
        let mut coverage = OtelCoverageState::default();

        let events = store.ingest_spans(
            vec![span("trace-1", "svc", "root", "root-span", "parent-1")],
            &mut coverage,
        );

        assert!(
            events
                .iter()
                .any(|event| matches!(event, TraceStoreEvent::OrphanSpanBuffered))
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, TraceStoreEvent::OrphanSpan))
        );
        assert!(!has_promotion(&events));
    }

    #[test]
    fn buffered_orphan_span_reassociates_on_sequence_start() {
        let mut store = TraceStore::default();
        let mut coverage = OtelCoverageState::default();

        store.ingest_spans(
            vec![span("trace-1", "svc", "root", "root-span", "parent-1")],
            &mut coverage,
        );
        let events = start(&mut store, &mut coverage, "trace-1");

        assert!(
            events
                .iter()
                .any(|event| matches!(event, TraceStoreEvent::OrphanSpanReassociated))
        );
        assert!(has_promotion(&events));
        assert_eq!(coverage.coverage_ratio(), (1, 0));
    }

    #[test]
    fn buffered_orphan_span_expires_as_true_orphan() {
        let mut store = TraceStore::default();
        let mut coverage = OtelCoverageState::default();

        store.ingest_spans(
            vec![span("trace-1", "svc", "root", "root-span", "parent-1")],
            &mut coverage,
        );
        std::thread::sleep(Duration::from_millis(5));
        let events = store.drain_timeouts(Duration::from_millis(1), 100);

        assert!(
            events
                .iter()
                .any(|event| matches!(event, TraceStoreEvent::OrphanSpan))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, TraceStoreEvent::OrphanSpanExpired))
        );
    }

    #[test]
    fn capacity_dropped_orphan_span_counts_as_orphan_loss() {
        let mut store = TraceStore::default();
        let mut coverage = OtelCoverageState::default();

        let mut events = Vec::new();
        for index in 0..=MAX_BUFFERED_ORPHAN_TRACES {
            events.extend(store.ingest_spans(
                vec![span(
                    &format!("trace-{index}"),
                    "svc",
                    "root",
                    &format!("root-span-{index}"),
                    "parent-1",
                )],
                &mut coverage,
            ));
        }

        assert!(
            events
                .iter()
                .any(|event| matches!(event, TraceStoreEvent::OrphanSpan))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, TraceStoreEvent::OrphanSpanCapacityDropped))
        );
        assert_eq!(
            store.buffered_orphan_span_count(),
            MAX_BUFFERED_ORPHAN_TRACES
        );
    }

    #[test]
    fn promoted_sequence_learns_later_novelty_without_duplicate_promotion() {
        let mut store = TraceStore::default();
        let mut coverage = OtelCoverageState::default();

        start(&mut store, &mut coverage, "trace-1");
        register(&mut store, "trace-1", "parent-1");
        let first_events = store.ingest_spans(
            vec![span("trace-1", "svc", "root", "root-span", "parent-1")],
            &mut coverage,
        );
        assert!(has_promotion(&first_events));
        finish(&mut store, "trace-1");

        let late_events = store.ingest_spans(
            vec![span("trace-1", "svc", "late-child", "child", "root-span")],
            &mut coverage,
        );

        assert!(!has_promotion(&late_events));
        assert_eq!(coverage.coverage_ratio(), (3, 0));
    }

    #[test]
    fn multiple_request_roots_learn_multiple_novelties_with_one_promotion() {
        let mut store = TraceStore::default();
        let mut coverage = OtelCoverageState::default();

        start(&mut store, &mut coverage, "trace-1");
        register(&mut store, "trace-1", "request-parent-1");
        register(&mut store, "trace-1", "request-parent-2");

        let first_events = store.ingest_spans(
            vec![span(
                "trace-1",
                "svc",
                "GET /one",
                "root-1",
                "request-parent-1",
            )],
            &mut coverage,
        );
        let second_events = store.ingest_spans(
            vec![span(
                "trace-1",
                "svc",
                "POST /two",
                "root-2",
                "request-parent-2",
            )],
            &mut coverage,
        );

        assert!(has_promotion(&first_events));
        assert!(!has_promotion(&second_events));
        assert_eq!(coverage.coverage_ratio(), (2, 0));
    }

    #[test]
    fn out_of_order_child_resolves_edge_when_parent_arrives() {
        let mut store = TraceStore::default();
        let mut coverage = OtelCoverageState::default();

        start(&mut store, &mut coverage, "trace-1");
        register(&mut store, "trace-1", "request-parent");
        store.ingest_spans(
            vec![span("trace-1", "svc", "child", "child-span", "root-span")],
            &mut coverage,
        );
        store.ingest_spans(
            vec![span(
                "trace-1",
                "svc",
                "root",
                "root-span",
                "request-parent",
            )],
            &mut coverage,
        );

        assert_eq!(coverage.coverage_ratio(), (3, 0));
    }
    #[test]
    fn root_registered_after_span_counts_root_seen_retroactively() {
        let mut store = TraceStore::default();
        let mut coverage = OtelCoverageState::default();

        start(&mut store, &mut coverage, "trace-1");
        store.ingest_spans(
            vec![span("trace-1", "svc", "root", "root-span", "parent-1")],
            &mut coverage,
        );
        let events = register(&mut store, "trace-1", "parent-1");

        assert!(
            events
                .iter()
                .any(|event| matches!(event, TraceStoreEvent::RequestRootRegisteredAfterSpan))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, TraceStoreEvent::RootSeen))
        );
    }

    #[test]
    fn unknown_lifecycle_messages_are_counted() {
        let mut store = TraceStore::default();

        let root_events = register(&mut store, "missing-trace", "parent-1");
        let finish_events = finish(&mut store, "missing-trace");

        assert!(
            root_events
                .iter()
                .any(|event| matches!(event, TraceStoreEvent::RequestRootUnknownTrace))
        );
        assert!(
            finish_events
                .iter()
                .any(|event| matches!(event, TraceStoreEvent::SequenceFinishUnknownTrace))
        );
    }
}
