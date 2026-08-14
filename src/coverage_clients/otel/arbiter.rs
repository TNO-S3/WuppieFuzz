use std::sync::mpsc::Sender;

use tokio::{sync::watch, time};

use super::{
    coverage::SharedCoverageState,
    trace_store::{TraceStore, TraceStoreEvent},
    types::{
        ArbiterMessage, DEFAULT_ARBITER_TICK_INTERVAL, DEFAULT_MAX_ACTIVE_SEQUENCES,
        DEFAULT_SEQUENCE_RETENTION_WINDOW, PromotionCandidate, SharedOtelTraceProcessingMetrics,
        record_engine_queue_depth,
    },
};

fn process_resolutions(
    metrics: &SharedOtelTraceProcessingMetrics,
    promotion_tx: &Sender<PromotionCandidate>,
    events: Vec<TraceStoreEvent>,
) -> bool {
    for event in events {
        match event {
            TraceStoreEvent::RequestRootRegistered => {
                let mut shared_metrics = metrics
                    .lock()
                    .expect("otel trace processing metrics mutex poisoned");
                shared_metrics.sequence_roots_expected =
                    shared_metrics.sequence_roots_expected.saturating_add(1);
            }
            TraceStoreEvent::RequestRootUnknownTrace => {
                let mut shared_metrics = metrics
                    .lock()
                    .expect("otel trace processing metrics mutex poisoned");
                shared_metrics.request_roots_unknown_trace =
                    shared_metrics.request_roots_unknown_trace.saturating_add(1);
            }
            TraceStoreEvent::SequenceFinishUnknownTrace => {
                let mut shared_metrics = metrics
                    .lock()
                    .expect("otel trace processing metrics mutex poisoned");
                shared_metrics.sequence_finish_unknown_trace = shared_metrics
                    .sequence_finish_unknown_trace
                    .saturating_add(1);
            }
            TraceStoreEvent::LateAfterEviction => {
                let mut shared_metrics = metrics
                    .lock()
                    .expect("otel trace processing metrics mutex poisoned");
                shared_metrics.spans_late_after_eviction =
                    shared_metrics.spans_late_after_eviction.saturating_add(1);
            }
            TraceStoreEvent::RootSeen => {
                let mut shared_metrics = metrics
                    .lock()
                    .expect("otel trace processing metrics mutex poisoned");
                shared_metrics.sequence_roots_seen =
                    shared_metrics.sequence_roots_seen.saturating_add(1);
            }
            TraceStoreEvent::Promotion {
                trace_id,
                candidate,
                ..
            } => {
                {
                    let mut shared_metrics = metrics
                        .lock()
                        .expect("otel trace processing metrics mutex poisoned");
                    shared_metrics.sequences_promoted =
                        shared_metrics.sequences_promoted.saturating_add(1);
                }

                log::debug!(
                    "OTel arbiter marked sequence submission {} for trace {} as novel",
                    candidate.submission_id,
                    trace_id
                );

                if promotion_tx.send(candidate).is_err() {
                    log::warn!(
                        "OTel promotion channel disconnected; delayed OTel seed promotion is unavailable"
                    );
                    return false;
                }
            }
            TraceStoreEvent::Evicted {
                trace_id,
                expected_parent_ids,
                seen_parent_ids,
                lifetime,
                was_novel,
                reason,
            } => {
                log::debug!(
                    "OTel sequence {trace_id} evicted after {:?}: saw {seen_parent_ids}/{expected_parent_ids} registered request roots, novel={was_novel}, reason={reason:?}",
                    lifetime
                );
            }
            TraceStoreEvent::NonNovel {
                trace_id,
                expected_parent_ids,
                seen_parent_ids,
            } => {
                log::debug!(
                    "OTel sequence {trace_id} evicted without new coverage after seeing {seen_parent_ids}/{expected_parent_ids} registered request roots"
                );
            }
            TraceStoreEvent::Dropped {
                trace_id,
                expected_parent_ids,
                seen_parent_ids,
                waited,
            } => {
                log::debug!(
                    "OTel sequence {trace_id} evicted after {:?} without spans: saw {seen_parent_ids}/{expected_parent_ids} registered request roots",
                    waited
                );
            }
            TraceStoreEvent::SequenceStarted
            | TraceStoreEvent::SequenceFinished
            | TraceStoreEvent::DuplicateSequenceStart
            | TraceStoreEvent::RequestRootRegisteredAfterSpan
            | TraceStoreEvent::OrphanSpan
            | TraceStoreEvent::OrphanSpanBuffered
            | TraceStoreEvent::OrphanSpanReassociated
            | TraceStoreEvent::OrphanSpanExpired
            | TraceStoreEvent::OrphanSpanCapacityDropped => {}
        }
    }

    true
}

struct TraceStateSnapshot {
    unique_span_keys: usize,
    unique_edge_keys: usize,
}

fn update_trace_state_metrics(
    metrics: &SharedOtelTraceProcessingMetrics,
    snapshot: TraceStateSnapshot,
) {
    let mut metrics = metrics
        .lock()
        .expect("otel trace processing metrics mutex poisoned");
    metrics.unique_span_keys = snapshot.unique_span_keys as u64;
    metrics.unique_edge_keys = snapshot.unique_edge_keys as u64;
}

pub(crate) async fn run_otel_arbiter(
    coverage_state: SharedCoverageState,
    metrics: SharedOtelTraceProcessingMetrics,
    mut job_rx: tokio::sync::mpsc::Receiver<ArbiterMessage>,
    promotion_tx: Sender<PromotionCandidate>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut trace_store = TraceStore::default();
    let mut tick = time::interval(DEFAULT_ARBITER_TICK_INTERVAL);

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            message = job_rx.recv() => {
                let Some(message) = message else {
                    log::warn!("OTel arbiter input channel disconnected; delayed OTel promotion will stop");
                    break;
                };

                match message {
                    ArbiterMessage::SequenceStarted {
                        submission_id,
                        input,
                        trace_id,
                    } => {
                        let events = {
                            let mut coverage_state = coverage_state
                                .lock()
                                .expect("otel coverage state mutex poisoned");
                            trace_store.start_sequence(trace_id, submission_id, input, &mut coverage_state)
                        };
                        if !process_resolutions(&metrics, &promotion_tx, events) {
                            break;
                        }
                    }
                    ArbiterMessage::RequestRootRegistered {
                        trace_id,
                        parent_id,
                    } => {
                        let events = trace_store.register_request_root(trace_id, parent_id);
                        if !process_resolutions(&metrics, &promotion_tx, events) {
                            break;
                        }
                    }
                    ArbiterMessage::SequenceFinished {
                        trace_id,
                    } => {
                        let events = trace_store.finish_sequence(trace_id);
                        if !process_resolutions(&metrics, &promotion_tx, events) {
                            break;
                        }
                    }
                    ArbiterMessage::ReceivedSpans(spans) => {
                        let events = {
                            let mut coverage_state = coverage_state
                                .lock()
                                .expect("otel coverage state mutex poisoned");
                            trace_store.ingest_spans(spans, &mut coverage_state)
                        };
                        if !process_resolutions(&metrics, &promotion_tx, events) {
                            break;
                        }
                    }
                    ArbiterMessage::Shutdown => break,
                }
                record_engine_queue_depth(&metrics, job_rx.len());
            }
            _ = tick.tick() => {}
        }

        let events = trace_store.drain_timeouts(
            DEFAULT_SEQUENCE_RETENTION_WINDOW,
            DEFAULT_MAX_ACTIVE_SEQUENCES,
        );
        if !process_resolutions(&metrics, &promotion_tx, events) {
            break;
        }
        let (unique_span_keys, unique_edge_keys) = {
            let coverage_state = coverage_state
                .lock()
                .expect("otel coverage state mutex poisoned");
            (
                coverage_state.span_key_count(),
                coverage_state.edge_key_count(),
            )
        };
        update_trace_state_metrics(
            &metrics,
            TraceStateSnapshot {
                unique_span_keys,
                unique_edge_keys,
            },
        );
    }
}
