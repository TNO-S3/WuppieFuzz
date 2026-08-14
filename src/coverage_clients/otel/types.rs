use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::{input::OpenApiInput, reporting::OtelTraceProcessingStats};

pub(crate) const DEFAULT_ARBITER_QUEUE_CAPACITY: usize = 65_536;
pub(crate) const DEFAULT_SEQUENCE_RETENTION_WINDOW: Duration = Duration::from_secs(120);
pub(crate) const DEFAULT_MAX_ACTIVE_SEQUENCES: usize = 100_000;
pub(crate) const DEFAULT_ARBITER_TICK_INTERVAL: Duration = Duration::from_millis(100);

/// Shared development metrics for the built-in OTel receiver and arbiter.
pub type SharedOtelTraceProcessingMetrics = Arc<Mutex<OtelTraceProcessingStats>>;

/// Create a shared accumulator for OTel receiver/arbiter metrics.
pub fn new_otel_trace_processing_metrics() -> SharedOtelTraceProcessingMetrics {
    Arc::new(Mutex::new(OtelTraceProcessingStats::default()))
}

/// Read a snapshot of the shared OTel receiver/arbiter metrics.
pub fn read_otel_trace_processing_metrics(
    metrics: &SharedOtelTraceProcessingMetrics,
) -> OtelTraceProcessingStats {
    *metrics
        .lock()
        .expect("otel trace processing metrics mutex poisoned")
}

pub(crate) fn record_engine_queue_depth(
    metrics: &SharedOtelTraceProcessingMetrics,
    queue_depth: usize,
) {
    let mut metrics = metrics
        .lock()
        .expect("otel trace processing metrics mutex poisoned");
    let queue_depth = queue_depth as u64;
    metrics.engine_queue_depth = queue_depth;
    metrics.engine_queue_high_watermark = metrics.engine_queue_high_watermark.max(queue_depth);
}

pub(crate) fn record_engine_backpressure(metrics: &SharedOtelTraceProcessingMetrics) {
    let mut metrics = metrics
        .lock()
        .expect("otel trace processing metrics mutex poisoned");
    metrics.engine_backpressure = metrics.engine_backpressure.saturating_add(1);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum OtelSpanKind {
    Unspecified,
    Internal,
    Server,
    Client,
    Producer,
    Consumer,
}

impl OtelSpanKind {
    pub(crate) fn from_otlp_kind(kind: i32) -> Self {
        match kind {
            1 => Self::Internal,
            2 => Self::Server,
            3 => Self::Client,
            4 => Self::Producer,
            5 => Self::Consumer,
            _ => Self::Unspecified,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Internal => "internal",
            Self::Server => "server",
            Self::Client => "client",
            Self::Producer => "producer",
            Self::Consumer => "consumer",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedSpan {
    pub service_namespace: Option<String>,
    pub service: String,
    pub name: String,
    pub kind: OtelSpanKind,
    pub http_request_method: Option<String>,
    pub http_route: Option<String>,
    pub url_template: Option<String>,
    pub rpc_system_name: Option<String>,
    pub rpc_method: Option<String>,
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: String,
    pub start_time_unix_nano: u64,
    pub end_time_unix_nano: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct PromotionCandidate {
    pub submission_id: u64,
    pub input: OpenApiInput,
}

#[derive(Debug)]
pub(crate) enum ArbiterMessage {
    SequenceStarted {
        submission_id: u64,
        input: OpenApiInput,
        trace_id: String,
    },
    RequestRootRegistered {
        trace_id: String,
        parent_id: String,
    },
    SequenceFinished {
        trace_id: String,
    },
    ReceivedSpans(Vec<ParsedSpan>),
    Shutdown,
}
