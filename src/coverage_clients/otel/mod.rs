//! OpenTelemetry coverage client and built-in OTLP receivers.

mod arbiter;
mod client;
mod coverage;
mod otlp_grpc;
mod otlp_http;
mod receiver;
mod trace_store;
mod types;

pub use client::OtelCoverageClient;
pub use types::{
    SharedOtelTraceProcessingMetrics, new_otel_trace_processing_metrics,
    read_otel_trace_processing_metrics,
};
