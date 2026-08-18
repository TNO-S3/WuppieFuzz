//! OTLP/gRPC `TraceService` implementation: accepts `Export` calls and forwards the parsed
//! spans to the arbiter job queue.

use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
    trace_service_server::{TraceService, TraceServiceServer},
};
use tokio::sync::mpsc::{Sender, error::TrySendError};
use tonic::{Request, Response, Status, codec::CompressionEncoding};

use super::{
    otlp_http::parse_export_trace_service_request,
    types::{
        ArbiterMessage, SharedOtelTraceProcessingMetrics, record_engine_backpressure,
        record_engine_queue_depth,
    },
};

#[derive(Clone)]
pub(crate) struct OtlpGrpcService {
    span_tx: Sender<ArbiterMessage>,
    metrics: SharedOtelTraceProcessingMetrics,
}

impl OtlpGrpcService {
    pub(crate) fn new(
        span_tx: Sender<ArbiterMessage>,
        metrics: SharedOtelTraceProcessingMetrics,
    ) -> Self {
        Self { span_tx, metrics }
    }

    pub(crate) fn into_server(self) -> TraceServiceServer<Self> {
        TraceServiceServer::new(self).accept_compressed(CompressionEncoding::Gzip)
    }
}

fn update_ok_metrics(metrics: &SharedOtelTraceProcessingMetrics, spans: usize) {
    let mut metrics = metrics
        .lock()
        .expect("otel trace processing metrics mutex poisoned");
    metrics.receiver_requests_ok = metrics.receiver_requests_ok.saturating_add(1);
    metrics.spans_received = metrics.spans_received.saturating_add(spans as u64);
}

fn update_queue_depth(
    span_tx: &Sender<ArbiterMessage>,
    metrics: &SharedOtelTraceProcessingMetrics,
) {
    record_engine_queue_depth(metrics, span_tx.max_capacity() - span_tx.capacity());
}

fn update_rejected_metric(metrics: &SharedOtelTraceProcessingMetrics) {
    let mut metrics = metrics
        .lock()
        .expect("otel trace processing metrics mutex poisoned");
    metrics.receiver_requests_rejected = metrics.receiver_requests_rejected.saturating_add(1);
}

#[tonic::async_trait]
impl TraceService for OtlpGrpcService {
    async fn export(
        &self,
        request: Request<ExportTraceServiceRequest>,
    ) -> Result<Response<ExportTraceServiceResponse>, Status> {
        let spans = parse_export_trace_service_request(request.into_inner());
        let span_count = spans.len();
        match self.span_tx.try_send(ArbiterMessage::ReceivedSpans(spans)) {
            Ok(()) => {
                update_queue_depth(&self.span_tx, &self.metrics);
                update_ok_metrics(&self.metrics, span_count);
                Ok(Response::new(ExportTraceServiceResponse {
                    partial_success: None,
                }))
            }
            Err(TrySendError::Full(_)) => {
                log::warn!("OTel arbiter queue is saturated; rejecting OTLP/gRPC export for retry");
                record_engine_backpressure(&self.metrics);
                update_queue_depth(&self.span_tx, &self.metrics);
                update_rejected_metric(&self.metrics);
                Err(Status::unavailable(
                    "OTel arbiter is overloaded; retry export later",
                ))
            }
            Err(TrySendError::Closed(_)) => {
                log::warn!(
                    "OTLP/gRPC receiver could not hand spans to the arbiter; delayed OTel guidance is unavailable"
                );
                update_rejected_metric(&self.metrics);
                Err(Status::unavailable(
                    "OTel arbiter is temporarily unavailable; retry export later",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use tonic::Request;

    use super::*;
    use crate::coverage_clients::otel::types::new_otel_trace_processing_metrics;

    #[tokio::test]
    async fn grpc_export_accepts_empty_request() {
        let (span_tx, mut span_rx) = tokio::sync::mpsc::channel(1);
        let metrics = new_otel_trace_processing_metrics();
        let service = OtlpGrpcService::new(span_tx, metrics.clone());

        service
            .export(Request::new(ExportTraceServiceRequest {
                resource_spans: Vec::new(),
            }))
            .await
            .expect("empty export should be accepted");

        assert!(
            matches!(span_rx.try_recv(), Ok(ArbiterMessage::ReceivedSpans(spans)) if spans.is_empty())
        );
        assert_eq!(metrics.lock().unwrap().receiver_requests_ok, 1);
    }
}
