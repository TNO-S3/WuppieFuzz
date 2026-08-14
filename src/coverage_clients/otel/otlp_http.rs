use std::io::Read;

use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::Response,
    routing::post,
};
use flate2::read::GzDecoder;
use opentelemetry_proto::tonic::{
    collector::trace::v1::{ExportTraceServiceRequest, ExportTraceServiceResponse},
    common::v1::{KeyValue, any_value::Value},
};
use prost::Message;
use prost_types::Any;
use tokio::sync::mpsc::{Sender, error::TrySendError};

use super::types::{ArbiterMessage, OtelSpanKind, ParsedSpan, SharedOtelTraceProcessingMetrics};
use super::types::{record_engine_backpressure, record_engine_queue_depth};

#[derive(Clone)]
pub(crate) struct OtlpHttpState {
    span_tx: Sender<ArbiterMessage>,
    metrics: SharedOtelTraceProcessingMetrics,
}

impl OtlpHttpState {
    pub(crate) fn new(
        span_tx: Sender<ArbiterMessage>,
        metrics: SharedOtelTraceProcessingMetrics,
    ) -> Self {
        Self { span_tx, metrics }
    }
}

#[derive(Clone, PartialEq, Message)]
struct RpcStatus {
    #[prost(int32, tag = "1")]
    code: i32,
    #[prost(string, tag = "2")]
    message: String,
    #[prost(message, repeated, tag = "3")]
    details: Vec<Any>,
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

fn update_decode_error_metric(metrics: &SharedOtelTraceProcessingMetrics) {
    let mut metrics = metrics
        .lock()
        .expect("otel trace processing metrics mutex poisoned");
    metrics.receiver_requests_decode_error =
        metrics.receiver_requests_decode_error.saturating_add(1);
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn string_attribute(attributes: &[KeyValue], key: &str) -> Option<String> {
    attributes
        .iter()
        .find(|attribute| attribute.key == key)
        .and_then(|attribute| attribute.value.as_ref())
        .and_then(|value| value.value.as_ref())
        .and_then(|value| match value {
            Value::StringValue(value) => Some(value.clone()),
            _ => None,
        })
}

pub(crate) fn parse_export_trace_service_request(
    request: ExportTraceServiceRequest,
) -> Vec<ParsedSpan> {
    let mut parsed = Vec::new();

    for resource_spans in request.resource_spans {
        let (service_namespace, service) = resource_spans
            .resource
            .as_ref()
            .map(|resource| {
                (
                    string_attribute(&resource.attributes, "service.namespace")
                        .filter(|namespace| !namespace.is_empty()),
                    string_attribute(&resource.attributes, "service.name")
                        .filter(|service| !service.is_empty())
                        .unwrap_or_else(|| "unknown_service".to_owned()),
                )
            })
            .unwrap_or_else(|| (None, "unknown_service".to_owned()));

        for scope_spans in resource_spans.scope_spans {
            for span in scope_spans.spans {
                if span.trace_id.len() != 16 {
                    log::warn!(
                        "Received OTLP span '{}' with invalid trace ID length {}; skipping span",
                        span.name,
                        span.trace_id.len()
                    );
                    continue;
                }

                if span.span_id.len() != 8 {
                    log::warn!(
                        "Received OTLP span '{}' with invalid span ID length {}; skipping span",
                        span.name,
                        span.span_id.len()
                    );
                    continue;
                }

                if !span.parent_span_id.is_empty() && span.parent_span_id.len() != 8 {
                    log::warn!(
                        "Received OTLP span '{}' with invalid parent span ID length {}; skipping span",
                        span.name,
                        span.parent_span_id.len()
                    );
                    continue;
                }

                parsed.push(ParsedSpan {
                    service_namespace: service_namespace.clone(),
                    service: service.clone(),
                    name: span.name,
                    kind: OtelSpanKind::from_otlp_kind(span.kind),
                    http_request_method: string_attribute(&span.attributes, "http.request.method")
                        .or_else(|| string_attribute(&span.attributes, "http.method")),
                    http_route: string_attribute(&span.attributes, "http.route"),
                    url_template: string_attribute(&span.attributes, "url.template"),
                    rpc_system_name: string_attribute(&span.attributes, "rpc.system.name")
                        .or_else(|| string_attribute(&span.attributes, "rpc.system")),
                    rpc_method: string_attribute(&span.attributes, "rpc.method"),
                    trace_id: lower_hex(&span.trace_id),
                    span_id: lower_hex(&span.span_id),
                    parent_span_id: lower_hex(&span.parent_span_id),
                    start_time_unix_nano: span.start_time_unix_nano,
                    end_time_unix_nano: span.end_time_unix_nano,
                });
            }
        }
    }

    parsed
}

fn protobuf_response<T: Message>(
    status_code: StatusCode,
    body: T,
    retry_after: Option<u64>,
) -> Response {
    let mut builder = Response::builder()
        .status(status_code)
        .header(header::CONTENT_TYPE, "application/x-protobuf");

    if let Some(seconds) = retry_after {
        builder = builder.header(header::RETRY_AFTER, seconds.to_string());
    }

    builder
        .body(Body::from(body.encode_to_vec()))
        .expect("hardcoded OTLP response headers should be valid")
}

fn success_response() -> Response {
    protobuf_response(
        StatusCode::OK,
        ExportTraceServiceResponse {
            partial_success: None,
        },
        None,
    )
}

fn error_response(status_code: StatusCode, message: impl Into<String>) -> Response {
    protobuf_response(
        status_code,
        RpcStatus {
            code: 0,
            message: message.into(),
            details: Vec::new(),
        },
        None,
    )
}

fn service_unavailable_response(message: impl Into<String>) -> Response {
    protobuf_response(
        StatusCode::SERVICE_UNAVAILABLE,
        RpcStatus {
            code: 0,
            message: message.into(),
            details: Vec::new(),
        },
        Some(1),
    )
}

fn header_value(headers: &HeaderMap, header_name: header::HeaderName) -> Option<String> {
    headers
        .get(header_name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn is_binary_protobuf_content_type(headers: &HeaderMap) -> bool {
    header_value(headers, header::CONTENT_TYPE)
        .map(|value| {
            value
                .split(';')
                .next()
                .map(str::trim)
                .is_some_and(|content_type| {
                    content_type.eq_ignore_ascii_case("application/x-protobuf")
                })
        })
        .unwrap_or(false)
}

fn decode_body(headers: &HeaderMap, body: Bytes) -> Result<Vec<u8>, String> {
    match header_value(headers, header::CONTENT_ENCODING).as_deref() {
        None | Some("") => Ok(body.to_vec()),
        Some(content_encoding) if content_encoding.eq_ignore_ascii_case("identity") => {
            Ok(body.to_vec())
        }
        Some(content_encoding) if content_encoding.eq_ignore_ascii_case("gzip") => {
            let mut decoded = Vec::new();
            let mut decoder = GzDecoder::new(body.as_ref());
            decoder
                .read_to_end(&mut decoded)
                .map_err(|error| format!("failed to decompress gzip OTLP request body: {error}"))?;
            Ok(decoded)
        }
        Some(content_encoding) => Err(format!(
            "unsupported Content-Encoding '{content_encoding}'; only identity and gzip are supported"
        )),
    }
}

pub(crate) fn build_otlp_http_router(state: OtlpHttpState) -> Router {
    Router::new()
        .route("/v1/traces", post(handle_otlp_http_request))
        .fallback(handle_otlp_http_fallback)
        .with_state(state)
}

async fn handle_otlp_http_fallback(
    State(state): State<OtlpHttpState>,
    method: Method,
    uri: Uri,
) -> Response {
    log::warn!(
        "OTLP receiver rejected {} {}: only POST /v1/traces is supported",
        method,
        uri
    );
    update_rejected_metric(&state.metrics);

    if uri.path() == "/v1/traces" {
        error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "only POST /v1/traces is supported for OTLP trace export",
        )
    } else {
        error_response(
            StatusCode::NOT_FOUND,
            "only /v1/traces is supported for OTLP trace export",
        )
    }
}

pub(crate) async fn handle_otlp_http_request(
    State(state): State<OtlpHttpState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_binary_protobuf_content_type(&headers) {
        log::warn!(
            "OTLP receiver rejected request with unsupported Content-Type {:?}; only application/x-protobuf is currently supported",
            header_value(&headers, header::CONTENT_TYPE)
        );
        update_rejected_metric(&state.metrics);
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "only application/x-protobuf OTLP/HTTP requests are supported",
        );
    }

    let body = match decode_body(&headers, body) {
        Ok(body) => body,
        Err(error) => {
            log::warn!("{error}");
            if error.contains("unsupported Content-Encoding") {
                update_rejected_metric(&state.metrics);
                return error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, error);
            }

            update_decode_error_metric(&state.metrics);
            return error_response(StatusCode::BAD_REQUEST, error);
        }
    };

    if body.is_empty() {
        update_ok_metrics(&state.metrics, 0);
        return success_response();
    }

    let export = match ExportTraceServiceRequest::decode(body.as_slice()) {
        Ok(export) => export,
        Err(error) => {
            log::warn!(
                "Failed to decode OTLP protobuf request body as ExportTraceServiceRequest: {error}"
            );
            update_decode_error_metric(&state.metrics);
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("invalid ExportTraceServiceRequest protobuf: {error}"),
            );
        }
    };

    let spans = parse_export_trace_service_request(export);
    let span_count = spans.len();
    match state.span_tx.try_send(ArbiterMessage::ReceivedSpans(spans)) {
        Ok(()) => {
            update_queue_depth(&state.span_tx, &state.metrics);
            update_ok_metrics(&state.metrics, span_count);
            success_response()
        }
        Err(TrySendError::Full(_)) => {
            log::warn!("OTel arbiter queue is saturated; rejecting OTLP/HTTP export for retry");
            record_engine_backpressure(&state.metrics);
            update_queue_depth(&state.span_tx, &state.metrics);
            update_rejected_metric(&state.metrics);
            service_unavailable_response("OTel arbiter is overloaded; retry export later")
        }
        Err(TrySendError::Closed(_)) => {
            log::warn!(
                "OTLP receiver could not hand spans to the arbiter; delayed OTel guidance is unavailable"
            );
            update_rejected_metric(&state.metrics);
            service_unavailable_response(
                "OTel arbiter is temporarily unavailable; retry export later",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Bytes,
        extract::State,
        http::{HeaderMap, HeaderValue, StatusCode, header},
    };
    use opentelemetry_proto::tonic::{
        collector::trace::v1::ExportTraceServiceRequest,
        common::v1::{AnyValue, KeyValue, any_value::Value},
        resource::v1::Resource,
        trace::v1::{ResourceSpans, ScopeSpans, Span},
    };
    use prost::Message;

    use super::{OtlpHttpState, handle_otlp_http_request, parse_export_trace_service_request};
    use crate::coverage_clients::otel::types::{
        ArbiterMessage, OtelSpanKind, new_otel_trace_processing_metrics,
    };

    fn string_attribute(key: &str, value: &str) -> KeyValue {
        KeyValue {
            key: key.to_owned(),
            value: Some(AnyValue {
                value: Some(Value::StringValue(value.to_owned())),
            }),
            key_strindex: 0,
        }
    }

    fn protobuf_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-protobuf"),
        );
        headers
    }

    #[test]
    fn parse_export_request_extracts_service_name_and_span_fields() {
        let export = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![
                        string_attribute("service.namespace", "owasp"),
                        string_attribute("service.name", "webgoat"),
                    ],
                    dropped_attributes_count: 0,
                    entity_refs: Vec::new(),
                }),
                scope_spans: vec![ScopeSpans {
                    scope: None,
                    spans: vec![Span {
                        trace_id: vec![
                            0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d,
                            0x0e, 0x0e, 0x47, 0x36,
                        ],
                        span_id: vec![0x56, 0xc5, 0x8a, 0x1f, 0x0b, 0x7d, 0x51, 0x10],
                        trace_state: String::new(),
                        parent_span_id: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11],
                        flags: 0,
                        name: "GET /WebGoat/login".to_owned(),
                        kind: 2,
                        start_time_unix_nano: 10,
                        end_time_unix_nano: 20,
                        attributes: vec![
                            string_attribute("http.request.method", "GET"),
                            string_attribute("http.route", "/WebGoat/login"),
                        ],
                        dropped_attributes_count: 0,
                        events: Vec::new(),
                        dropped_events_count: 0,
                        links: Vec::new(),
                        dropped_links_count: 0,
                        status: None,
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };

        let parsed = parse_export_trace_service_request(export);

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].service_namespace.as_deref(), Some("owasp"));
        assert_eq!(parsed[0].service, "webgoat");
        assert_eq!(parsed[0].name, "GET /WebGoat/login");
        assert_eq!(parsed[0].kind, OtelSpanKind::Server);
        assert_eq!(parsed[0].http_request_method.as_deref(), Some("GET"));
        assert_eq!(parsed[0].http_route.as_deref(), Some("/WebGoat/login"));
        assert_eq!(parsed[0].trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(parsed[0].span_id, "56c58a1f0b7d5110");
        assert_eq!(parsed[0].parent_span_id, "aabbccddeeff0011");
        assert_eq!(parsed[0].start_time_unix_nano, 10);
        assert_eq!(parsed[0].end_time_unix_nano, 20);
    }

    #[tokio::test]
    async fn http_export_accepts_empty_body() {
        let (span_tx, mut span_rx) = tokio::sync::mpsc::channel(1);
        let metrics = new_otel_trace_processing_metrics();

        let response = handle_otlp_http_request(
            State(OtlpHttpState::new(span_tx, metrics.clone())),
            protobuf_headers(),
            Bytes::new(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(span_rx.try_recv().is_err());
        assert_eq!(metrics.lock().unwrap().receiver_requests_ok, 1);
    }

    #[tokio::test]
    async fn http_export_returns_503_when_engine_queue_is_full() {
        let (span_tx, mut span_rx) = tokio::sync::mpsc::channel(1);
        span_tx
            .try_send(ArbiterMessage::Shutdown)
            .expect("test queue should accept filler message");
        let metrics = new_otel_trace_processing_metrics();
        let body = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: None,
                scope_spans: Vec::new(),
                schema_url: String::new(),
            }],
        }
        .encode_to_vec();

        let response = handle_otlp_http_request(
            State(OtlpHttpState::new(span_tx, metrics.clone())),
            protobuf_headers(),
            Bytes::from(body),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(matches!(span_rx.try_recv(), Ok(ArbiterMessage::Shutdown)));
        assert_eq!(metrics.lock().unwrap().receiver_requests_rejected, 1);
    }
}
