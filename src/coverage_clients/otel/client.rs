//! The [`CoverageClient`] implementation for OTel-based coverage: injects trace context into
//! outgoing requests, drives the built-in OTLP receiver/arbiter, and reports coverage derived
//! from spans back to the fuzzer via [`DelayedGuidance`].

use std::{
    net::SocketAddr,
    path::Path,
    sync::mpsc::{self, Receiver},
};

use anyhow::Context;
use rand::RngExt;
use tokio::sync::mpsc::{Sender, error::TrySendError};

use crate::{
    coverage_clients::{CoverageClient, DelayedGuidance},
    input::OpenApiInput,
};

use super::{
    coverage::{SharedCoverageState, new_shared_coverage_state},
    receiver::{OtelReceiverHandle, start_otel_receiver},
    types::{
        ArbiterMessage, PromotionCandidate, SharedOtelTraceProcessingMetrics,
        record_engine_backpressure, record_engine_queue_depth,
    },
};

fn random_trace_id() -> String {
    let mut rng = rand::rng();
    loop {
        let trace_hi: u64 = rng.random();
        let trace_lo: u64 = rng.random();
        if trace_hi != 0 || trace_lo != 0 {
            return format!("{trace_hi:016x}{trace_lo:016x}");
        }
    }
}

fn random_span_id() -> String {
    let mut rng = rand::rng();
    loop {
        let span_id: u64 = rng.random();
        if span_id != 0 {
            return format!("{span_id:016x}");
        }
    }
}

fn send_arbiter_message(
    job_tx: &Sender<ArbiterMessage>,
    metrics: &SharedOtelTraceProcessingMetrics,
    message: ArbiterMessage,
    description: &str,
) -> Result<(), ()> {
    match job_tx.try_send(message) {
        Ok(()) => {
            record_engine_queue_depth(metrics, job_tx.max_capacity() - job_tx.capacity());
            Ok(())
        }
        Err(TrySendError::Full(message)) => {
            log::warn!(
                "OTel arbiter queue is saturated while sending {description}; applying backpressure until the arbiter catches up"
            );
            record_engine_backpressure(metrics);
            job_tx.blocking_send(message).map_err(|error| {
                log::warn!(
                    "OTel arbiter queue disconnected while sending {description}; delayed OTel guidance is disabled: {error}"
                );
            })?;
            record_engine_queue_depth(metrics, job_tx.max_capacity() - job_tx.capacity());
            Ok(())
        }
        Err(TrySendError::Closed(_)) => {
            log::warn!(
                "OTel arbiter queue disconnected while sending {description}; delayed OTel guidance is disabled"
            );
            Err(())
        }
    }
}

/// Coverage client that turns OTLP-received OTel spans into delayed seed promotions.
pub struct OtelCoverageClient {
    current_trace_id: Option<String>,
    otel_http_receiver_bind: Option<SocketAddr>,
    otel_grpc_receiver_bind: Option<SocketAddr>,
    coverage_state: SharedCoverageState,
    trace_processing_metrics: SharedOtelTraceProcessingMetrics,
    job_tx: Sender<ArbiterMessage>,
    promotion_rx: Receiver<PromotionCandidate>,
    next_submission_id: u64,
    replaying_promotion: bool,
    guidance_enabled: bool,
    _receiver_handle: OtelReceiverHandle,
    dummy_cov_map: Box<[u8; 1]>,
}

impl OtelCoverageClient {
    /// Create a new OTel coverage client backed by the built-in OTLP receivers.
    pub fn new(
        otel_http_receiver_bind: Option<SocketAddr>,
        otel_grpc_receiver_bind: Option<SocketAddr>,
        trace_processing_metrics: SharedOtelTraceProcessingMetrics,
    ) -> anyhow::Result<Self> {
        let coverage_state = new_shared_coverage_state();
        let (promotion_tx, promotion_rx) = mpsc::channel();

        let receiver_handle = start_otel_receiver(
            otel_http_receiver_bind,
            otel_grpc_receiver_bind,
            coverage_state.clone(),
            trace_processing_metrics.clone(),
            promotion_tx,
        )
        .context("failed to start OTLP receiver")?;
        let job_tx = receiver_handle.job_tx();

        Ok(Self {
            current_trace_id: None,
            otel_http_receiver_bind,
            otel_grpc_receiver_bind,
            coverage_state,
            trace_processing_metrics,
            job_tx,
            promotion_rx,
            next_submission_id: 0,
            replaying_promotion: false,
            guidance_enabled: true,
            _receiver_handle: receiver_handle,
            dummy_cov_map: Box::new([0u8; 1]),
        })
    }

    #[cfg(test)]
    fn new_for_tests() -> Self {
        let trace_processing_metrics = super::new_otel_trace_processing_metrics();
        let coverage_state = new_shared_coverage_state();
        let (promotion_tx, promotion_rx) = mpsc::channel();
        let receiver_handle = start_otel_receiver(
            Some("127.0.0.1:0".parse().unwrap()),
            Some("127.0.0.1:0".parse().unwrap()),
            coverage_state.clone(),
            trace_processing_metrics.clone(),
            promotion_tx,
        )
        .expect("test OTLP receiver should start");
        let job_tx = receiver_handle.job_tx();

        Self {
            current_trace_id: None,
            otel_http_receiver_bind: Some("127.0.0.1:0".parse().unwrap()),
            otel_grpc_receiver_bind: Some("127.0.0.1:0".parse().unwrap()),
            coverage_state,
            trace_processing_metrics,
            job_tx,
            promotion_rx,
            next_submission_id: 0,
            replaying_promotion: false,
            guidance_enabled: true,
            _receiver_handle: receiver_handle,
            dummy_cov_map: Box::new([0u8; 1]),
        }
    }

    fn clear_current_sequence(&mut self) {
        self.current_trace_id = None;
    }

    fn start_sequence_with_input(&mut self, input: &OpenApiInput) -> Option<String> {
        if self.replaying_promotion || !self.guidance_enabled {
            return None;
        }

        if let Some(trace_id) = &self.current_trace_id {
            return Some(trace_id.clone());
        }

        let submission_id = self.next_submission_id;
        self.next_submission_id = self.next_submission_id.saturating_add(1);

        let trace_id = random_trace_id();
        if send_arbiter_message(
            &self.job_tx,
            &self.trace_processing_metrics,
            ArbiterMessage::SequenceStarted {
                submission_id,
                input: input.clone(),
                trace_id: trace_id.clone(),
            },
            "OTel sequence start",
        )
        .is_err()
        {
            self.guidance_enabled = false;
            self.clear_current_sequence();
            return None;
        }

        self.current_trace_id = Some(trace_id.clone());
        Some(trace_id)
    }
}

impl CoverageClient for OtelCoverageClient {
    fn fetch_coverage(&mut self, _reset: bool) {}

    fn finish_request_sequence(&mut self, input: &OpenApiInput) {
        <Self as DelayedGuidance>::finish_request_sequence(self, input);
    }

    fn get_coverage_ptr(&mut self) -> *mut u8 {
        self.dummy_cov_map.as_mut_ptr()
    }

    fn get_coverage_len(&self) -> usize {
        0
    }

    fn max_coverage_ratio(&mut self) -> (u64, u64) {
        self.coverage_state
            .lock()
            .expect("otel coverage state mutex poisoned")
            .coverage_ratio()
    }

    fn generate_coverage_report(&self, report_path: &Path) {
        use std::fmt::Write;

        let state = self
            .coverage_state
            .lock()
            .expect("otel coverage state mutex poisoned");

        let mut out = String::new();
        writeln!(out, "OTel Coverage Report").ok();
        writeln!(out, "====================").ok();
        writeln!(
            out,
            "OTLP/HTTP receiver: {}",
            self.otel_http_receiver_bind
                .map(|bind| bind.to_string())
                .unwrap_or_else(|| "disabled".to_owned())
        )
        .ok();
        writeln!(
            out,
            "OTLP/gRPC receiver: {}",
            self.otel_grpc_receiver_bind
                .map(|bind| bind.to_string())
                .unwrap_or_else(|| "disabled".to_owned())
        )
        .ok();
        writeln!(out, "Unique span types  : {}", state.span_names.len()).ok();
        writeln!(out, "Unique span edges  : {}", state.edge_names.len()).ok();
        writeln!(out).ok();

        writeln!(out, "Span types (service [kind] operation):").ok();
        for span in &state.span_names {
            writeln!(out, "  {}", span.display()).ok();
        }

        writeln!(out).ok();
        writeln!(out, "Span edges (parent -> child):").ok();
        for edge in &state.edge_names {
            writeln!(
                out,
                "  {}  ->  {}",
                edge.parent.display(),
                edge.child.display()
            )
            .ok();
        }

        let file_path = report_path.join("otel_coverage.txt");
        if let Err(error) = std::fs::write(&file_path, out.as_bytes()) {
            log::error!("Failed to write OTel coverage report to {file_path:?}: {error}");
        } else {
            log::info!("OTel coverage report written to {file_path:?}");
        }
    }

    fn delayed_guidance(&mut self) -> Option<&mut dyn DelayedGuidance> {
        Some(self)
    }
}

impl DelayedGuidance for OtelCoverageClient {
    fn start_request_sequence(&mut self, input: &OpenApiInput) {
        self.start_sequence_with_input(input);
    }

    fn traceparent_for_request(&mut self) -> Option<String> {
        if self.replaying_promotion || !self.guidance_enabled {
            return None;
        }

        let trace_id = self
            .current_trace_id
            .clone()
            .or_else(|| self.start_sequence_with_input(&OpenApiInput(Vec::new())))?;
        let parent_id = random_span_id();

        if send_arbiter_message(
            &self.job_tx,
            &self.trace_processing_metrics,
            ArbiterMessage::RequestRootRegistered {
                trace_id: trace_id.clone(),
                parent_id: parent_id.clone(),
            },
            "OTel request root registration",
        )
        .is_err()
        {
            self.guidance_enabled = false;
            self.clear_current_sequence();
            return None;
        }

        let traceparent = format!("00-{trace_id}-{parent_id}-01");
        log::trace!("Injecting sequence-scoped traceparent: {traceparent}");
        Some(traceparent)
    }

    fn finish_request_sequence(&mut self, input: &OpenApiInput) {
        let _ = input;
        if self.replaying_promotion {
            self.clear_current_sequence();
            return;
        }

        let Some(trace_id) = self.current_trace_id.take() else {
            return;
        };

        if !self.guidance_enabled {
            return;
        }

        if send_arbiter_message(
            &self.job_tx,
            &self.trace_processing_metrics,
            ArbiterMessage::SequenceFinished { trace_id },
            "OTel sequence finish",
        )
        .is_err()
        {
            self.guidance_enabled = false;
        }
    }

    fn drain_promoted_inputs(&mut self) -> Vec<OpenApiInput> {
        let mut promoted = Vec::new();
        while let Ok(candidate) = self.promotion_rx.try_recv() {
            log::debug!(
                "Drained delayed OTel promotion candidate {}",
                candidate.submission_id
            );
            promoted.push(candidate.input);
        }
        promoted
    }

    fn set_replaying_promotion(&mut self, replaying: bool) {
        self.replaying_promotion = replaying;
        if replaying {
            self.clear_current_sequence();
        }
    }
}

impl Drop for OtelCoverageClient {
    fn drop(&mut self) {
        match self.job_tx.try_send(ArbiterMessage::Shutdown) {
            Ok(()) | Err(TrySendError::Closed(_)) => {}
            Err(TrySendError::Full(message)) => {
                let _ = self.job_tx.blocking_send(message);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::coverage_clients::{CoverageClient, DelayedGuidance};

    use super::OtelCoverageClient;

    fn make_client() -> OtelCoverageClient {
        OtelCoverageClient::new_for_tests()
    }

    #[test]
    fn traceparent_returns_some() {
        let mut client = make_client();
        assert!(client.traceparent_for_request().is_some());
    }

    #[test]
    fn traceparent_format_matches_w3c_spec() {
        let mut client = make_client();
        let traceparent = client.traceparent_for_request().unwrap();
        let parts: Vec<&str> = traceparent.split('-').collect();

        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "00");
        assert_eq!(parts[1].len(), 32);
        assert_eq!(parts[2].len(), 16);
        assert_eq!(parts[3], "01");
    }

    #[test]
    fn traceparent_reuses_trace_id_within_sequence_but_changes_parent_id() {
        let mut client = make_client();
        let first = client.traceparent_for_request().unwrap();
        let second = client.traceparent_for_request().unwrap();

        let first_parts: Vec<&str> = first.split('-').collect();
        let second_parts: Vec<&str> = second.split('-').collect();
        assert_eq!(first_parts[1], second_parts[1]);
        assert_ne!(first_parts[2], second_parts[2]);
    }

    #[test]
    fn finish_request_sequence_resets_trace_id_for_next_sequence() {
        let mut client = make_client();
        let first = client.traceparent_for_request().unwrap();
        DelayedGuidance::finish_request_sequence(&mut client, &crate::input::OpenApiInput(vec![]));
        let second = client.traceparent_for_request().unwrap();

        let first_trace_id = first.split('-').nth(1).unwrap();
        let second_trace_id = second.split('-').nth(1).unwrap();
        assert_ne!(first_trace_id, second_trace_id);
    }

    #[test]
    fn coverage_client_finish_request_sequence_resets_trace_id_for_next_sequence() {
        let mut client = make_client();
        let first = client.traceparent_for_request().unwrap();
        CoverageClient::finish_request_sequence(&mut client, &crate::input::OpenApiInput(vec![]));
        let second = client.traceparent_for_request().unwrap();

        let first_trace_id = first.split('-').nth(1).unwrap();
        let second_trace_id = second.split('-').nth(1).unwrap();
        assert_ne!(first_trace_id, second_trace_id);
    }

    #[test]
    fn replay_mode_disables_traceparent_injection() {
        let mut client = make_client();
        client.set_replaying_promotion(true);
        assert!(client.traceparent_for_request().is_none());
    }

    #[test]
    fn live_coverage_len_is_zero() {
        let client = make_client();
        assert_eq!(client.get_coverage_len(), 0);
    }
}
