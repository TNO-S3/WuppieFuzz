//! Spawns the background Tokio runtime that runs the OTLP/HTTP and OTLP/gRPC receivers
//! alongside the arbiter task, and exposes a handle to submit jobs and trigger shutdown.

use std::{
    net::{SocketAddr, TcpListener as StdTcpListener},
    sync::mpsc::Sender as StdSender,
    thread::{self, JoinHandle},
};

use anyhow::{Context, anyhow};
use tokio::{net::TcpListener, runtime, sync::watch};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use super::{
    arbiter::run_otel_arbiter,
    coverage::SharedCoverageState,
    otlp_grpc::OtlpGrpcService,
    otlp_http::{OtlpHttpState, build_otlp_http_router},
    types::{ArbiterMessage, DEFAULT_ARBITER_QUEUE_CAPACITY, SharedOtelTraceProcessingMetrics},
};

pub(crate) struct OtelReceiverHandle {
    job_tx: tokio::sync::mpsc::Sender<ArbiterMessage>,
    shutdown_tx: Option<watch::Sender<bool>>,
    thread: Option<JoinHandle<()>>,
}

impl OtelReceiverHandle {
    pub(crate) fn job_tx(&self) -> tokio::sync::mpsc::Sender<ArbiterMessage> {
        self.job_tx.clone()
    }
}

impl Drop for OtelReceiverHandle {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(true);
        }

        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn bind_tcp_listener(bind_addr: SocketAddr, description: &str) -> anyhow::Result<StdTcpListener> {
    let listener = StdTcpListener::bind(bind_addr)
        .map_err(|error| anyhow!("failed to bind {description} on {bind_addr}: {error}"))?;
    listener
        .set_nonblocking(true)
        .with_context(|| format!("failed to set {description} listener nonblocking"))?;
    Ok(listener)
}

async fn run_http_receiver(
    listener: StdTcpListener,
    span_tx: tokio::sync::mpsc::Sender<ArbiterMessage>,
    metrics: SharedOtelTraceProcessingMetrics,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let listener = match TcpListener::from_std(listener) {
        Ok(listener) => listener,
        Err(error) => {
            log::warn!("Failed to convert OTLP/HTTP listener to Tokio listener: {error}");
            return;
        }
    };
    let app = build_otlp_http_router(OtlpHttpState::new(span_tx, metrics));
    let shutdown = async move {
        let _ = shutdown_rx.changed().await;
    };

    if let Err(error) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
    {
        log::warn!("OTLP/HTTP receiver stopped with error: {error}");
    }
}

async fn run_grpc_receiver(
    listener: StdTcpListener,
    span_tx: tokio::sync::mpsc::Sender<ArbiterMessage>,
    metrics: SharedOtelTraceProcessingMetrics,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let listener = match TcpListener::from_std(listener) {
        Ok(listener) => listener,
        Err(error) => {
            log::warn!("Failed to convert OTLP/gRPC listener to Tokio listener: {error}");
            return;
        }
    };
    let incoming = TcpListenerStream::new(listener);
    let shutdown = async move {
        let _ = shutdown_rx.changed().await;
    };

    if let Err(error) = Server::builder()
        .add_service(OtlpGrpcService::new(span_tx, metrics).into_server())
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await
    {
        log::warn!("OTLP/gRPC receiver stopped with error: {error}");
    }
}

pub(crate) fn start_otel_receiver(
    http_bind_addr: Option<SocketAddr>,
    grpc_bind_addr: Option<SocketAddr>,
    coverage_state: SharedCoverageState,
    metrics: SharedOtelTraceProcessingMetrics,
    promotion_tx: StdSender<super::types::PromotionCandidate>,
) -> anyhow::Result<OtelReceiverHandle> {
    if http_bind_addr.is_none() && grpc_bind_addr.is_none() {
        return Err(anyhow!(
            "OpenTelemetry coverage requires at least one enabled OTLP receiver"
        ));
    }

    let http_listener = http_bind_addr
        .map(|bind_addr| bind_tcp_listener(bind_addr, "OTLP/HTTP receiver"))
        .transpose()?;
    let grpc_listener = grpc_bind_addr
        .map(|bind_addr| bind_tcp_listener(bind_addr, "OTLP/gRPC receiver"))
        .transpose()?;

    if let Some(listener) = &http_listener {
        let http_bound_addr = listener
            .local_addr()
            .context("failed to read bound OTLP/HTTP receiver address")?;
        log::info!(
            "Started built-in OTLP/HTTP receiver on {http_bound_addr}; point target auto-instrumentation at http://<this-host>:{}/v1/traces",
            http_bound_addr.port()
        );
        if http_bound_addr.ip().is_loopback() {
            log::warn!(
                "The OTLP/HTTP receiver is bound to loopback ({http_bound_addr}); containerized fuzzing targets will usually not be able to reach it"
            );
        }
    } else {
        log::info!("Built-in OTLP/HTTP receiver disabled");
    }

    if let Some(listener) = &grpc_listener {
        let grpc_bound_addr = listener
            .local_addr()
            .context("failed to read bound OTLP/gRPC receiver address")?;
        log::info!(
            "Started built-in OTLP/gRPC receiver on {grpc_bound_addr}; point target auto-instrumentation at grpc://<this-host>:{}",
            grpc_bound_addr.port()
        );
        if grpc_bound_addr.ip().is_loopback() {
            log::warn!(
                "The OTLP/gRPC receiver is bound to loopback ({grpc_bound_addr}); containerized fuzzing targets will usually not be able to reach it"
            );
        }
    } else {
        log::info!("Built-in OTLP/gRPC receiver disabled");
    }

    let (job_tx, job_rx) = tokio::sync::mpsc::channel(DEFAULT_ARBITER_QUEUE_CAPACITY);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let http_span_tx = job_tx.clone();
    let http_metrics = metrics.clone();
    let http_shutdown_rx = shutdown_rx.clone();
    let grpc_span_tx = job_tx.clone();
    let grpc_metrics = metrics.clone();
    let grpc_shutdown_rx = shutdown_rx.clone();
    let arbiter_shutdown_rx = shutdown_rx.clone();

    let thread = thread::Builder::new()
        .name("otel-runtime".to_owned())
        .spawn(move || {
            let runtime = match runtime::Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime,
                Err(error) => {
                    log::error!("Failed to start OTEL Tokio runtime: {error}");
                    return;
                }
            };

            runtime.block_on(async move {
                let http_task = http_listener.map(|listener| {
                    tokio::spawn(run_http_receiver(
                        listener,
                        http_span_tx,
                        http_metrics,
                        http_shutdown_rx,
                    ))
                });

                let grpc_task = grpc_listener.map(|listener| {
                    tokio::spawn(run_grpc_receiver(
                        listener,
                        grpc_span_tx,
                        grpc_metrics,
                        grpc_shutdown_rx,
                    ))
                });

                let arbiter_task = tokio::spawn(run_otel_arbiter(
                    coverage_state,
                    metrics,
                    job_rx,
                    promotion_tx,
                    arbiter_shutdown_rx,
                ));

                let _ = arbiter_task.await;
                if let Some(http_task) = http_task {
                    let _ = http_task.await;
                }
                if let Some(grpc_task) = grpc_task {
                    let _ = grpc_task.await;
                }
            });
        })
        .context("failed to spawn OTEL runtime thread")?;

    Ok(OtelReceiverHandle {
        job_tx,
        shutdown_tx: Some(shutdown_tx),
        thread: Some(thread),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receiver_requires_at_least_one_enabled_protocol() {
        let coverage_state = super::super::coverage::new_shared_coverage_state();
        let metrics = super::super::types::new_otel_trace_processing_metrics();
        let (promotion_tx, _promotion_rx) = std::sync::mpsc::channel();

        let result = start_otel_receiver(None, None, coverage_state, metrics, promotion_tx);

        assert!(result.is_err());
    }

    #[test]
    fn receiver_allows_http_only() {
        let coverage_state = super::super::coverage::new_shared_coverage_state();
        let metrics = super::super::types::new_otel_trace_processing_metrics();
        let (promotion_tx, _promotion_rx) = std::sync::mpsc::channel();

        let result = start_otel_receiver(
            Some("127.0.0.1:0".parse().unwrap()),
            None,
            coverage_state,
            metrics,
            promotion_tx,
        );

        assert!(result.is_ok());
    }
}
