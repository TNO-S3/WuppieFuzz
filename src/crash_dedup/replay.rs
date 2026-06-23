use std::time::Duration;

use anyhow::Result;
use libafl::executors::ExitKind;
use libafl_bolts::HasLen;
use reqwest::StatusCode;
use strum::IntoDiscriminant;

use crate::{
    authentication::{Authentication, build_http_client},
    configuration::Configuration,
    crash_dedup::identity::{CrashIdentity, CrashKind, ObservedExitKind, ResponseClass},
    executor::process_response,
    input::{OpenApiInput, OpenApiRequest},
    openapi::{
        build_request::build_request_from_input,
        spec::Spec,
        validate_response::{Response, ValidationError, ValidationErrorDiscriminants},
    },
    parameter_feedback::ParameterFeedback,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedCrash {
    pub identity: CrashIdentity,
    pub crashing_request_index: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayOutcome {
    Crash(ObservedCrash),
    Completed,
    Stopped(String),
}

fn coarse_response_class(response: &Response) -> ResponseClass {
    // Uses WuppieFuzz's buffered Response wrapper, so reading the body here
    // does not consume it for later validation or status access.
    if response.content_length() == 0 {
        return ResponseClass::Empty;
    }

    if response.json::<serde_json::Value>().is_ok() {
        return ResponseClass::Json;
    }

    match response.text() {
        Ok(text) => {
            let trimmed = text.trim_start();
            if trimmed.starts_with('{') || trimmed.starts_with('[') {
                ResponseClass::InvalidJson
            } else if looks_like_html(&text) {
                ResponseClass::Html
            } else {
                ResponseClass::Plaintext
            }
        }
        Err(_) => ResponseClass::BinaryOrUnknown,
    }
}

fn looks_like_html(text: &str) -> bool {
    let trimmed = text.trim_start().to_ascii_lowercase();
    trimmed.starts_with("<!doctype html>")
        || trimmed.starts_with("<html")
        || trimmed.contains("<body")
}

fn response_crash_kind(
    status: StatusCode,
    validation_error: Option<&ValidationError>,
) -> CrashKind {
    if status.is_server_error() {
        return CrashKind::Http5xx;
    }
    validation_error
        .map(|err| CrashKind::Validation(err.discriminant()))
        .unwrap_or(CrashKind::HttpResponseCrash)
}

fn transport_identity_parts(error: &reqwest::Error) -> (CrashKind, ResponseClass) {
    if error.is_timeout() {
        (CrashKind::TransportTimeout, ResponseClass::TransportTimeout)
    } else if error.is_connect() {
        (
            CrashKind::TransportConnectionError,
            ResponseClass::TransportConnectionError,
        )
    } else if error.is_decode() {
        (
            CrashKind::TransportDecodeError,
            ResponseClass::TransportDecodeError,
        )
    } else {
        (
            CrashKind::TransportUnknownError,
            ResponseClass::TransportUnknownError,
        )
    }
}

fn observed_response_identity(
    status: StatusCode,
    validation_error: Option<&ValidationError>,
    endpoint: Option<String>,
    response_class: ResponseClass,
) -> CrashIdentity {
    CrashIdentity {
        exit_kind: ObservedExitKind::Crash,
        crash_kind: response_crash_kind(status, validation_error),
        http_status: Some(status.as_u16()),
        validation_error_discriminant: validation_error.map(|err| err.discriminant()),
        endpoint,
        response_class,
    }
}

fn observed_transport_identity(error: &reqwest::Error, endpoint: Option<String>) -> CrashIdentity {
    let (crash_kind, response_class) = transport_identity_parts(error);
    CrashIdentity {
        // The executor reports all transport failures as LibAFL timeouts; CrashKind keeps
        // the more specific timeout/connection/decode distinction.
        exit_kind: ObservedExitKind::Timeout,
        crash_kind,
        http_status: None,
        validation_error_discriminant: None,
        endpoint,
        response_class,
    }
}

fn endpoint_string(request: &OpenApiRequest) -> String {
    format!("{} {}", request.method, request.path)
}

enum ReplayStep {
    Continue,
    Stop(String),
    Crash(ObservedCrash),
}

enum BuiltReplayRequest {
    // Boxed to avoid a large size difference between variants (reqwest::blocking::Request is ~304 bytes).
    Request(Box<reqwest::blocking::Request>),
    Skip,
    Stop(String),
}

pub fn replay_input(
    input: &OpenApiInput,
    api: &Spec,
    config: &Configuration,
) -> Result<ReplayOutcome> {
    let (mut authentication, cookie_store, client) = build_http_client(api)?;

    replay_input_with_client(
        input,
        api,
        config.request_timeout,
        &config.crash_criteria,
        &client,
        &mut authentication,
        &cookie_store,
    )
}

struct ReplayContext<'a> {
    api: &'a Spec,
    request_timeout_ms: u64,
    crash_criteria: &'a [ValidationErrorDiscriminants],
    client: &'a reqwest::blocking::Client,
    cookie_store: &'a std::sync::Arc<reqwest_cookie_store::CookieStoreMutex>,
}

fn replay_input_with_client(
    input: &OpenApiInput,
    api: &Spec,
    request_timeout_ms: u64,
    crash_criteria: &[ValidationErrorDiscriminants],
    client: &reqwest::blocking::Client,
    authentication: &mut Authentication,
    cookie_store: &std::sync::Arc<reqwest_cookie_store::CookieStoreMutex>,
) -> Result<ReplayOutcome> {
    let ctx = ReplayContext {
        api,
        request_timeout_ms,
        crash_criteria,
        client,
        cookie_store,
    };
    let mut parameter_feedback = ParameterFeedback::new(input.len());
    for (request_index, request) in input.0.iter().enumerate() {
        match replay_request(
            request_index,
            request,
            &ctx,
            authentication,
            &mut parameter_feedback,
        )? {
            ReplayStep::Continue => {}
            ReplayStep::Stop(reason) => return Ok(ReplayOutcome::Stopped(reason)),
            ReplayStep::Crash(crash) => return Ok(ReplayOutcome::Crash(crash)),
        }
    }

    Ok(ReplayOutcome::Completed)
}

fn replay_request(
    request_index: usize,
    request: &OpenApiRequest,
    ctx: &ReplayContext<'_>,
    authentication: &mut Authentication,
    parameter_feedback: &mut ParameterFeedback,
) -> Result<ReplayStep> {
    let mut request = request.clone();

    if let Err(error) = request.resolve_parameter_references(parameter_feedback) {
        log::debug!(
            "Cannot instantiate request while replaying crash: missing backreference: {error}"
        );
        return Ok(ReplayStep::Stop(error.to_string()));
    }

    parameter_feedback.process_request(request_index, &request);

    let request_built = match build_replay_request(
        ctx.client,
        authentication,
        ctx.cookie_store,
        ctx.api,
        ctx.request_timeout_ms,
        &request,
    )? {
        BuiltReplayRequest::Request(request) => *request,
        BuiltReplayRequest::Skip => return Ok(ReplayStep::Continue),
        BuiltReplayRequest::Stop(reason) => return Ok(ReplayStep::Stop(reason)),
    };

    match ctx.client.execute(request_built) {
        Ok(response) => {
            let response: Response = response.into();
            let response_class = coarse_response_class(&response);
            let mut exit_kind = ExitKind::Ok;

            let validation_error = process_response(
                request_index,
                &request,
                &response,
                ctx.api,
                ctx.crash_criteria,
                &mut exit_kind,
                parameter_feedback,
            );

            if exit_kind == ExitKind::Crash {
                Ok(ReplayStep::Crash(ObservedCrash {
                    identity: observed_response_identity(
                        response.status(),
                        validation_error.as_ref(),
                        Some(endpoint_string(&request)),
                        response_class,
                    ),
                    crashing_request_index: request_index,
                }))
            } else {
                Ok(ReplayStep::Continue)
            }
        }
        Err(error) => Ok(ReplayStep::Crash(ObservedCrash {
            identity: observed_transport_identity(&error, Some(endpoint_string(&request))),
            crashing_request_index: request_index,
        })),
    }
}

fn build_replay_request(
    client: &reqwest::blocking::Client,
    authentication: &mut Authentication,
    cookie_store: &std::sync::Arc<reqwest_cookie_store::CookieStoreMutex>,
    api: &Spec,
    request_timeout_ms: u64,
    request: &OpenApiRequest,
) -> Result<BuiltReplayRequest> {
    let request_builder =
        match build_request_from_input(client, authentication, cookie_store, api, request) {
            Ok(builder) => builder.timeout(Duration::from_millis(request_timeout_ms)),
            Err(error) => {
                log::warn!("Could not generate HTTP request while replaying crash: {error}");
                return Ok(BuiltReplayRequest::Skip);
            }
        };

    match request_builder.build() {
        Ok(request) => Ok(BuiltReplayRequest::Request(Box::new(request))),
        Err(error) => {
            log::warn!("Reqwest failed to build replay request: {error}");
            Ok(BuiltReplayRequest::Stop(error.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;
    use strum::VariantArray;

    use super::*;
    use crate::{
        input::{
            Body, Method, ParameterContents,
            parameter::{OReference, ParameterKind},
        },
        parameter_access::{ParameterAccess, ParameterAccessElements},
    };

    fn test_spec(server_url: String) -> Spec {
        let raw_spec: oas3::Spec = serde_json::from_value(json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1.0.0" },
            "servers": [{ "url": server_url }],
            "paths": {
                "/items": {
                    "get": { "responses": { "200": { "description": "ok" } } }
                }
            }
        }))
        .expect("test OpenAPI spec should deserialize");
        Spec::from(raw_spec)
    }

    fn test_client_parts() -> (
        Authentication,
        Arc<reqwest_cookie_store::CookieStoreMutex>,
        reqwest::blocking::Client,
    ) {
        let cookie_store = Arc::new(reqwest_cookie_store::CookieStoreMutex::new(
            reqwest_cookie_store::CookieStore::default(),
        ));
        let client = reqwest::blocking::Client::builder()
            .cookie_provider(Arc::clone(&cookie_store))
            .build()
            .expect("test HTTP client should build");
        (Authentication::None, cookie_store, client)
    }

    #[test]
    fn replay_input_returns_observed_crash_for_http_500() -> anyhow::Result<()> {
        let mut server = mockito::Server::new();
        let _mock = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(500)
            .with_body(r#"{"error":"boom"}"#)
            .create();

        let api = test_spec(server.url());
        let (mut authentication, cookie_store, client) = test_client_parts();
        let input = OpenApiInput(vec![OpenApiRequest {
            method: Method::Get,
            path: "/items".into(),
            body: Body::Empty,
            parameters: Default::default(),
        }]);

        let outcome = replay_input_with_client(
            &input,
            &api,
            30_000,
            ValidationErrorDiscriminants::VARIANTS,
            &client,
            &mut authentication,
            &cookie_store,
        )?;
        let ReplayOutcome::Crash(crash) = outcome else {
            panic!("HTTP 500 should be observed as a crash, got {outcome:?}");
        };

        assert_eq!(crash.identity.crash_kind, CrashKind::Http5xx);
        assert_eq!(crash.identity.http_status, Some(500));
        assert_eq!(crash.identity.endpoint.as_deref(), Some("GET /items"));
        assert_eq!(crash.identity.response_class, ResponseClass::Json);

        Ok(())
    }

    #[test]
    fn unresolved_backreference_stops_replay() -> anyhow::Result<()> {
        let api = test_spec(String::from("http://127.0.0.1:9"));
        let (mut authentication, cookie_store, client) = test_client_parts();
        let input = OpenApiInput(vec![OpenApiRequest {
            method: Method::Get,
            path: "/items".into(),
            body: Body::Empty,
            parameters:
                [(
                    (String::from("id"), ParameterKind::Query),
                    ParameterContents::OReference(OReference {
                        request_index: 0,
                        parameter_access: ParameterAccess::response_body(
                            ParameterAccessElements::new(),
                        ),
                    }),
                )]
                .into(),
        }]);

        let outcome = replay_input_with_client(
            &input,
            &api,
            30_000,
            ValidationErrorDiscriminants::VARIANTS,
            &client,
            &mut authentication,
            &cookie_store,
        )?;

        assert!(matches!(outcome, ReplayOutcome::Stopped(_)));
        Ok(())
    }
}
