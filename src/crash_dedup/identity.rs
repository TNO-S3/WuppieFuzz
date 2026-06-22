use crate::openapi::validate_response::ValidationErrorDiscriminants;

/// Coarse category of failure observed while replaying a crash input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrashKind {
    /// The target returned a server-side HTTP status code.
    Http5xx,
    /// The response violated the OpenAPI contract in a way configured as crashing.
    Validation(ValidationErrorDiscriminants),
    /// The response was classified as a crash without a more specific kind.
    HttpResponseCrash,
    /// The request timed out before a response was received.
    TransportTimeout,
    /// The client could not establish a connection to the target.
    TransportConnectionError,
    /// The client received a response it could not decode.
    TransportDecodeError,
    /// The client reported a transport error that does not fit a narrower bucket.
    TransportUnknownError,
}

impl std::fmt::Display for CrashKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http5xx => f.write_str("http_5xx"),
            Self::Validation(discriminant) => write!(f, "validation_{discriminant:?}"),
            Self::HttpResponseCrash => f.write_str("http_response_crash"),
            Self::TransportTimeout => f.write_str("transport_timeout"),
            Self::TransportConnectionError => f.write_str("transport_connection_error"),
            Self::TransportDecodeError => f.write_str("transport_decode_error"),
            Self::TransportUnknownError => f.write_str("transport_unknown_error"),
        }
    }
}

/// Coarse classification of the response body or transport failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResponseClass {
    /// Body parsed as JSON.
    Json,
    /// Response had no body.
    Empty,
    /// Body was text that did not look like HTML or malformed JSON.
    Plaintext,
    /// Body looked like an HTML document.
    Html,
    /// Body looked JSON-shaped but failed to parse as JSON.
    InvalidJson,
    /// Body could not be classified as a supported textual format.
    BinaryOrUnknown,
    /// No response was received before the timeout.
    TransportTimeout,
    /// No response was received because the connection failed.
    TransportConnectionError,
    /// Response decoding failed at the transport/client layer.
    TransportDecodeError,
    /// Transport/client failure that does not fit a narrower bucket.
    TransportUnknownError,
}

impl std::fmt::Display for ResponseClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Json => "json",
            Self::Empty => "empty",
            Self::Plaintext => "plaintext",
            Self::Html => "html",
            Self::InvalidJson => "invalid_json",
            Self::BinaryOrUnknown => "binary_or_unknown",
            Self::TransportTimeout => "transport_timeout",
            Self::TransportConnectionError => "transport_connection_error",
            Self::TransportDecodeError => "transport_decode_error",
            Self::TransportUnknownError => "transport_unknown_error",
        };
        f.write_str(value)
    }
}

/// Whether replay observed a crash response or a timeout-like executor result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ObservedExitKind {
    /// Replay observed a crashing response.
    Crash,
    /// Replay ended with a timeout-like executor result rather than a response crash.
    Timeout,
}

impl std::fmt::Display for ObservedExitKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Crash => f.write_str("crash"),
            Self::Timeout => f.write_str("timeout"),
        }
    }
}

/// Opaque key used to order and group crash observations.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CrashClusterKey {
    exit_kind: String,
    crash_kind: String,
    http_status: Option<u16>,
    validation_error_discriminant: Option<String>,
    endpoint: Option<String>,
    response_class: ResponseClass,
}

impl std::fmt::Display for CrashClusterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}|{}|{}|{}|{}|{}",
            self.exit_kind,
            self.crash_kind,
            self.http_status.map(|s| s.to_string()).unwrap_or_default(),
            self.validation_error_discriminant.as_deref().unwrap_or(""),
            self.endpoint.as_deref().unwrap_or(""),
            self.response_class,
        )
    }
}

/// Coarse identity used to group crashes with similar characteristics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrashIdentity {
    pub exit_kind: ObservedExitKind,
    pub crash_kind: CrashKind,
    pub http_status: Option<u16>,
    pub validation_error_discriminant: Option<ValidationErrorDiscriminants>,
    pub endpoint: Option<String>,
    pub response_class: ResponseClass,
}

impl CrashIdentity {
    /// Returns the full key used for crash clustering.
    pub fn cluster_key(&self) -> CrashClusterKey {
        CrashClusterKey {
            exit_kind: self.exit_kind.to_string(),
            crash_kind: self.crash_kind.to_string(),
            http_status: self.http_status,
            validation_error_discriminant: self
                .validation_error_discriminant
                .as_ref()
                .map(|discriminant| format!("{discriminant:?}")),
            endpoint: self.endpoint.clone(),
            response_class: self.response_class,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> CrashIdentity {
        CrashIdentity {
            exit_kind: ObservedExitKind::Crash,
            crash_kind: CrashKind::Http5xx,
            http_status: Some(500),
            validation_error_discriminant: None,
            endpoint: Some("POST /users".into()),
            response_class: ResponseClass::Json,
        }
    }

    #[test]
    fn cluster_key_is_stable_for_equal_identities() {
        assert_eq!(identity().cluster_key(), identity().cluster_key());
    }

    #[test]
    fn full_cluster_key_preserves_current_string_format() {
        assert_eq!(
            identity().cluster_key().to_string(),
            "crash|http_5xx|500||POST /users|json"
        );
    }

    #[test]
    fn changed_identity_dimensions_change_the_cluster_key() {
        let baseline = identity();

        let mut different_endpoint = identity();
        different_endpoint.endpoint = Some("GET /users".into());
        assert_ne!(baseline.cluster_key(), different_endpoint.cluster_key());

        let mut different_status = identity();
        different_status.http_status = Some(502);
        assert_ne!(baseline.cluster_key(), different_status.cluster_key());

        let mut different_response_class = identity();
        different_response_class.response_class = ResponseClass::Html;
        assert_ne!(
            baseline.cluster_key(),
            different_response_class.cluster_key()
        );
    }
}
