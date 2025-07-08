//! Helper functions for (de)serializing Inputs.
//!
//! The yaml structure for requests has slightly different formats for the parameters
//! and the request body, but internally they are the same type. This requires a
//! conversion to an intermediate type, which happens in this module.

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
use serde::{
    de::{self, Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};

use super::{Body, Method, OpenApiRequest, ParameterContents, parameter::ParameterKind};

pub(crate) fn serialize_bytes_to_b64<S>(bi: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    base64.encode(bi).serialize(serializer)
}
pub(crate) fn deserialize_bytes_from_b64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    base64.decode(s.as_bytes()).map_err(de::Error::custom)
}

/// A helper struct to serialize `OpenApiRequest`s. It is identical to the
/// original, but the contained `Body` type is serialized differently.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SerializableOpenApiRequest {
    method: Method,
    path: String,

    #[serde(default, skip_serializing_if = "Body::is_empty")]
    body: Body,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    parameters: BTreeMap<(String, ParameterKind), ParameterContents>,
}

impl From<OpenApiRequest> for SerializableOpenApiRequest {
    fn from(request: OpenApiRequest) -> Self {
        Self {
            method: request.method,
            path: request.path,
            body: request.body,
            parameters: request.parameters,
        }
    }
}

impl From<SerializableOpenApiRequest> for OpenApiRequest {
    fn from(request: SerializableOpenApiRequest) -> Self {
        Self {
            method: request.method,
            path: request.path,
            body: request.body,
            parameters: request.parameters,
        }
    }
}
