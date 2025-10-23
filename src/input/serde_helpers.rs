//! Helper functions for (de)serializing Inputs.
//!
//! The yaml structure for requests has slightly different formats for the parameters
//! and the request body, but internally they are the same type. This requires a
//! conversion to an intermediate type, which happens in this module.

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
use serde::{
    de::{Deserialize, Deserializer, Error},
    ser::{Serialize, Serializer},
};
use serde_yaml::{
    Value,
    value::{Tag, TaggedValue},
};

use crate::input::parameter::{IReference, OReference, SimpleValue};

use super::{Body, Method, OpenApiRequest, ParameterContents, parameter::ParameterKind};

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

impl Serialize for ParameterContents {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            // These serialize normally:
            ParameterContents::Object(map) => map.serialize(serializer),
            ParameterContents::Array(arr) => arr.serialize(serializer),
            ParameterContents::LeafValue(v) => v.serialize(serializer),
            ParameterContents::Bytes(b) => {
                // First, serialize the bytes to base64 string
                let encoded_str = base64.encode(b);
                // Then wrap in a tagged value
                let tagged = Value::Tagged(Box::new(TaggedValue {
                    tag: Tag::new("RawBytes"),
                    value: Value::String(encoded_str),
                }));

                tagged.serialize(serializer)
            }

            // Custom tagged YAML serialization:
            ParameterContents::OReference(r) => {
                let val = serde_yaml::to_value(r).map_err(serde::ser::Error::custom)?;
                let tagged = Value::Tagged(Box::new(TaggedValue {
                    tag: Tag::new("ReferenceToEarlierResponse"),
                    value: val,
                }));
                tagged.serialize(serializer)
            }

            ParameterContents::IReference(r) => {
                let val = serde_yaml::to_value(r).map_err(serde::ser::Error::custom)?;
                let tagged = Value::Tagged(Box::new(TaggedValue {
                    tag: Tag::new("ReferenceToEarlierRequest"),
                    value: val,
                }));
                tagged.serialize(serializer)
            }
        }
    }
}

// Helper: convert serde_yaml::Value -> ParameterContents (recursive)
fn value_to_parameter_contents(val: Value) -> Result<ParameterContents, serde_yaml::Error> {
    use serde_yaml::value::TaggedValue;

    match val {
        Value::Tagged(boxed) => {
            let TaggedValue { tag, value } = *boxed;
            match tag.to_string().as_str() {
                "!ReferenceToEarlierResponse" => {
                    // Deserialize the inner mapping directly into OReference
                    let inner: OReference = serde_yaml::from_value(value)?;
                    Ok(ParameterContents::OReference(inner))
                }
                "!ReferenceToEarlierRequest" => {
                    let inner: IReference = serde_yaml::from_value(value)?;
                    Ok(ParameterContents::IReference(inner))
                }
                "!RawBytes" => {
                    // The value should be a string, decode base64
                    if let Value::String(s) = value.clone() {
                        let bytes = base64
                            .decode(s)
                            .expect("Failed to decode Base64-encoding into bytes.");
                        Ok(ParameterContents::Bytes(bytes))
                    } else {
                        Err(serde::de::Error::custom("RawBytes must be a string"))
                    }
                }
                // For any other tag (e.g. !String, !ApplicationJson, !Object, !Array, !RawBytes)
                // we drop the tag and recurse on the inner value.
                _ => value_to_parameter_contents(value),
            }
        }

        Value::Mapping(map) => {
            let mut out = BTreeMap::new();
            for (k, v) in map {
                // YAML keys can be non-strings. Convert to string when possible.
                let key_str = match k {
                    Value::String(s) => s,
                    Value::Bool(b) => b.to_string(),
                    Value::Number(n) => n.to_string(),
                    // If keys are complex nodes, you can choose how to handle them.
                    other => {
                        // Use YAML serialization as fallback to produce a key string
                        let s = serde_yaml::to_string(&other)?;
                        // trim newlines that serde_yaml::to_string may add
                        out.insert(s.trim().to_string(), value_to_parameter_contents(v)?);
                        continue;
                    }
                };
                let parsed_value = value_to_parameter_contents(v)?;
                out.insert(key_str, parsed_value);
            }
            Ok(ParameterContents::Object(out))
        }

        Value::Sequence(seq) => {
            let mut vec = Vec::with_capacity(seq.len());
            for item in seq {
                vec.push(value_to_parameter_contents(item)?);
            }
            Ok(ParameterContents::Array(vec))
        }

        Value::String(s) => Ok(ParameterContents::LeafValue(SimpleValue::String(s))),

        Value::Number(n) => {
            // Convert YAML number into f64 for SimpleValue::Number (adjust if needed)
            let f = n
                .as_f64()
                .ok_or_else(|| -> serde_yaml::Error { Error::custom("invalid number") })?;
            Ok(ParameterContents::LeafValue(SimpleValue::Number(
                serde_json::Number::from_f64(f).unwrap(),
            )))
        }

        Value::Bool(b) => Ok(ParameterContents::LeafValue(SimpleValue::Bool(b))),
        Value::Null => Ok(ParameterContents::LeafValue(SimpleValue::Null)),
    }
}

// Implement Deserialize by first reading a serde_yaml::Value then converting.
impl<'de> Deserialize<'de> for ParameterContents {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = Value::deserialize(deserializer)?;
        value_to_parameter_contents(val)
            .map_err(|e| D::Error::custom(format!("Deserialization failed: {e}")))
    }
}
