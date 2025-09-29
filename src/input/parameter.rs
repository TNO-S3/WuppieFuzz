use std::{
    borrow::Cow,
    collections::BTreeMap,
    fmt::{Debug, Display, Formatter, Result},
};

use base64::{Engine as _, display::Base64Display, engine::general_purpose::STANDARD};
use libafl_bolts::rands::Rand;
use openapiv3::Parameter;
use reqwest::header::HeaderValue;
use serde_json::{Map, Number, Value};

use super::utils::new_rand_input;
use crate::parameter_access::{ParameterAccess, ParameterAccessElement, ParameterAccessElements};

/// Structs that help describe parameters to HTTP requests in a way that the fuzzer can still
/// mutate and reason about. The ParameterKind enum describes the places a parameter can occur
/// (query, header etc.);
///
/// the Kind together with the parameter name must be unique within a request/operation.
/// The ParameterContents enum describes the different kinds of value a parameter can take,
/// e.g. an array, or a string, or a reference to the output of a previous request.
///
/// See also: dependency graph module

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Hash)]
pub enum SimpleValue {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
}

impl SimpleValue {
    pub fn to_value(&self) -> Value {
        match self {
            SimpleValue::Null => Value::Null,
            SimpleValue::Bool(val) => Value::Bool(*val),
            SimpleValue::Number(val) => Value::Number(val.clone()),
            SimpleValue::String(val) => Value::String(val.clone()),
        }
    }
}

impl From<SimpleValue> for Value {
    fn from(value: SimpleValue) -> Self {
        match value {
            SimpleValue::Null => Value::Null,
            SimpleValue::Bool(val) => Value::Bool(val),
            SimpleValue::Number(val) => Value::Number(val),
            SimpleValue::String(val) => Value::String(val),
        }
    }
}

impl Display for SimpleValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        Display::fmt(&self.to_value(), f)
    }
}

/// The contents of a parameter or of the body of an HTTP request made by the fuzzer.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Hash)]
#[serde(tag = "DataType", content = "Contents")]
pub enum ParameterContents {
    /// If the parameter type is one of `object`, `array` or `leaf_value`, it is a
    /// structured value we can reason about.
    /// Mutators can attempt to mutate it using knowledge of the type, i.e. numbers
    /// will always be mutated into other numbers, and array elements can be shuffled.
    #[serde(rename = "Object")]
    Object(BTreeMap<String, ParameterContents>),
    #[serde(rename = "Array")]
    Array(Vec<ParameterContents>),
    #[serde(rename = "PrimitiveValue")]
    LeafValue(SimpleValue),

    /// If the parameter type is `bytes_b64`, it represents arbitrary binary contents.
    /// This is normally only encountered in the request body. Mutators will attempt
    /// to mutate it using bit-flips, byte swaps and the like.
    ///
    /// This parameter is named `bytes_b64` in the serialization to make clear that it
    /// should be encoded using Base64. It is stored unencoded internally, and is not
    /// required to be a valid String.
    #[serde(rename = "RawBytes")]
    #[serde(serialize_with = "super::serde_helpers::serialize_bytes_to_b64")]
    #[serde(deserialize_with = "super::serde_helpers::deserialize_bytes_from_b64")]
    Bytes(Vec<u8>),

    /// If the parameter type is `reference`, it represents a value copied from an
    /// earlier request's response. For instance, the fuzzer might attempt to insert a
    /// record, receive an ID in return, and make further HTTP requests to amend the
    /// record by giving the returned ID parameter as the ID parameter of the later
    /// requests.
    #[serde(rename = "ReferenceToEarlierResponse")]
    Reference {
        #[serde(rename = "request")]
        request_index: usize,
        #[serde(rename = "parameter_name")]
        parameter_access: ParameterAccess,
    },
}

impl ParameterContents {
    /// Returns whether the `ParameterContents` is the `reference` variant.
    pub fn is_reference(&self) -> bool {
        matches!(self, ParameterContents::Reference { .. })
    }

    /// Returns the bytes-representation of this `ParameterContents`.
    /// If this is the `bytes` variant, a reference is returned.
    /// If this is the `contents` variant, the contained object is serialized into
    /// a new `Vec<u8>`.
    /// If this is an unresolved reference, `None` is returned.
    pub fn bytes(&self) -> Option<Cow<'_, [u8]>> {
        match self {
            ParameterContents::Object(v) => {
                let mut json_map = Map::new();
                for (k, v) in v.iter() {
                    json_map.insert(k.clone().to_string(), v.to_value());
                }
                Some(Value::Object(json_map).to_string().into_bytes().into())
            }
            ParameterContents::Array(arr) => {
                let json_list: Vec<Value> = arr.iter().map(|x| x.clone().to_value()).collect();
                Some(Value::Array(json_list).to_string().into_bytes().into())
            }
            ParameterContents::LeafValue(val) => Some(val.to_string().into_bytes().into()),
            ParameterContents::Bytes(bi) => Some(bi.into()),
            ParameterContents::Reference { .. } => None,
        }
    }

    /// Breaks a `reference` variant of a `ParameterContents` if it targets a request number
    /// for which `f` returns true. Inserts a `bytes` variant with random contents instead.
    pub fn break_reference_if_target<F, R>(&mut self, rand: &mut R, f: F)
    where
        R: Rand,
        F: Fn(usize) -> bool,
    {
        match self {
            ParameterContents::Reference { request_index, .. } if f(*request_index) => {
                *self = ParameterContents::Bytes(new_rand_input(rand));
            }
            _ => (),
        }
    }

    /// Returns the mutable index of a `reference` variant of a `ParameterContents`.
    pub fn reference_index(&mut self) -> Option<&mut usize> {
        match self {
            ParameterContents::Reference { request_index, .. } => Some(request_index),
            _ => None,
        }
    }

    pub fn to_value(&self) -> serde_json::Value {
        match self {
            ParameterContents::Object(content) => {
                let mut json_map = Map::new();
                for (key, val) in content {
                    json_map.insert(key.clone().to_string(), val.to_value());
                }
                Value::Object(json_map)
            }
            ParameterContents::Array(arr) => arr.iter().map(|val| val.to_value()).collect(),
            ParameterContents::LeafValue(val) => val.to_value(),
            ParameterContents::Bytes(bytes) => {
                // Creating a value from random bytes is kind of hard, since serde_json
                // plays way too nice and insists on valid json, therefore a valid String.
                // However, we can't really change this behaviour easily...
                serde_json::Value::String(String::from_utf8_lossy(bytes).to_string())
            }
            ParameterContents::Reference { .. } => {
                panic!("Can not make a reqwest body out of a ParameterContents::Reference")
            }
        }
    }

    /// Returns the parameter value for use in a URL.
    pub fn to_url_encoding(&self) -> Cow<'_, str> {
        match self {
            ParameterContents::Bytes(bytes) => urlencoding::encode_binary(bytes),
            ParameterContents::LeafValue(SimpleValue::String(string)) => {
                urlencoding::encode(string)
            }
            _ => urlencoding::encode(&self.to_string()).into_owned().into(),
        }
    }

    /// Returns the parameter value for use as a header value:
    /// the Bytes variant is uses as-is where possible, otherwise mime-encoded.
    /// Other value types are formatted as a string.
    pub fn to_header_value(&self) -> HeaderValue {
        match self {
            ParameterContents::Bytes(bytes) => match HeaderValue::from_bytes(bytes) {
                Ok(header) => header,
                Err(_) => HeaderValue::from_str(&mime_encode_bytes(bytes))
                    .expect("Mime encoding was not valid string??"),
            },
            _ => HeaderValue::from_str(&self.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("")),
        }
    }

    /// Returns the parameter value for use as a cookie value:
    /// the Bytes variant is mime-encoded, any other value is formatted to a String.
    pub fn to_cookie_value(&self) -> String {
        match self {
            ParameterContents::Bytes(bytes) => mime_encode_bytes(bytes),
            _ => self.to_string(),
        }
    }

    pub fn resolve_mut(&mut self, path: &ParameterAccessElements) -> Option<&mut Self> {
        let mut result = self;
        for path_element in &path.0 {
            match (result, path_element) {
                (ParameterContents::Object(mapping), ParameterAccessElement::Name(name)) => {
                    result = mapping.get_mut(name)?
                }
                (ParameterContents::Array(vector), ParameterAccessElement::Offset(index)) => {
                    result = vector.get_mut(*index)?
                }
                _ => return None,
            }
        }
        Some(result)
    }

    /// Returns a nested field of this ParameterContents, as addressed by the parameter_access.
    /// If the addressing does not identify a field (by having bad field names, out-of-bound indexes,
    /// or too many elements), None is returned.
    pub fn resolve(&self, parameter_access: &ParameterAccess) -> Option<&Self> {
        let mut result = self;
        let elements = parameter_access.get_body_access_elements().unwrap();
        for path_element in &elements.0 {
            match (result, path_element) {
                (ParameterContents::Object(mapping), ParameterAccessElement::Name(name)) => {
                    result = mapping.get(name)?
                }
                (ParameterContents::Array(vector), ParameterAccessElement::Offset(index)) => {
                    result = vector.get(*index)?
                }
                _ => return None,
            }
        }
        Some(result)
    }
}

impl Display for ParameterContents {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            ParameterContents::Object(obj) => write!(f, "{:?}", &obj),
            ParameterContents::Array(arr) => write!(f, "{:?}", &arr),
            ParameterContents::LeafValue(v) => Display::fmt(&v, f),
            ParameterContents::Bytes(bi) => Base64Display::new(bi, &STANDARD).fmt(f),
            ParameterContents::Reference {
                request_index,
                parameter_access,
            } => write!(
                f,
                "parameter {parameter_access} from request {request_index}"
            ),
        }
    }
}

impl From<BTreeMap<String, ParameterContents>> for ParameterContents {
    fn from(value: BTreeMap<String, ParameterContents>) -> Self {
        ParameterContents::Object(value)
    }
}

impl From<String> for ParameterContents {
    fn from(value: String) -> Self {
        Self::LeafValue(SimpleValue::String(value))
    }
}

impl From<bool> for ParameterContents {
    fn from(value: bool) -> Self {
        Self::LeafValue(SimpleValue::Bool(value))
    }
}

impl From<Number> for ParameterContents {
    fn from(value: Number) -> Self {
        Self::LeafValue(SimpleValue::Number(value))
    }
}

impl From<Value> for ParameterContents {
    fn from(value: Value) -> Self {
        match value {
            Value::Null => Self::LeafValue(SimpleValue::Null),
            Value::Bool(val) => Self::from(val),
            Value::Number(val) => Self::from(val),
            Value::String(val) => Self::from(val),
            Value::Array(arr) => {
                Self::Array(arr.into_iter().map(ParameterContents::from).collect())
            }
            Value::Object(content) => Self::Object(
                content
                    .into_iter()
                    .map(|(key, val)| (key, ParameterContents::from(val)))
                    .collect(),
            ),
        }
    }
}

/// Helper enum to differentiate between different kinds of parameters. Implements Eq, unlike
/// the openapiv3::Parameter, so we can use it as a filter.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum ParameterKind {
    Path,
    Query,
    Header,
    Cookie,

    // The Body variant is not used in the OpenApiRequest itself, since there is a separate
    // (optional) Body field. However, the input/output graph generation benefits from having
    // this variant to annotate parameters with the place they appear in.
    // TODO: maybe later also refactor the request type so the body fields are stored as
    // parameters. It ignores the possibility that the body is, say, audio/mp3, but we assume
    // json anyway, so...
    Body,
}

impl ParameterKind {
    pub fn matches(&self, parameter: &Parameter) -> bool {
        self == &parameter.into()
    }
}

impl From<&Parameter> for ParameterKind {
    fn from(parameter: &Parameter) -> Self {
        match parameter.kind {
            openapiv3::ParameterKind::Query { .. } => Self::Query,
            openapiv3::ParameterKind::Header { .. } => Self::Header,
            openapiv3::ParameterKind::Path { .. } => Self::Path,
            openapiv3::ParameterKind::Cookie { .. } => Self::Cookie,
        }
    }
}

/// Return the Mime utf-8 + base-64 encoding of a byte array.
fn mime_encode_bytes(bytes: &[u8]) -> String {
    String::from("=?UTF-8?B?") + &base64::engine::general_purpose::STANDARD.encode(bytes) + "?="
}
