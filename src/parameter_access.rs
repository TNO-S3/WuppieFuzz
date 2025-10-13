//! ParameterAccess identifies a field in a request or response, in a header, body, path, cookie, etc.
//! This is used for two (related) purposes:
//!
//! 1. Store references to values in responses to earlier requests, e.g. to reuse an ID returned by
//!    the server in a later request.
//! 2. To create normalized versions of parameters in both requests and responses. These normalizations
//!    are then used to link some request parameters to earlier response parameters, so in this case it
//!    is useful to have a way to identify a request parameter so it can be replaced with a reference.
//!
//! For non-body fields, the identifier is simply a string with the name of the variable.
//! For body fields parameters can be nested in objects and lists, in which case we use
//! [a list](ParameterAccessElements) with elements of type [`ParameterAccessElement`](ParameterAccessElement)
//! which are used to "descend" into body structures to identify a field.

use std::{
    fmt::{Display, Formatter},
    hash::Hash,
};

use openapiv3::Schema;
use serde::{Deserialize, Serialize};

use crate::input::parameter::ParameterKind;

#[derive(
    Clone, Debug, serde::Serialize, serde::Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord,
)]
pub enum ParameterAccessElement {
    /// Identifies a field in an object
    Name(String),
    /// Identifies an item in a list
    Offset(usize),
}

impl Display for ParameterAccessElement {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ParameterAccessElement::Name(name) => write!(f, "{name}"),
            ParameterAccessElement::Offset(offset) => write!(f, "{offset}"),
        }
    }
}

impl From<String> for ParameterAccessElement {
    fn from(value: String) -> Self {
        if value.chars().all(|c| c.is_ascii_digit()) {
            Self::Offset(value.parse().unwrap())
        } else {
            Self::Name(value)
        }
    }
}

impl From<usize> for ParameterAccessElement {
    fn from(value: usize) -> Self {
        Self::Offset(value)
    }
}

#[derive(
    Default,
    Clone,
    Debug,
    serde::Serialize,
    serde::Deserialize,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct ParameterAccessElements(pub Vec<ParameterAccessElement>);

impl ParameterAccessElements {
    pub fn new() -> Self {
        Self(vec![])
    }

    pub fn from_elements(elements: &[ParameterAccessElement]) -> Self {
        Self(elements.to_vec())
    }

    pub fn parameter_accesses_from_schema(
        parent_access: ParameterAccessElements,
        schema: &openapiv3::RefOr<Schema>,
        api: &openapiv3::OpenAPI,
    ) -> Vec<ParameterAccessElements> {
        match schema.resolve(api).kind {
            openapiv3::SchemaKind::Type(openapiv3::Type::Object(ref obj)) => obj
                .properties
                .iter()
                .flat_map(|(name, child_schema)| {
                    let mut accesses = vec![];
                    let current_access =
                        parent_access.with_new_element(ParameterAccessElement::Name(name.clone()));
                    accesses.push(current_access.clone());
                    accesses.extend(Self::parameter_accesses_from_schema(
                        current_access,
                        child_schema,
                        api,
                    ));
                    accesses
                })
                .collect(),
            _ => vec![],
        }
    }

    pub fn with_new_element(&self, new_element: ParameterAccessElement) -> Self {
        let mut elements = self.0.clone();
        elements.push(new_element);
        Self::from_elements(&elements)
    }
}

impl Display for ParameterAccessElements {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.0
                .clone()
                .into_iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>()
                .join("/")
        )
    }
}

impl From<&[ParameterAccessElement]> for ParameterAccessElements {
    fn from(value: &[ParameterAccessElement]) -> Self {
        Self::from_elements(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RequestParameterAccess {
    Body(ParameterAccessElements),
    Query(String),
    Path(String),
    Header(String),
    Cookie(String),
}

impl Display for RequestParameterAccess {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Body(parameter_access) => parameter_access.fmt(f),
            Self::Query(value) | Self::Path(value) | Self::Header(value) | Self::Cookie(value) => {
                write!(f, "{value}")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResponseParameterAccess {
    Body(ParameterAccessElements),
    Header(String),
    Cookie(String),
}

impl Display for ResponseParameterAccess {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Body(parameter_access) => parameter_access.fmt(f),
            Self::Header(value) | Self::Cookie(value) => {
                write!(f, "{value}")
            }
        }
    }
}

/// See [module level documentation](crate::parameter_access).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParameterAccess {
    #[serde(with = "serde_yaml::with::singleton_map")]
    Request(RequestParameterAccess),
    #[serde(with = "serde_yaml::with::singleton_map")]
    Response(ResponseParameterAccess),
}

impl ParameterAccess {
    pub fn simple_name(&self) -> &str {
        match self {
            ParameterAccess::Request(request_parameter_access) => match request_parameter_access {
                RequestParameterAccess::Body(_) => "",
                RequestParameterAccess::Query(name)
                | RequestParameterAccess::Path(name)
                | RequestParameterAccess::Header(name)
                | RequestParameterAccess::Cookie(name) => name,
            },
            ParameterAccess::Response(response_parameter_access) => {
                match response_parameter_access {
                    ResponseParameterAccess::Body(_) => "",
                    ResponseParameterAccess::Header(name)
                    | ResponseParameterAccess::Cookie(name) => name,
                }
            }
        }
    }
    pub fn unwrap_request_variant(&self) -> &RequestParameterAccess {
        if let Self::Request(request_variant) = self {
            request_variant
        } else {
            panic!(
                "Tried to unwrap a ParamterAccess as a Request variant, but it contains a Response variant!"
            )
        }
    }
    pub(crate) fn request_query(name: String) -> Self {
        Self::Request(RequestParameterAccess::Query(name))
    }
    pub(crate) fn request_path(name: String) -> Self {
        Self::Request(RequestParameterAccess::Path(name))
    }
    pub(crate) fn request_header(name: String) -> Self {
        Self::Request(RequestParameterAccess::Header(name))
    }
    pub(crate) fn request_cookie(name: String) -> Self {
        Self::Request(RequestParameterAccess::Cookie(name))
    }
    pub(crate) fn request_body(elements: ParameterAccessElements) -> Self {
        Self::Request(RequestParameterAccess::Body(elements))
    }
    pub(crate) fn response_body(elements: ParameterAccessElements) -> Self {
        Self::Response(ResponseParameterAccess::Body(elements))
    }
    pub(crate) fn response_cookie(name: String) -> Self {
        Self::Response(ResponseParameterAccess::Cookie(name))
    }
    pub fn get_body_access_elements(&self) -> Option<&ParameterAccessElements> {
        let warn_text = "Trying to get access elements from non-body RequestParameterAccess";
        match self {
            ParameterAccess::Request(request_parameter_access) => match request_parameter_access {
                RequestParameterAccess::Body(parameter_access_elements) => {
                    Some(parameter_access_elements)
                }
                _ => {
                    log::warn!("{}", warn_text);
                    None
                }
            },
            ParameterAccess::Response(response_parameter_access) => match response_parameter_access
            {
                ResponseParameterAccess::Body(parameter_access_elements) => {
                    Some(parameter_access_elements)
                }
                _ => {
                    log::warn!("{}", warn_text);
                    None
                }
            },
        }
    }
    pub fn matches(&self, param: &openapiv3::Parameter) -> bool {
        ParameterKind::from(param) == self.into() && param.name == self.simple_name()
    }
    pub(crate) fn with_new_element(&self, new_element: ParameterAccessElement) -> Self {
        match self {
            ParameterAccess::Request(request_parameter_access) => {
                if let RequestParameterAccess::Body(access_elements) = request_parameter_access {
                    Self::request_body(access_elements.with_new_element(new_element))
                } else {
                    panic!(
                        "Trying to add element to Request {self:?}, but with_new_element is only sensible for Body variants."
                    )
                }
            }
            ParameterAccess::Response(response_parameter_access) => {
                if let ResponseParameterAccess::Body(access_elements) = response_parameter_access {
                    Self::request_body(access_elements.with_new_element(new_element))
                } else {
                    panic!(
                        "Trying to add element to Response {self:?}, but with_new_element is only sensible for Body variants."
                    )
                }
            }
        }
    }
}

impl Display for ParameterAccess {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ParameterAccess::Request(request_parameter_access) => request_parameter_access.fmt(f),
            ParameterAccess::Response(response_parameter_access) => {
                response_parameter_access.fmt(f)
            }
        }
    }
}

/// A matching between two parameters from different requests that represents a link between these.
/// There are two types of ParameterMatching:
///
/// 1. Request: matches two request parameters so they contain the same value (e.g. a client-provided id).
///             this could be resolved at corpus-generation time into a static value, but keeping it as
///             a reference ensures that the link is kept when mutating the input value.  
/// 2. Response: indicates that the input parameter could contain a backreference to the output parameter
///              for which a value was returned by the server. Necessarily resolved at runtime.
///
#[derive(Debug, Clone, PartialEq)]
pub enum ParameterMatching {
    Request {
        output_access: ParameterAccess,
        input_access: ParameterAccess,
        input_name_normalized: String,
    },
    Response {
        output_access: ParameterAccess,
        input_access: ParameterAccess,
        input_name_normalized: String,
    },
}

impl ParameterMatching {
    pub(crate) fn input_access(&self) -> &ParameterAccess {
        match self {
            ParameterMatching::Request { input_access, .. } => input_access,
            ParameterMatching::Response { input_access, .. } => input_access,
        }
    }
    pub(crate) fn output_access(&self) -> &ParameterAccess {
        match self {
            ParameterMatching::Request { output_access, .. } => output_access,
            ParameterMatching::Response { output_access, .. } => output_access,
        }
    }
    pub(crate) fn input_name_normalized(&self) -> &str {
        match self {
            ParameterMatching::Request {
                input_name_normalized,
                ..
            } => input_name_normalized,
            ParameterMatching::Response {
                input_name_normalized,
                ..
            } => input_name_normalized,
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone)]
pub(crate) struct ParameterAddressing {
    pub(crate) request_index: usize,
    pub(crate) access: ParameterAccess,
}

impl ParameterAddressing {
    pub fn new(request_index: usize, access: ParameterAccess) -> Self {
        Self {
            request_index,
            access,
        }
    }
}

impl From<(usize, ParameterAccess)> for ParameterAddressing {
    fn from(value: (usize, ParameterAccess)) -> Self {
        Self {
            request_index: value.0,
            access: value.1,
        }
    }
}
