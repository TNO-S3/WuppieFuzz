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
            ParameterAccessElement::Name(name) => write!(f, "{}", name),
            ParameterAccessElement::Offset(offset) => write!(f, "{}", offset),
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
        log::warn!("{:?}", self.0);
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
        Self::from_elements(&value.to_vec())
    }
}

impl From<&ParameterAccess> for ParameterKind {
    fn from(value: &ParameterAccess) -> Self {
        match value {
            ParameterAccess::Body(_) => Self::Body,
            ParameterAccess::Query(_) => Self::Query,
            ParameterAccess::Path(_) => Self::Path,
            ParameterAccess::Header(_) => Self::Header,
            ParameterAccess::Cookie(_) => Self::Cookie,
        }
    }
}

/// See [module level documentation](crate::parameter_access).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParameterAccess {
    // Request(RequestParameterAccess),
    // Response(ResponseParameterAccess),
    Body(ParameterAccessElements),
    Query(String),
    Path(String),
    Header(String),
    Cookie(String),
}

impl ParameterAccess {
    pub fn simple_name(&self) -> &str {
        match self {
            Self::Body(_) => "",
            Self::Query(name) | Self::Path(name) | Self::Header(name) | Self::Cookie(name) => name,
        }
    }
    pub(crate) fn request_query(name: String) -> Self {
        Self::Query(name)
    }
    pub(crate) fn request_path(name: String) -> Self {
        Self::Path(name)
    }
    pub(crate) fn request_body(elements: ParameterAccessElements) -> Self {
        Self::Body(elements)
    }
    pub(crate) fn response_body(elements: ParameterAccessElements) -> Self {
        Self::Body(elements)
    }
    pub fn create_of_kind(
        kind: ParameterKind,
        string_contents: Option<String>,
        access_contents: Option<ParameterAccessElements>,
    ) -> Self {
        match kind {
            ParameterKind::Path => Self::Path(string_contents.unwrap()),
            ParameterKind::Query => Self::Query(string_contents.unwrap()),
            ParameterKind::Header => Self::Header(string_contents.unwrap()),
            ParameterKind::Cookie => Self::Cookie(string_contents.unwrap()),
            ParameterKind::Body => Self::Body(access_contents.unwrap()),
        }
    }
    pub fn get_body_access_elements(&self) -> Option<&ParameterAccessElements> {
        if let Self::Body(elements) = self {
            Some(elements)
        } else {
            log::warn!("Trying to get access elements from non-body RequestParameterAccess");
            None
        }
    }
    pub fn matches(&self, param: &openapiv3::Parameter) -> bool {
        ParameterKind::from(param) == self.into() && param.name == self.simple_name()
    }
    pub(crate) fn with_new_element(&self, new_element: ParameterAccessElement) -> Self {
        match self {
            ParameterAccess::Body(access_elements) => {
                Self::request_body(access_elements.with_new_element(new_element))
            }
            _ => panic!(
                "Trying to add element to {self:?}, but with_new_element is only sensible for Body variants."
            ),
        }
    }
}

impl Display for ParameterAccess {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ParameterAccess::Body(parameter_access) => parameter_access.fmt(f),
            ParameterAccess::Query(value)
            | ParameterAccess::Path(value)
            | ParameterAccess::Header(value)
            | ParameterAccess::Cookie(value) => write!(f, "{value}"),
        }
    }
}

/// A matching between an output- and input parameter that represents a link between these,
/// indicating that the input parameter could contain a backreference to the output parameter.
#[derive(Debug, Clone, PartialEq)]
pub struct ParameterMatching {
    pub(crate) output_access: ParameterAccess,
    pub(crate) input_access: ParameterAccess,
    pub(crate) input_name_normalized: String,
}
