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
    Name(String),
    Offset(usize),
}

impl Display for ParameterAccessElement {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ParameterAccessElement::Name(name) => name.clone(),
                ParameterAccessElement::Offset(offset) => offset.to_string(),
            }
        )
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
pub struct ParameterAccess {
    pub elements: Vec<ParameterAccessElement>,
}

impl ParameterAccess {
    pub fn new(elements: Vec<ParameterAccessElement>) -> Self {
        let result = Self {
            elements: elements.clone(),
        };
        result
    }

    pub fn parameter_accesses_from_schema(
        parent_access: ParameterAccess,
        schema: &openapiv3::RefOr<Schema>,
        api: &openapiv3::OpenAPI,
    ) -> Vec<ParameterAccess> {
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
        let mut elements = self.elements.clone();
        elements.push(new_element);
        Self::new(elements)
    }

    pub fn into_parameter_name(&self) -> &str {
        if let ParameterAccessElement::Name(name) = &self.elements[0] {
            name
        } else {
            todo!("Need to decide on how to handle invalid conversion to parameter name")
        }
    }
}

impl Display for ParameterAccess {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.elements
                .clone()
                .into_iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>()
                .join("/")
        )
    }
}

impl From<&[ParameterAccessElement]> for ParameterAccess {
    fn from(value: &[ParameterAccessElement]) -> Self {
        Self::new(value.to_vec())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
pub enum ResponseParameterAccess {
    Body(ParameterAccess),
    Cookie(String),
}

impl ResponseParameterAccess {
    fn simple_name(&self) -> &str {
        match self {
            Self::Body(_) => "",
            Self::Cookie(name) => &name,
        }
    }

    // pub fn with_new_element(&self, new_element: ParameterAccessElement) -> Self {
    //     let mut elements = self.elements.clone();
    //     elements.push(new_element);
    //     Self::new(elements)
    // }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RequestParameterAccess {
    Body(ParameterAccess),
    Query(String),
    Path(String),
    Header(String),
    Cookie(String),
}

impl RequestParameterAccess {
    fn simple_name(&self) -> &str {
        match self {
            Self::Body(_) => "",
            Self::Query(name) | Self::Path(name) | Self::Header(name) | Self::Cookie(name) => &name,
        }
    }

    pub fn matches(&self, param: &openapiv3::Parameter) -> bool {
        ParameterKind::from(param) == self.into() && param.name == self.simple_name()
    }
}

impl From<&RequestParameterAccess> for ParameterKind {
    fn from(value: &RequestParameterAccess) -> Self {
        match value {
            RequestParameterAccess::Body(_) => Self::Body,
            RequestParameterAccess::Query(_) => Self::Query,
            RequestParameterAccess::Path(_) => Self::Path,
            RequestParameterAccess::Header(_) => Self::Header,
            RequestParameterAccess::Cookie(_) => Self::Cookie,
        }
    }
}

/// A parameter name saved in two variants: the canonical name appearing as the
/// output parameter in the spec, the canonical name appearing as the input parameter
/// in the spec.
#[derive(Debug, Clone, PartialEq)]
pub struct ParameterMatching {
    pub(crate) name_output: ParameterAccess,
    pub(crate) name_input: RequestParameterAccess,
    normalized: String,
}
