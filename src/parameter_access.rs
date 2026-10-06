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

use oas3::spec::{ObjectOrReference, Parameter, Schema};
use serde::{Deserialize, Serialize};

use crate::{input::parameter::ParameterKind, openapi::spec::Spec};

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

    /// Lists all parameter accesses (field names and, recursively, their
    /// nested fields) reachable from `schema`.
    ///
    /// Schemas can be mutually recursive (e.g. `User` has a field of type
    /// `UserIdentity`, which in turn has a field of type `User`), so this
    /// tracks the `$ref` paths already followed on the current path and stops
    /// recursing once one would be followed again, mirroring
    /// `interesting_values_for_schema`'s cycle handling in
    /// `openapi::examples`. A recursion depth limit is kept as a backstop for
    /// long chains of distinct (non-repeating) `$ref`s, which the cycle check
    /// alone does not bound.
    pub fn parameter_accesses_from_schema(
        parent_access: ParameterAccessElements,
        schema: &Schema,
        api: &Spec,
    ) -> Vec<ParameterAccessElements> {
        Self::parameter_accesses_from_schema_impl(parent_access, schema, api, &[], 0)
    }

    fn parameter_accesses_from_schema_impl(
        parent_access: ParameterAccessElements,
        schema: &Schema,
        api: &Spec,
        ignore_reference_names: &[&str],
        recursion_depth: usize,
    ) -> Vec<ParameterAccessElements> {
        if parameter_access_recursion_limit_exceeded(recursion_depth) {
            return vec![];
        }

        let mut ignore_references = ignore_reference_names.to_owned();
        if let Some(ref_path) = ref_path_of(schema) {
            if ignore_references.contains(&ref_path) {
                return vec![];
            }
            ignore_references.push(ref_path);
        }

        let resolved = match schema.resolve(api) {
            Ok(resolved) => resolved,
            Err(_) => return vec![],
        };

        let object_schema = match resolved {
            Schema::Boolean(_) => return vec![],
            Schema::Object(object_or_reference) => match *object_or_reference {
                ObjectOrReference::Object(object_schema) => object_schema,
                ObjectOrReference::Ref { .. } => return vec![],
            },
        };

        object_schema
            .properties
            .iter()
            .flat_map(|(name, child_schema)| {
                let mut accesses = vec![];
                let current_access =
                    parent_access.with_new_element(ParameterAccessElement::Name(name.clone()));
                accesses.push(current_access.clone());
                accesses.extend(Self::parameter_accesses_from_schema_impl(
                    current_access,
                    child_schema,
                    api,
                    &ignore_references,
                    recursion_depth + 1,
                ));
                accesses
            })
            .collect()
    }

    pub fn with_new_element(&self, new_element: ParameterAccessElement) -> Self {
        let mut elements = self.0.clone();
        elements.push(new_element);
        Self::from_elements(&elements)
    }
}

/// Returns the `$ref` path of `schema`, if it is a reference rather than an
/// inline schema.
fn ref_path_of(schema: &Schema) -> Option<&str> {
    match schema {
        Schema::Object(object_or_reference) => match object_or_reference.as_ref() {
            ObjectOrReference::Ref { ref_path, .. } => Some(ref_path),
            ObjectOrReference::Object(_) => None,
        },
        Schema::Boolean(_) => None,
    }
}

/// Returns `true` once the recursion depth has reached the limit (20). Unlike
/// `openapi::examples`'s analogous guard, this one is hit on every fuzzing
/// iteration (not just once during corpus generation) whenever a spec has
/// deeply nested or (previously) cyclic schemas, so the warning is only
/// logged once per process to avoid flooding the terminal.
fn parameter_access_recursion_limit_exceeded(recursion_depth: usize) -> bool {
    static WARNED: std::sync::Once = std::sync::Once::new();
    crate::recursion::recursion_limit_exceeded(recursion_depth, 20, &WARNED, || {
        format!(
            "Parameter access resolution exceeds {recursion_depth} steps for at least one \
             schema, this will result in some response fields not being available for the link \
             mutator. This is likely due to a deeply nested or circular schema (further \
             occurrences of this warning are suppressed)."
        )
    })
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
    pub fn get_body_access_elements(&self) -> Result<&ParameterAccessElements, &str> {
        let error_text = "Trying to get access elements from non-body ParameterAccess";
        match self {
            ParameterAccess::Request(request_parameter_access) => match request_parameter_access {
                RequestParameterAccess::Body(parameter_access_elements) => {
                    Ok(parameter_access_elements)
                }
                _ => Err(error_text),
            },
            ParameterAccess::Response(response_parameter_access) => match response_parameter_access
            {
                ResponseParameterAccess::Body(parameter_access_elements) => {
                    Ok(parameter_access_elements)
                }
                _ => Err(error_text),
            },
        }
    }
    pub fn get_non_body_access_element(&self) -> Result<String, &str> {
        let error_text = "Trying to get simple parameter name from body ParameterAccess";
        match self {
            ParameterAccess::Request(request_parameter_access) => match request_parameter_access {
                RequestParameterAccess::Body(_) => Err(error_text),
                RequestParameterAccess::Query(name)
                | RequestParameterAccess::Path(name)
                | RequestParameterAccess::Header(name)
                | RequestParameterAccess::Cookie(name) => Ok(name.clone()),
            },
            ParameterAccess::Response(response_parameter_access) => {
                match response_parameter_access {
                    ResponseParameterAccess::Body(_) => Err(error_text),
                    ResponseParameterAccess::Header(name)
                    | ResponseParameterAccess::Cookie(name) => Ok(name.clone()),
                }
            }
        }
    }
    pub fn matches(&self, param: Parameter) -> bool {
        ParameterKind::from(param.clone()) == self.into() && param.name == self.simple_name()
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
                    Self::response_body(access_elements.with_new_element(new_element))
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
///    this could be resolved at corpus-generation time into a static value, but keeping it as
///    a reference ensures that the link is kept when mutating the input value.  
/// 2. Response: indicates that the input parameter could contain a backreference to the output parameter
///    for which a value was returned by the server. Necessarily resolved at runtime.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal `Spec` whose `components.schemas` contains two
    /// mutually-recursive schemas: `User` has a field of type `UserIdentity`,
    /// which in turn has a field of type `User` (e.g. a "last logged in as"
    /// back-reference). This mirrors the real-world spec (scout-api) that
    /// previously caused `parameter_accesses_from_schema` to recurse
    /// indefinitely and overflow the stack.
    fn spec_with_mutually_recursive_schemas() -> Spec {
        let json = r##"{
            "openapi": "3.0.0",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "components": {
                "schemas": {
                    "User": {
                        "type": "object",
                        "properties": {
                            "name": { "type": "string" },
                            "identity": { "$ref": "#/components/schemas/UserIdentity" }
                        }
                    },
                    "UserIdentity": {
                        "type": "object",
                        "properties": {
                            "provider": { "type": "string" },
                            "user": { "$ref": "#/components/schemas/User" }
                        }
                    }
                }
            }
        }"##;
        oas3::from_json(json).expect("spec should parse").into()
    }

    /// Regression test for a stack overflow previously observed when fuzzing
    /// an API (scout-api) whose response schemas were mutually recursive:
    /// without cycle detection, `parameter_accesses_from_schema` recursed
    /// forever on `User -> UserIdentity -> User -> ...`, crashing the whole
    /// process (not just failing an assertion) rather than returning an
    /// error. If this test hangs, crashes, or aborts rather than completing
    /// quickly, the cycle detection has regressed.
    #[test]
    fn mutually_recursive_schema_does_not_overflow_stack() {
        let spec = spec_with_mutually_recursive_schemas();
        let user_schema = Schema::Object(Box::new(ObjectOrReference::Ref {
            ref_path: "#/components/schemas/User".to_string(),
            summary: None,
            description: None,
        }));

        let accesses = ParameterAccessElements::parameter_accesses_from_schema(
            ParameterAccessElements::new(),
            &user_schema,
            &spec,
        );

        // Both fields of `User`, the one non-recursive field of
        // `UserIdentity` (`provider`), and the `user` field itself (which
        // points back to `User`) should be reachable exactly once; the field
        // is listed, but its own fields (which would repeat `name`/`identity`
        // forever) must not be expanded again.
        let names: Vec<String> = accesses.iter().map(ToString::to_string).collect();
        assert!(names.contains(&"name".to_string()));
        assert!(names.contains(&"identity".to_string()));
        assert!(names.contains(&"identity/provider".to_string()));
        assert!(names.contains(&"identity/user".to_string()));
        assert!(
            !names.contains(&"identity/user/name".to_string()),
            "should not recurse back into the already-visited `User` schema"
        );
    }
}
