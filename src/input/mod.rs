//! This module contains input representations for OpenAPI-based HTTP requests
//! made by the fuzzer. One input is a sequence of HTTP requests. Requests later
//! in the sequence may refer to values returned from earlier requests, so that
//! state generated in the earlier requests may be exploited to find bugs
//! efficiently.
//!
//! # Serialized representation
//!
//! Inputs may be serialized to and from YAML files, for instance as part of a
//! starting corpus or as a crash when fuzzing. Such YAML files have the following
//! structure.
//!
//! ```yaml
//! requests:
//!   - method: GET
//!     path: /something/somewhere
//!   - method: POST
//!     path: "/path/{name_of_parameter_in_path}/something"
//!     body:
//!       # The body can be a submitted form (as below), but also TextPlain or
//!       # ApplicationJson, or it can be omitted.
//!       XWwwFormUrlencoded:
//!         # The contents of any parameter can be a leaf_value, shown below,
//!         # or an object or array containing values of its own (again, leaf
//!         # values or more objects or arrays).
//!         object:
//!           a_field:
//!             leaf_value:
//!               # Values can be given a type, like String or Null or Bool or
//!               # Number, or can be objects (like the one containing this
//!               # field), or can be base64-encoded values like below.
//!               String: This is some text
//!           also_field:
//!             leaf_value:
//!               bytes_b64: U2l0ej10ej0=
//!     parameters:
//!       # Each parameter has a name and a location (Path, Query, Header or
//!       # Cookie) which can be specified like this:
//!       ? - name_of_parameter_in_path
//!         - Path
//!       : leaf_value:
//!           String: "x|~?\u001fO'S"
//!       ? - name_of_parameter_in_query_string
//!         - Query
//!       # Parameter values can be specified as references to earlier requests
//!       # like this. The earlier GET request in this example should return an
//!       # object with a field, which is then substituted here.
//!       : reference:
//!           request: 0
//!           parameter_name: name_of_field_in_returned_object_from_first_request
//! ```

use std::{
    borrow::Cow,
    collections::{
        BTreeMap,
        btree_map::{Iter, ValuesMut},
    },
    fs::File,
    hash::{BuildHasher, Hash, Hasher},
    io::Read,
    path::Path,
};

use ahash::RandomState;
use libafl::{Error, corpus::CorpusId, inputs::Input};
use libafl_bolts::{HasLen, fs::write_file_atomic, rands::Rand};
use oas3::spec::Operation;

use self::parameter::ParameterKind;
pub use self::{method::Method, parameter::ParameterContents, utils::new_rand_input};
use crate::{
    input::parameter::{IReference, OReference},
    openapi::spec::Spec,
    parameter_access::{
        ParameterAccess, ParameterAccessElements, ParameterAddressing, RequestParameterAccess,
    },
    parameter_feedback::ParameterFeedback,
    state::HasRandAndOpenAPI,
};

pub mod method;
pub mod parameter;
mod serde_helpers;
mod utils;
/// The main representation of an HTTP request in WuppieFuzz.
///
/// It contains an HTTP method and a path to send the request to, and optionally
/// contains a body and/or named parameters. These can contain concrete values or
/// references to responses from requests made earlier; see documentation for
/// `ParameterContents` for more information.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Hash)]
#[serde(
    into = "serde_helpers::SerializableOpenApiRequest",
    from = "serde_helpers::SerializableOpenApiRequest"
)]
pub struct OpenApiRequest {
    pub method: Method,
    // Parameters in the path are represented by {{parameter_name}}, which is replaced by a value
    // based on the parameters map.
    pub path: String,

    // The request body is always considered as variables/parameters. It must be an object
    // in which keys are the names of the parameters.
    pub body: Body,

    // Maps query-, header-, path-, and cookie-parameters to ParameterContents.
    // These are all assumed to be identifiable by a name represented as a String.
    pub parameters: BTreeMap<(String, ParameterKind), ParameterContents>,
}

#[derive(Default, Clone, Debug, serde::Serialize, serde::Deserialize, Hash)]
pub enum Body {
    #[default]
    Empty,
    TextPlain(ParameterContents),
    ApplicationJson(ParameterContents),
    XWwwFormUrlencoded(ParameterContents),
}

impl Body {
    /// Build a body with variables from contents and their type determined by the operation
    pub fn build(api: &Spec, operation: &Operation, contents: Option<ParameterContents>) -> Self {
        let (param_contents, ref_or_body) = match (contents, &operation.request_body) {
            (Some(indexmap), Some(ref_or_body)) => (indexmap, ref_or_body),
            _ => return Body::Empty,
        };

        match ref_or_body.resolve(api) {
            Ok(body) => {
                for key in body.content.keys() {
                    if key.starts_with("application/json") {
                        return Body::ApplicationJson(param_contents);
                    }
                    if key.starts_with("application/x-www-form-urlencoded") {
                        return Body::XWwwFormUrlencoded(param_contents);
                    }
                    if key.starts_with("text/plain") {
                        return Body::TextPlain(param_contents.to_string().into());
                    }
                }
                Body::Empty
            }
            Err(reference) => {
                panic!("API specification contains broken reference {reference}")
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Body::Empty)
    }
}

impl OpenApiRequest {
    /// Replaces all references in the parameters IndexMap by values collected in earlier requests.
    pub fn resolve_parameter_references(
        &mut self,
        parameter_values: &ParameterFeedback,
    ) -> Result<(), libafl::Error> {
        fn resolve_single_parameter(
            parameter: &mut ParameterContents,
            parameter_values: &ParameterFeedback,
        ) -> Result<(), libafl::Error> {
            match parameter {
                ParameterContents::OReference(OReference {
                    request_index,
                    parameter_access,
                }) => {
                    let resolved_backref = parameter_values
                        .get(*request_index, parameter_access)
                        .ok_or_else(|| {
                        libafl::Error::unknown(format!(
                            "invalid response-backreference to {request_index}:{parameter_access}"
                        ))
                    })?;
                    *parameter = resolved_backref.clone();
                }
                ParameterContents::IReference(IReference {
                    request_index,
                    parameter_access,
                }) => {
                    let resolved_backref = parameter_values
                        .get(*request_index, parameter_access)
                        .ok_or_else(|| {
                        libafl::Error::unknown(format!(
                            "invalid request-backreference to {request_index}:{parameter_access}"
                        ))
                    })?;
                    *parameter = resolved_backref.clone();
                }
                ParameterContents::Object(obj_contents) => {
                    for nested_parameter in obj_contents.values_mut() {
                        resolve_single_parameter(nested_parameter, parameter_values)?;
                    }
                }
                ParameterContents::Array(arr) => {
                    for nested_parameter in arr {
                        resolve_single_parameter(nested_parameter, parameter_values)?;
                    }
                }
                ParameterContents::LeafValue(_) | ParameterContents::Bytes(_) => (),
            }
            Ok(())
        }

        // Resolve body parameters
        match &mut self.body {
            Body::Empty => (), // No (reference) parameters in body, so nothing to resolve here!
            Body::TextPlain(body)
            | Body::ApplicationJson(body)
            | Body::XWwwFormUrlencoded(body) => match body {
                ParameterContents::OReference { .. } | ParameterContents::IReference { .. } => {
                    resolve_single_parameter(body, parameter_values)?;
                }
                ParameterContents::Object(obj_contents) => {
                    for nested_parameter in obj_contents.values_mut() {
                        resolve_single_parameter(nested_parameter, parameter_values)?;
                    }
                }
                ParameterContents::Array(arr) => {
                    for nested_parameter in arr {
                        resolve_single_parameter(nested_parameter, parameter_values)?;
                    }
                }
                ParameterContents::LeafValue(_) | ParameterContents::Bytes(_) => (),
            },
        }

        // Resolve URL-parameters
        for parameter in self.parameters.values_mut() {
            resolve_single_parameter(parameter, parameter_values)?;
        }
        Ok(())
    }

    /// Derive a body for a Reqwest request from this OpenApiRequest
    pub fn reqwest_body(&self) -> Option<reqwest::blocking::Body> {
        match &self.body {
            Body::Empty => None,
            Body::TextPlain(body) | Body::ApplicationJson(body) => {
                serde_json::to_string(&body.to_value())
                    .ok()
                    .map(reqwest::blocking::Body::from)
            }
            Body::XWwwFormUrlencoded(body) => {
                let mut encoded = url::form_urlencoded::Serializer::new(String::new());
                match body {
                    ParameterContents::Object(obj_contents) => {
                        for pair in obj_contents.iter() {
                            match pair.1 {
                                ParameterContents::LeafValue(first_level_concrete) => {
                                    match first_level_concrete {
                                        // String must be handled separately, otherwise it gets surrounded by quotes.
                                        parameter::SimpleValue::String(inner_str) => {
                                            encoded.append_pair(pair.0.as_ref(), inner_str)
                                        }
                                        _ => encoded.append_pair(
                                            pair.0.as_ref(),
                                            first_level_concrete.to_string().as_str(),
                                        ),
                                    }
                                }
                                ParameterContents::Array(inner_array) => encoded.extend_pairs(
                                    inner_array
                                        .iter()
                                        .map(|element| (pair.0.to_string(), element.to_string())),
                                ),
                                ParameterContents::Object(inner_map) => {
                                    encoded.extend_pairs(inner_map.iter().map(|(field, value)| {
                                        (field.to_string(), value.to_string())
                                    }))
                                }
                                _ => &mut encoded,
                            };
                        }
                    }
                    ParameterContents::OReference { .. } => {
                        todo!("Trying to create form body from oreference: {body}")
                    }
                    ParameterContents::IReference { .. } => {
                        todo!("Trying to create form body from ireference: {body}")
                    }
                    ParameterContents::Bytes(val) => {
                        todo!("Trying to create form body from bytes: {:?}", val)
                    }
                    ParameterContents::Array(_) | ParameterContents::LeafValue(_) => {
                        panic!(
                            "Form bodies must not be of type array or leaf, but interpretable as key-value objects.\nOffending body: {body}"
                        );
                    }
                }
                Some(reqwest::blocking::Body::from(encoded.finish()))
            }
        }
    }

    pub fn body_content_type(&self) -> &'static str {
        match self.body {
            Body::Empty => "",
            Body::TextPlain(_) => "text/plain",
            Body::ApplicationJson(_) => "application/json",
            Body::XWwwFormUrlencoded(_) => "application/x-www-form-urlencoded",
        }
    }

    /// Returns a mutable reference to a parameter identified by the RequestParameterAccess.
    pub fn get_mut_parameter<'a>(
        &'a mut self,
        req_parameter_access: &RequestParameterAccess,
    ) -> Option<&'a mut ParameterContents> {
        // Can't use or_else with a closure because you'd have to move self
        // which is not possible
        #[allow(clippy::or_fun_call)]
        match &req_parameter_access {
            RequestParameterAccess::Body(parameter_access) => match &mut self.body {
                Body::Empty => None,
                Body::TextPlain(text) => Some(text),
                Body::ApplicationJson(parameters) | Body::XWwwFormUrlencoded(parameters) => {
                    parameters.resolve_mut(parameter_access)
                }
            },
            RequestParameterAccess::Query(name)
            | RequestParameterAccess::Path(name)
            | RequestParameterAccess::Header(name)
            | RequestParameterAccess::Cookie(name) => self
                .parameters
                .get_mut(&(name.clone(), req_parameter_access.into())),
        }
    }

    /// Returns whether this request contains a (non-body) parameter with the given name
    pub fn contains_parameter(&self, find_name: &str) -> bool {
        self.parameters
            .iter()
            .any(|((name, _), _)| name == find_name)
    }
}

impl std::fmt::Display for OpenApiRequest {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "{} {}", self.method, self.path)?;
        for ((name, kind), contents) in &self.parameters {
            write!(fmt, "\n  {name} in {kind:?}: {contents}")?;
        }
        match &self.body {
            Body::Empty => (),
            Body::TextPlain(text) => write!(fmt, "\n text body: {text}")?,
            Body::ApplicationJson(body_content) | Body::XWwwFormUrlencoded(body_content) => {
                write!(fmt, "Contents in body: {body_content}")?;
            }
        }
        Ok(())
    }
}

/// The main input type for the fuzzer is a series of HTTP requests, represented
/// by this type.
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug, Hash)]
pub struct OpenApiInput(pub Vec<OpenApiRequest>);

pub enum IterWrapper<'a> {
    WithOption(Option<&'a ParameterContents>),
    WithIter(Iter<'a, String, ParameterContents>),
}

impl<'a> Iterator for IterWrapper<'a> {
    type Item = (Cow<'a, String>, &'a ParameterContents);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            IterWrapper::WithOption(o) => o.take().map(|c| (Cow::Owned(String::new()), c)),
            IterWrapper::WithIter(i) => i.next().map(|(s, c)| (Cow::Borrowed(s), c)),
        }
    }
}

pub enum ParamContentsAtLevel0Wrapper<'a> {
    SimpleOption(Option<&'a mut ParameterContents>),
    InObject(ValuesMut<'a, String, ParameterContents>),
    InArray(std::slice::IterMut<'a, ParameterContents>),
}

impl<'a> Iterator for ParamContentsAtLevel0Wrapper<'a> {
    type Item = &'a mut ParameterContents;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ParamContentsAtLevel0Wrapper::SimpleOption(o) => o.take(),
            ParamContentsAtLevel0Wrapper::InObject(i) => i.next(),
            ParamContentsAtLevel0Wrapper::InArray(i) => i.next(),
        }
    }
}

impl OpenApiInput {
    /// Returns an iterator that yields all `ParameterContents` for which `filter`
    /// is true, from all requests in the series. Each item is accompanied by
    /// the index of the request it appears in.
    // TODO: filter nested parameters too!
    pub fn parameter_filter<'a, F>(
        &'a mut self,
        filter: &'a F,
    ) -> impl Iterator<Item = (usize, &'a mut ParameterContents)> + 'a
    where
        F: Fn(&&'a mut ParameterContents) -> bool + 'a,
    {
        self.0
            .iter_mut()
            .enumerate()
            .flat_map(move |(request_idx, openapi_request)| {
                // For each input, collect any named parameters ...
                openapi_request
                    .parameters
                    .iter_mut()
                    .map(|(_, v)| v)
                    // .. then add any fields from the body as well ..
                    .chain(match &mut openapi_request.body {
                        Body::Empty => ParamContentsAtLevel0Wrapper::SimpleOption(None),
                        Body::TextPlain(text) => {
                            ParamContentsAtLevel0Wrapper::SimpleOption(Some(text))
                        }
                        Body::ApplicationJson(parameters)
                        | Body::XWwwFormUrlencoded(parameters) => match parameters {
                            ParameterContents::Object(obj_param) => {
                                ParamContentsAtLevel0Wrapper::InObject(obj_param.values_mut())
                            }
                            ParameterContents::Array(arr) => {
                                ParamContentsAtLevel0Wrapper::InArray(arr.iter_mut())
                            }
                            _ => ParamContentsAtLevel0Wrapper::SimpleOption(Some(parameters)),
                        },
                    })
                    // .. then only return filtered ones with the request index
                    .filter(filter)
                    .map(move |v| (request_idx, v))
            })
    }

    /// This returns all reference parameters as (source, target) addressings.
    pub(crate) fn reference_parameters(
        &self,
    ) -> impl Iterator<Item = (ParameterAddressing, ParameterAddressing)> + '_ {
        self.0
            .iter()
            .enumerate()
            .flat_map(move |(request_idx, openapi_request)| {
                // For each input, collect any named parameters ...
                openapi_request
                    .parameters
                    .iter()
                    // .map(|((n, k), v)| (Cow::Borrowed(n), *k, v))
                    .map(|((n, k), v)| (Cow::Borrowed(n), *k, v))
                    //.. then add any fields from the body as well ..
                    .chain(
                        // TODO: also return nested (reference) parameters
                        match &openapi_request.body {
                            Body::Empty => IterWrapper::WithOption(None),
                            Body::TextPlain(text) => IterWrapper::WithOption(Some(text)),
                            Body::ApplicationJson(contents)
                            | Body::XWwwFormUrlencoded(contents) => match contents {
                                ParameterContents::Object(obj_params) => {
                                    IterWrapper::WithIter(obj_params.iter())
                                }
                                ParameterContents::OReference(..) => {
                                    IterWrapper::WithOption(Some(contents))
                                }
                                ParameterContents::IReference(..) => {
                                    IterWrapper::WithOption(Some(contents))
                                }
                                _ => IterWrapper::WithOption(None),
                            },
                        }
                        .map(|(n, v)| (n, ParameterKind::Body, v)),
                    )
                    // Only preserve references
                    .filter_map(|(n, k, v)| match v {
                        ParameterContents::OReference(OReference {
                            request_index,
                            parameter_access,
                        })
                        | ParameterContents::IReference(IReference {
                            request_index,
                            parameter_access,
                        }) => Some(((n, k), (request_index, parameter_access))),

                        _ => None,
                    })
                    // Turn parameter name (here still a String) into ParameterAccess
                    // and return the (request, target) ParameterAddressing tuple.
                    .map(move |((n, parameter_kind), (ti, tn))| {
                        (
                            ParameterAddressing::new(
                                request_idx,
                                match parameter_kind {
                                    ParameterKind::Path => ParameterAccess::Request(
                                        RequestParameterAccess::Path(n.clone().into_owned()),
                                    ),
                                    ParameterKind::Query => ParameterAccess::Request(
                                        RequestParameterAccess::Query(n.clone().into_owned()),
                                    ),
                                    ParameterKind::Header => ParameterAccess::Request(
                                        RequestParameterAccess::Header(n.clone().into_owned()),
                                    ),
                                    ParameterKind::Cookie => ParameterAccess::Request(
                                        RequestParameterAccess::Cookie(n.clone().into_owned()),
                                    ),
                                    ParameterKind::Body => {
                                        ParameterAccess::Request(RequestParameterAccess::Body(
                                            ParameterAccessElements::from_elements(&[n
                                                .into_owned()
                                                .into()]),
                                        ))
                                    }
                                },
                            ),
                            ParameterAddressing::new(*ti, tn.to_owned()),
                        )
                    })
            })
    }

    /// Returns an iterator that yields all (named) return value names from all
    /// requests, along with the index of the request they appear in.
    pub(crate) fn return_values(&self, api: &Spec) -> Vec<ParameterAddressing> {
        self.0
            .iter()
            .enumerate()
            // Find the request's corresponding operation in the API spec
            .filter_map(|(i, e)| {
                api.operations()
                    .find(|(p, m, _)| e.path == *p && e.method == Method::from(m))
                    .map(|op| (i, op.2))
            })
            // Extract the specification of each operation's possible responses
            .flat_map(|(i, op)| {
                op.responses
                    .as_ref()
                    .into_iter()
                    .flat_map(|btm| btm.iter())
                    .filter_map(|(_, ref_or_response)| ref_or_response.resolve(api).ok())
                    // Filter this by extracting only json responses, which contain usable return values
                    .flat_map(|response| {
                        response.content.iter().find_map(|(key, value)| {
                            key.starts_with("application/json")
                                .then_some(value.schema.clone())
                                .flatten()
                        })
                    })
                    // Finally if the schema is an object, extract its field names
                    .flat_map(|x| {
                        ParameterAccessElements::parameter_accesses_from_schema(
                            ParameterAccessElements::new(),
                            &x,
                            api,
                        )
                    })
                    .map(move |resps| {
                        ParameterAddressing::new(i, ParameterAccess::response_body(resps))
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Checks whether all references in the OpenApiInput refer to parameters that exist.
    /// Replaces broken references by random data.
    pub fn fix_broken_references<R>(&mut self, rand: &mut R)
    where
        R: Rand,
    {
        let to_replace: Vec<_> = self
            .reference_parameters()
            .filter(
                // Select broken references: source- or target-request does not exist or the source
                // request no longer has the reference parameter accessible.
                // We do not have the response available at this point, so we cannot check whether
                // the reference will actually be resolvable when we get the response.
                |(src_addressing, target_addressing)| match (
                    self.0.clone().get_mut(src_addressing.request_index),
                    self.0.clone().get(target_addressing.request_index),
                ) {
                    (None, None) | (None, Some(_)) | (Some(_), None) => true,
                    (Some(src), Some(_)) => src
                        .get_mut_parameter(src_addressing.access.unwrap_request_variant())
                        .is_none(),
                },
            )
            // Reference is broken - replace (later... borrow checker forbids doing it here
            // since it can't verify we don't mess up the loop from reference_parameters)
            .map(|(source_addressing, _)| source_addressing)
            .collect();

        for src_addressing in to_replace {
            let idx = src_addressing.request_index;
            let parameter_access = src_addressing.access;
            match &parameter_access {
                ParameterAccess::Response(_response_parameter_access) => {
                    unreachable!("References only occur in Request variants.");
                }
                ParameterAccess::Request(request_access) => match request_access {
                    RequestParameterAccess::Body(parameter_access_elements) => {
                        match &mut self.0[idx].body {
                            Body::Empty | Body::TextPlain(_) => {
                                log::warn!("Marked body parameter in request {idx} with name {parameter_access} for replacement,
                                but the body is Empty or TextPlain!");
                                continue;
                            }
                            Body::ApplicationJson(contents)
                            | Body::XWwwFormUrlencoded(contents) => match contents {
                                ParameterContents::Object(_obj_param) => {
                                    let resolved =
                                        contents.resolve_mut(parameter_access_elements).unwrap();
                                    resolved.break_reference_if_target(rand, |_| true);
                                }
                                ParameterContents::OReference(OReference {
                                    request_index,
                                    parameter_access,
                                }) => {
                                    log::warn!("Marked body parameter in response {idx} with name {parameter_access} for replacement.
                                    The body's immediate contents are however an (unnamed) reference, pointing to a parameter
                                    with name {parameter_access} in response {request_index}.");
                                    continue;
                                }

                                ParameterContents::IReference(IReference {
                                    request_index,
                                    parameter_access,
                                }) => {
                                    log::warn!("Marked body parameter in request {idx} with name {parameter_access} for replacement.
                                    The body's immediate contents are however an (unnamed) reference, pointing to a parameter
                                    with name {parameter_access} in request {request_index}.");
                                    continue;
                                }
                                ParameterContents::Array(arr_param) => {
                                    for elem in arr_param.iter() {
                                        if let ParameterContents::OReference { .. } = elem {
                                            log::warn!("Array contains reference, but we cannot identify this with
                                    request_idx, name, parameter_kind triplet. Therefore we cannot resolve the reference.");
                                        }
                                    }
                                    continue;
                                }
                                ParameterContents::LeafValue(_) => {
                                    log::warn!("Marked body parameter in request {idx} with name {parameter_access} for replacement,
                                        but the body is a LeafValue: {contents}");
                                    continue;
                                }
                                ParameterContents::Bytes(_) => {
                                    log::warn!("Marked body parameter in request {idx} with name {parameter_access} for replacement,
                                        but the body is of type Bytes: {contents}");
                                    continue;
                                }
                            },
                        }
                    }
                    // RequestParameterAccess::Query(_) => todo!(),
                    // RequestParameterAccess::Path(_) => todo!(),
                    // RequestParameterAccess::Header(_) => todo!(),
                    // RequestParameterAccess::Cookie(_) => todo!(),
                    _ => self.0[idx]
                        .parameters
                        .get_mut(&(
                            parameter_access.simple_name().to_string(),
                            (&parameter_access).into(),
                        ))
                        .unwrap()
                        .break_reference_if_target(rand, |_| true),
                },
            }
        }
    }

    /// Checks if a request chain is valid: no references to future requests.
    /// Panics if not.
    #[cfg(debug_assertions)]
    pub fn assert_valid(&mut self, message: &str) {
        for (appears_in, param) in self.parameter_filter(&|v| v.is_reference()) {
            let refers_to = *param.reference_index().unwrap();
            if refers_to >= appears_in {
                panic!(
                    "Request chain is invalid: request {appears_in} refers to request {refers_to} ({message})"
                )
            }
        }
    }

    /// Checks if a request chain is valid: no references to future requests.
    /// Panics if not. In release mode, this is a no-op.
    #[cfg(not(debug_assertions))]
    pub fn assert_valid(&mut self, _message: &str) {}
}

impl HasLen for OpenApiInput {
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl Input for OpenApiInput {
    fn generate_name(&self, _idx: Option<CorpusId>) -> String {
        let mut hasher = RandomState::with_seeds(0, 0, 0, 0).build_hasher();
        for request in &self.0 {
            hasher.write(request.method.as_bytes());
            hasher.write(request.path.as_bytes());
            for (name, value) in &request.parameters {
                hasher.write(name.0.to_string().as_bytes());
                hasher.write(&[name.1 as u8]);
                hasher.write(value.to_string().as_bytes());
            }
            match &request.body {
                Body::Empty => (),
                Body::TextPlain(value) => hasher.write(value.to_string().as_bytes()),
                Body::ApplicationJson(content) | Body::XWwwFormUrlencoded(content) => {
                    hasher.write(content.to_string().as_bytes());
                }
            }
        }
        format!("{:016x}", hasher.finish())
    }

    fn to_file<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        match serde_yaml::to_string(self) {
            Ok(s) => write_file_atomic(path, s.as_bytes()),
            Err(e) => Err(Error::serialize(e.to_string())),
        }
    }

    fn from_file<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mut file = File::open(path)?;
        let mut bytes: Vec<u8> = vec![];
        file.read_to_end(&mut bytes)?;
        serde_yaml::from_slice(&bytes).map_err(|err| Error::serialize(err.to_string()))
    }
}

/// Fix a malformed (perhaps by a mutator) request using the API specification.
/// This will remove named parameters that do not exist in the spec, and add new ones
/// if necessary, generating random values for them using `new_rand_input`.
pub fn fix_input_parameters<S>(state: &mut S, operation: usize, input: &mut OpenApiRequest)
where
    S: HasRandAndOpenAPI,
{
    // Make a new set of parameter values by taking existing values that are still
    // relevant, and making up random new ones if none exist
    let (rand, api) = state.rand_mut_and_openapi();
    let new_params: BTreeMap<(String, ParameterKind), ParameterContents> = api
        .operations()
        .nth(operation)
        .expect("fix_input_parameters called with out of bounds operation index")
        .2
        .parameters
        .iter()
        // Keep only concrete values and valid references
        .filter_map(|ref_or_param| ref_or_param.resolve(api).ok())
        // Convert to (parameter_name, parameter_kind) tuples
        .map(|param| (param.name.clone(), param.into()))
        .map(|(name, kind)| {
            let key = (name, kind);
            // Remove *AND RETURN*, meaning we *keep* the parameter for this key
            input.parameters.remove_entry(&key).unwrap_or_else(|| {
                (
                    key,
                    ParameterContents::from(
                        String::from_utf8_lossy(&new_rand_input(rand)).to_string(),
                    ),
                )
            })
        })
        .collect();
    input.parameters = new_params;
}

impl std::fmt::Display for OpenApiInput {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        for request in &self.0 {
            writeln!(fmt, "{request}")?
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::{Body, Method, OpenApiRequest, ParameterContents};

    #[test]
    fn test_reqwest_body() {
        let mut form_map = serde_json::Map::new();
        form_map.insert("str_name".to_string(), json!("param_value"));
        form_map.insert("num_name".to_string(), json!(37));
        form_map.insert("bool_name".to_string(), json!(true));
        form_map.insert("arr_name".to_string(), json!([3, 4, 5]));
        form_map.insert(
            "obj_name".to_string(),
            json!({"field1": 2, "Field2": false}),
        );
        let body_contents = ParameterContents::from(serde_json::Value::Object(form_map));
        let form_body = Body::XWwwFormUrlencoded(body_contents);
        let openapi_request = OpenApiRequest {
            method: Method::Post,
            path: "/".to_owned(),
            body: form_body,
            parameters: BTreeMap::new(),
        };
        let bodified = openapi_request
            .reqwest_body()
            .expect("Failed to convert OpenApiRequest to a reqwest.Body");
        let query_pairs = bodified
            .as_bytes()
            .expect("Could not convert reqwest.Body to bytes")
            .split(|byte| *byte == b'&')
            .collect::<Vec<_>>();
        assert!(query_pairs.contains(&&b"str_name=param_value"[..]));
        assert!(query_pairs.contains(&&b"num_name=37"[..]));
        assert!(query_pairs.contains(&&b"bool_name=true"[..]));
        assert!(query_pairs.contains(&&b"arr_name=3"[..]));
        assert!(query_pairs.contains(&&b"arr_name=4"[..]));
        assert!(query_pairs.contains(&&b"arr_name=5"[..]));
        assert!(query_pairs.contains(&&b"field1=2"[..]));
        assert!(query_pairs.contains(&&b"Field2=false"[..]));
    }
}
