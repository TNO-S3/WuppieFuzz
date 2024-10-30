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

use self::parameter::ParameterKind;
pub use self::{method::Method, parameter::ParameterContents};
use crate::openapi::{JsonContent, TextPlain, WwwForm};
use crate::{
    openapi::find_operation, parameter_feedback::ParameterFeedback, state::HasRandAndOpenAPI,
};
use ahash::RandomState;
use indexmap::map::ValuesMut;
use indexmap::{map::Iter, IndexMap};
use libafl::corpus::CorpusId;
use libafl::{inputs::Input, Error};
use libafl_bolts::{fs::write_file_atomic, rands::Rand, HasLen};
use openapiv3::{OpenAPI, Operation, SchemaKind, Type};
use std::{borrow::Cow, hash::BuildHasher, hash::Hasher};
use std::{fs::File, io::Read, path::Path};

pub mod method;
pub mod parameter;
mod serde_helpers;

/// The main representation of an HTTP request in WuppieFuzz.
///
/// It contains an HTTP method and a path to send the request to, and optionally
/// contains a body and/or named parameters. These can contain concrete values or
/// references to responses from requests made earlier; see documentation for
/// `ParameterContents` for more information.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(
    into = "serde_helpers::SerializableOpenApiRequest",
    from = "serde_helpers::SerializableOpenApiRequest"
)]
pub struct OpenApiRequest {
    pub method: Method,
    pub path: String,

    pub body: Body,
    pub parameters: IndexMap<(String, ParameterKind), ParameterContents>,
}

#[derive(Default, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum Body {
    #[default]
    Empty,
    TextPlain(ParameterContents),
    ApplicationJson(ParameterContents),
    XWwwFormUrlencoded(ParameterContents),
}

impl Body {
    /// Build a body with variables from contents and their type determined by the operation
    pub fn build(
        api: &OpenAPI,
        operation: &Operation,
        contents: Option<ParameterContents>,
    ) -> Self {
        let (param_contents, ref_or_body) = match (contents, &operation.request_body) {
            (Some(indexmap), Some(ref_or_body)) => (indexmap, ref_or_body),
            _ => return Body::Empty,
        };

        match ref_or_body.resolve(api) {
            Ok(body) => {
                if body.content.has_json_content() {
                    return Body::ApplicationJson(param_contents);
                }
                if body.content.has_www_form_content() {
                    return Body::XWwwFormUrlencoded(param_contents);
                }
                if body.content.has_text_plain() {
                    return Body::TextPlain(param_contents.to_string().into());
                }
                Body::Empty
            }
            Err(reference) => {
                panic!("API specification contains broken reference {}", reference)
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
            if let ParameterContents::Reference {
                request_index,
                parameter_name,
            } = parameter
            {
                let resolved_backref = parameter_values
                    .get(*request_index, parameter_name)
                    .ok_or_else(|| {
                        libafl::Error::unknown(format!(
                            "invalid backreference to {request_index}:{parameter_name}"
                        ))
                    })?;
                *parameter = ParameterContents::from(resolved_backref.clone());
            }

            Ok(())
        }

        // Resolve body parameters
        match &mut self.body {
            Body::Empty => (), // No (reference) parameters in body, so nothing to resolve here!
            Body::TextPlain(_) => todo!(),
            Body::ApplicationJson(body) | Body::XWwwFormUrlencoded(body) => match body {
                ParameterContents::Reference { .. } => {
                    resolve_single_parameter(body, parameter_values)?;
                }
                ParameterContents::Object(obj_contents) => {
                    for (_key, nested_parameter) in obj_contents {
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
                                            encoded.append_pair(pair.0, inner_str)
                                        }
                                        _ => encoded.append_pair(
                                            pair.0,
                                            first_level_concrete.to_string().as_str(),
                                        ),
                                    }
                                }
                                ParameterContents::Array(inner_array) => encoded.extend_pairs(
                                    inner_array
                                        .iter()
                                        .map(|element| (pair.0, element.to_string())),
                                ),
                                ParameterContents::Object(inner_map) => encoded.extend_pairs(
                                    inner_map
                                        .iter()
                                        .map(|(field, value)| (field, value.to_string())),
                                ),
                                _ => &mut encoded,
                            };
                        }
                    }
                    ParameterContents::Reference { .. } => {
                        todo!("Trying to create form body from reference: {body}")
                    }
                    ParameterContents::Bytes(val) => {
                        todo!("Trying to create form body from bytes: {:?}", val)
                    }
                    ParameterContents::Array(_) | ParameterContents::LeafValue(_) => {
                        panic!("Form bodies must not be of type array or leaf, but interpretable as key-value objects.\nOffending body: {}", body);
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

    /// Finds a parameter of ParameterKind (Query, Path, Cookie, etc.)
    /// with the given name and returns a mutable reference to it.
    /// If none exists, checks the body for a field with the given name.
    pub fn get_mut_parameter<'a>(
        &'a mut self,
        name: &str,
        kind: ParameterKind,
    ) -> Option<&'a mut ParameterContents> {
        // Can't use or_else with a closure because you'd have to move self
        // which is not possible
        #[allow(clippy::or_fun_call)]
        match kind {
            ParameterKind::Path
            | ParameterKind::Query
            | ParameterKind::Header
            | ParameterKind::Cookie => self.parameters.get_mut(&(name.to_owned(), kind)),
            ParameterKind::Body => match &mut self.body {
                Body::Empty => None,
                Body::TextPlain(text) => Some(text),
                // For getting named parameters, we consider only first-level parameters in object values
                // TODO: implement a way to address nested parameters and non-object parameters.
                Body::ApplicationJson(parameters) | Body::XWwwFormUrlencoded(parameters) => {
                    if let ParameterContents::Object(obj_param) = parameters {
                        obj_param.get_mut(name)
                    } else {
                        None
                    }
                }
            },
        }
    }

    /// Returns whether this request contains a parameter with the given name
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
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
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

    /// This returns all reference parameters as follows:
    /// (request idx, param name, param location, target request idx, target name)
    pub fn reference_parameters(
        &self,
    ) -> impl Iterator<Item = (usize, String, ParameterKind, usize, String)> + '_ {
        self.0
            .iter()
            .enumerate()
            .flat_map(move |(request_idx, openapi_request)| {
                // For each input, collect any named parameters ...
                openapi_request
                    .parameters
                    .iter()
                    .map(|((n, k), v)| (Cow::Borrowed(n), *k, v))
                    //.. then add any fields from the body as well ..
                    .chain(
                        match &openapi_request.body {
                            Body::Empty => IterWrapper::WithOption(None),
                            Body::TextPlain(text) => IterWrapper::WithOption(Some(text)),
                            Body::ApplicationJson(contents)
                            | Body::XWwwFormUrlencoded(contents) => match contents {
                                ParameterContents::Object(obj_params) => {
                                    IterWrapper::WithIter(obj_params.iter())
                                }
                                ParameterContents::Reference { .. } => {
                                    IterWrapper::WithOption(Some(contents))
                                }
                                _ => IterWrapper::WithOption(None),
                            },
                        }
                        .map(|(n, v)| (n, ParameterKind::Body, v)),
                    )
                    .filter_map(|(n, k, v)| match v {
                        ParameterContents::Reference {
                            request_index,
                            parameter_name,
                        } => Some(((n, k), (request_index, parameter_name))),
                        _ => None,
                    })
                    .map(move |((n, k), (ti, tn))| {
                        (request_idx, n.into_owned(), k, *ti, tn.to_owned())
                    })
            })
    }

    /// Returns an iterator that yields all named return values from all
    /// requests, along with the index of the request they appear in.
    pub fn return_values<'a>(&self, api: &'a OpenAPI) -> Vec<(usize, &'a str)> {
        self.0
            .iter()
            .enumerate()
            // Find the request's corresponding operation in the API spec
            .filter_map(|(i, e)| find_operation(api, &e.path, e.method).map(|op| (i, op)))
            // Extract the specification of each operation's possible responses
            .flat_map(|(i, op)| {
                op.responses
                    .responses
                    .iter()
                    .filter_map(|(_, ref_or_response)| ref_or_response.resolve(api).ok())
                    // Filter this by extracting only json responses, which contain usable return values
                    .flat_map(|response| {
                        response
                            .content
                            .get_json_content()
                            .and_then(|media| media.schema.as_ref())
                    })
                    // Finally if the schema is an object, extract its field names
                    .filter_map(|schema| match schema.resolve(api).kind {
                        SchemaKind::Type(Type::Object(ref obj)) => Some(obj.properties.keys()),
                        _ => None,
                    })
                    .flatten()
                    .map(move |resps| (i, resps.as_ref()))
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
                // Select broken references: target request does not exist or does not
                // contain the referenced parameter name
                |(_, _, _, target_idx, target_name)| match self.0.get(*target_idx) {
                    None => true,
                    Some(request) => !request.contains_parameter(target_name),
                },
            )
            // Reference is broken - replace (later... borrow checker forbids doing it here
            // since it can't verify we don't mess up the loop from reference_parameters)
            .map(|(source_idx, source_name, source_kind, _, _)| {
                (source_idx, source_name, source_kind)
            })
            .collect();

        for (idx, name, kind) in to_replace {
            match kind {
                ParameterKind::Body => match &mut self.0[idx].body {
                    Body::Empty | Body::TextPlain(_) => {
                        log::warn!("Marked body parameter in request {idx} with name {name} for replacement,
                                    but the body is Empty or TextPlain!");
                        continue
                    },
                    Body::ApplicationJson(contents) | Body::XWwwFormUrlencoded(contents) => {
                        match contents {
                            ParameterContents::Object(obj_param) => &mut obj_param[&name],
                            // Note that a Reference parameter is not by itself named, but must be the value in an Object parameter.
                            // The parameter_name-field in a Reference only identifies the target of the Reference.
                            ParameterContents::Reference { parameter_name, request_index } => {
                                log::warn!("Marked body parameter in request {idx} with name {name} for replacement.
                                        The body's immediate contents are however an (unnamed) reference, pointing to a parameter
                                        with name {parameter_name} in request {request_index}.");
                                continue
                            }
                            // Note that Array fields currently cannot be addressed as variable parameters.
                            // Therefore, Arrays currently should not contain any references.
                            // If they do, we do not resolve them here.
                            ParameterContents::Array(arr_param) => {
                                for elem in arr_param.iter() {
                                    if let ParameterContents::Reference { .. } = elem {
                                        log::warn!("Array contains reference, but we cannot identify this with
                                        request_idx, name, parameter_kind triplet. Therefore we cannot resolve the reference.");
                                    }
                                }
                                continue
                            }
                            ParameterContents::LeafValue(_) => {
                                log::warn!("Marked body parameter in request {idx} with name {name} for replacement,
                                            but the body is a LeafValue: {contents}");
                                continue
                            },
                            ParameterContents::Bytes(_) => {
                                log::warn!("Marked body parameter in request {idx} with name {name} for replacement,
                                            but the body is of type Bytes: {contents}");
                                continue
                            },
                        }
                    }
                },
                _ => &mut self.0[idx].parameters[&(name, kind)],
            }
            .break_reference_if_target(rand, |_| true);
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
                    "Request chain is invalid: request {} refers to request {} ({})",
                    appears_in, refers_to, message
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
                hasher.write(name.0.as_bytes());
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

/// Helper function that gives a new random input of length 8 (which seems sensible for
/// most api parameters), starting out with sort-of ascii.
pub fn new_rand_input<R: Rand>(rand: &mut R) -> Vec<u8> {
    let r = rand.next();
    (0..8).map(|i| (r >> i) as u8 & 0x7f).collect()
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
    let mut new_params: IndexMap<(String, ParameterKind), ParameterContents> = api
        .operations()
        .nth(operation)
        .expect("fix_input_parameters called with out of bounds operation index")
        .2
        .parameters
        .iter()
        // Keep only concrete values and valid references
        .filter_map(|ref_or_param| ref_or_param.resolve(api).ok())
        // Convert to (parameter_name, parameter_kind) tuples
        .map(|param| (param.data.name.clone(), param.into()))
        .map(|(name, kind)| {
            let key = (name, kind);
            // Remove *AND RETURN*, meaning we *keep* the parameter for this key
            input.parameters.swap_remove_entry(&key).unwrap_or_else(|| {
                (
                    key,
                    ParameterContents::from(
                        String::from_utf8_lossy(&new_rand_input(rand)).to_string(),
                    ),
                )
            })
        })
        .collect();
    new_params.sort_keys();
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
    use indexmap::IndexMap;
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
            parameters: IndexMap::new(),
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
