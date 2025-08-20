use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::{
    initial_corpus::dependency_graph::parameter_access::{
        ParameterAccess, ResponseParameterAccess,
    },
    input::{Body, Method, OpenApiRequest, ParameterContents::Object},
    openapi::validate_response::Response,
};

/// ParameterFeedbackMetadata collects parameter values from requests as they
/// are made. This allows the harness to insert the values in subsequent requests
/// if a parameter contains a backreference to an earlier request.
#[derive(Debug, Clone)]
pub struct ParameterFeedback(Vec<HashMap<ResponseParameterAccess, Value>>);

impl From<&Vec<HashMap<ResponseParameterAccess, Value>>> for ParameterFeedback {
    fn from(collection: &Vec<HashMap<ResponseParameterAccess, Value>>) -> Self {
        Self(collection.clone())
    }
}

impl serde::Serialize for ParameterFeedback {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for ParameterFeedback {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self(Vec::deserialize(deserializer)?))
    }
}

impl ParameterFeedback {
    #[must_use]
    pub fn new(num_requests: usize) -> Self {
        Self(vec![HashMap::new(); num_requests])
    }

    /// Returns the value saved for the given request
    pub fn get(&self, request_index: usize, param: &ResponseParameterAccess) -> Option<&Value> {
        // Tuple indexing leads to clones... Better to implement as double hashmap?
        self.0.get(request_index)?.get(param)
    }

    pub fn contains(&self, request_index: usize, param: &ResponseParameterAccess) -> bool {
        self.0
            .get(request_index)
            .map(|m| m.contains_key(param))
            .unwrap_or(false)
    }

    /// Adds the given parameter/value combination to memory. Returns whether successful
    /// (if the request index is out of bounds, false is returned).
    pub fn set(
        &mut self,
        request_index: usize,
        param: ResponseParameterAccess,
        value: Value,
    ) -> bool {
        self.0
            .get_mut(request_index)
            .map(|m| m.insert(param, value))
            .is_some()
    }

    fn add_response_parameter(
        &mut self,
        request_index: usize,
        parent_access: ResponseParameterAccess,
        field: serde_json::Value,
    ) {
        self.set(request_index, parent_access.clone(), field.clone());
        // Only a Body response can contain nested values which we treat below.
        // Response cookies were already set with the line above.
        if let ResponseParameterAccess::Body(parameter_access) = parent_access {
            match field {
                Value::Array(values) => {
                    for (offset, value) in values.into_iter().enumerate() {
                        let access = parameter_access.with_new_element(offset.into());
                        self.add_response_parameter(
                            request_index,
                            ResponseParameterAccess::Body(access),
                            value,
                        );
                    }
                }
                Value::Object(map) => {
                    for (param, value) in map.into_iter() {
                        let access = parameter_access.with_new_element(param.into());
                        self.add_response_parameter(
                            request_index,
                            ResponseParameterAccess::Body(access),
                            value,
                        );
                    }
                }
                _ => (), // Non-composite value was already added above this match.
            }
        }
    }

    /// Processes the values returned in a Response.
    ///
    /// The body is parsed as a json object or an array of objects, and if successful,
    /// the fields are saved as parameter values. Cookies set as a `Set-Cookie` header
    /// are saved in their `param=value` form.
    pub fn process_response(&mut self, request_index: usize, mut response: Response) {
        // We take any returned json values and save key-value parameters we find
        // (e.g. id = 37) for use as parameters in later requests.
        match response.json::<serde_json::Value>() {
            // Objects in responses: save all field/value combinations
            Ok(field) => self.add_response_parameter(
                request_index,
                ResponseParameterAccess::Body(ParameterAccess::new(vec![])),
                field,
            ),
            Err(e) => {
                log::trace!("Error parsing response: {:?}", e);
            }
        }
        // We also record the values of any Set-Cookie headers
        // TODO: parse cookies in validate_response.rs to also treat them as non-String types
        for (name, value) in response.cookies() {
            self.add_response_parameter(
                request_index,
                ResponseParameterAccess::Cookie(name),
                serde_json::Value::String(value),
            );
        }
    }

    #[allow(unused)]
    fn reset(&mut self) {
        self.0.clear()
    }
}
