use std::collections::HashMap;

use serde_json::Value;

use crate::{
    openapi::validate_response::Response,
    parameter_access::{ParameterAccess, ParameterAccessElements, ParameterAddressing},
};

/// ParameterFeedbackMetadata collects parameter values from requests as they
/// are made. This allows the harness to insert the values in subsequent requests
/// if a parameter contains a backreference to an earlier request.
#[derive(Debug, Clone)]
pub struct ParameterFeedback(Vec<HashMap<ParameterAccess, Value>>);

impl From<&Vec<HashMap<ParameterAccess, Value>>> for ParameterFeedback {
    fn from(collection: &Vec<HashMap<ParameterAccess, Value>>) -> Self {
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
    pub fn get(&self, request_index: usize, param: &ParameterAccess) -> Option<&Value> {
        // Tuple indexing leads to clones... Better to implement as double hashmap?
        self.0.get(request_index)?.get(param)
    }

    pub fn contains(&self, request_index: usize, param: &ParameterAccess) -> bool {
        self.0
            .get(request_index)
            .map(|m| m.contains_key(param))
            .unwrap_or(false)
    }

    /// Adds the given parameter/value combination to memory. Returns whether successful
    /// (if the request index is out of bounds, false is returned).
    pub(crate) fn set(&mut self, addressing: ParameterAddressing, value: Value) -> bool {
        self.0
            .get_mut(addressing.request_index)
            .map(|m| m.insert(addressing.access, value))
            .is_some()
    }

    fn add_response_parameter(
        &mut self,
        addressing: ParameterAddressing,
        field: serde_json::Value,
    ) {
        self.set(addressing, field.clone());
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
                ParameterAddressing::new(
                    request_index,
                    ParameterAccess::response_body(ParameterAccessElements::new()),
                ),
                field,
            ),
            Err(e) => {
                log::trace!("Error parsing response: {e:?}");
            }
        }
        // We also record the values of any Set-Cookie headers
        // TODO: try to parse cookies in validate_response.rs to also treat them as non-String types?
        for (name, value) in response.cookies() {
            self.add_response_parameter(
                ParameterAddressing::new(request_index, ParameterAccess::response_cookie(name)),
                serde_json::Value::String(value),
            );
        }
    }

    #[allow(unused)]
    fn reset(&mut self) {
        self.0.clear()
    }
}
