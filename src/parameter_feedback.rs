use std::collections::HashMap;

use serde_json::Value;

use crate::{
    input::{Body, Method, OpenApiRequest, ParameterContents::Object, parameter::ParameterAccess},
    openapi::validate_response::Response,
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
    pub fn set(&mut self, request_index: usize, param: ParameterAccess, value: Value) -> bool {
        self.0
            .get_mut(request_index)
            .map(|m| m.insert(param, value))
            .is_some()
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
            Ok(serde_json::Value::Object(hashmap)) => {
                for (param, value) in hashmap.into_iter() {
                    self.set(request_index, param.into(), value);
                }
            }
            // Arrays in responses: take the first element, which should be an object,
            // and save all field/value combinations.
            // Since we can only save one value per field name per request, we can only
            // keep one object worth of values, and we forget the rest.
            Ok(serde_json::Value::Array(vec)) => {
                if let Some(serde_json::Value::Object(hashmap)) = vec.into_iter().next() {
                    for (param, value) in hashmap.into_iter() {
                        self.set(request_index, param.into(), value);
                    }
                }
            }
            _ => {
                log::trace!(
                    "Response was not an object or array: {:?}",
                    response.json::<serde_json::Value>()
                );
                ()
            }
        }
        // We also record the values of any Set-Cookie headers
        for (name, value) in response.cookies() {
            self.set(request_index, name.into(), serde_json::Value::String(value));
        }
    }

    /// Process any body values in a request if its type is POST.
    ///
    /// If there is a request body with fields, either JSON or form data, the contents are
    /// added to the ParameterFeedback. This is useful because if create make a resource in the
    /// program under test, future requests need to be able to refer back to it.
    pub fn process_post_request(&mut self, request_index: usize, request: OpenApiRequest) {
        match request.body {
            Body::ApplicationJson(Object(obj_contents))
            | Body::XWwwFormUrlencoded(Object(obj_contents))
                if request.method == Method::Post =>
            {
                for (param, value) in obj_contents {
                    self.set(request_index, param, value.to_value());
                }
            }
            _ => (),
        }
    }

    #[allow(unused)]
    fn reset(&mut self) {
        self.0.clear()
    }
}
