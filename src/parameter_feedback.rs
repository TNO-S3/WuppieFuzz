use std::collections::HashMap;

use crate::{
    input::ParameterContents,
    openapi::validate_response::{Response},
    parameter_access::{
        ParameterAccess, ParameterAccessElements, ParameterAddressing, RequestParameterAccess,
        ResponseParameterAccess,
    },
};

/// ParameterFeedbackMetadata collects parameter values from requests as they
/// are made and responses as they are received. This allows the harness to insert
/// the values in subsequent requests if a parameter contains a backreference.
///
/// The struct wraps a Vec where feedback for the Nth request/response is stored
/// in element N. Each element is a HashMap with ParameterAccess keys, so that
/// any flavor (body, header, cookie, etc.) feedback can be stored for both
/// requests and responses.
///
/// Note that for Body feedback, Object values are stored as-is; the
/// ParameterAccess contains an empty ParameterAccessElements indicating
/// that the Value is the entire request/response body. Any indexing with a
/// ParameterAccess must be done manually.
#[derive(Debug, Clone)]
pub struct ParameterFeedback(Vec<HashMap<ParameterAccess, ParameterContents>>);

impl From<&Vec<HashMap<ParameterAccess, ParameterContents>>> for ParameterFeedback {
    fn from(collection: &Vec<HashMap<ParameterAccess, ParameterContents>>) -> Self {
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
    pub fn get(
        &self,
        request_index: usize,
        access: &ParameterAccess,
    ) -> Option<&ParameterContents> {
        // Tuple indexing leads to clones... Better to implement as double hashmap?
        let nth_feedbacks = self.0.get(request_index)?;
        let nth_feedback = nth_feedbacks.get(access);
        if nth_feedback.is_some() {
            nth_feedback
        } else {
            // ParameterContents may be stored for "empty" access, if no root level key is used
            // such as for an object in the Body.
            match access {
                ParameterAccess::Request(request_access) => {
                    let root_value = nth_feedbacks.get(&ParameterAccess::request_body(
                        ParameterAccessElements::new(),
                    ))?;
                    match request_access {
                        RequestParameterAccess::Body(_) => root_value.resolve(access),
                        _ => None,
                    }
                }
                ParameterAccess::Response(response_access) => {
                    let root_value = nth_feedbacks.get(&ParameterAccess::response_body(
                        ParameterAccessElements::new(),
                    ))?;
                    match response_access {
                        ResponseParameterAccess::Body(_) => root_value.resolve(access),
                        _ => None,
                    }
                }
            }
        }
    }

    pub fn contains(&self, request_index: usize, param: &ParameterAccess) -> bool {
        self.0
            .get(request_index)
            .map(|m| m.contains_key(param))
            .unwrap_or(false)
    }

    /// Adds the given parameter/value combination to memory. Returns whether successful
    /// (if the request index is out of bounds, false is returned).
    pub(crate) fn set(
        &mut self,
        addressing: ParameterAddressing,
        value: ParameterContents,
    ) -> bool {
        self.0
            .get_mut(addressing.request_index)
            .map(|m| m.insert(addressing.access, value))
            .is_some()
    }

    fn add_response_parameter(
        &mut self,
        addressing: ParameterAddressing,
        field: ParameterContents,
    ) {
        self.set(addressing, field.clone());
    }

    /// Processes the values returned in a Response.
    ///
    /// The body is parsed as a json object or an array of objects, and if successful,
    /// the fields are saved as parameter values. Cookies set as a `Set-Cookie` header
    /// are saved in their `param=value` form.
    pub fn process_response(&mut self, request_index: usize, response: &Response) {
        // We take any returned json values and save key-value parameters we find
        // (e.g. id = 37) for use as parameters in later requests.
        match response.json::<serde_json::Value>() {
            // Objects in responses: save all field/value combinations
            Ok(field) => self.add_response_parameter(
                ParameterAddressing::new(
                    request_index,
                    ParameterAccess::response_body(ParameterAccessElements::new()),
                ),
                field.into(),
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
                value.into(),
            );
        }
    }

    #[allow(unused)]
    fn reset(&mut self) {
        self.0.clear()
    }
}
