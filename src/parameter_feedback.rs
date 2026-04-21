use std::collections::HashMap;

use crate::{
    input::{Body, OpenApiRequest, ParameterContents, parameter::ParameterKind},
    openapi::validate_response::Response,
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

    fn add_request_parameter(&mut self, addressing: ParameterAddressing, field: ParameterContents) {
        self.set(addressing, field.clone());
    }

    /// Processes the resolved parameter values in an OpenApiRequest.
    pub fn process_request(&mut self, request_index: usize, request: &OpenApiRequest) {
        match &request.body {
            Body::Empty => {}
            Body::TextPlain(body)
            | Body::ApplicationJson(body)
            | Body::XWwwFormUrlencoded(body) => self.add_request_parameter(
                ParameterAddressing::new(
                    request_index,
                    ParameterAccess::request_body(ParameterAccessElements::new()),
                ),
                body.clone(),
            ),
        }

        for ((name, kind), value) in &request.parameters {
            let access = match kind {
                ParameterKind::Query => ParameterAccess::request_query(name.clone()),
                ParameterKind::Path => ParameterAccess::request_path(name.clone()),
                ParameterKind::Header => ParameterAccess::request_header(name.clone()),
                ParameterKind::Cookie => ParameterAccess::request_cookie(name.clone()),
                ParameterKind::Body => continue,
            };
            self.add_request_parameter(
                ParameterAddressing::new(request_index, access),
                value.clone(),
            );
        }
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::ParameterFeedback;
    use crate::{
        input::{
            Body, Method, OpenApiRequest, ParameterContents,
            parameter::{IReference, ParameterKind},
        },
        parameter_access::{ParameterAccess, ParameterAccessElement, ParameterAccessElements},
    };

    #[test]
    fn process_request_records_request_values() {
        let mut feedback = ParameterFeedback::new(1);
        let request = OpenApiRequest {
            method: Method::Post,
            path: "/widgets/{widget_id}".to_string(),
            body: Body::ApplicationJson(
                serde_json::json!({
                    "outer": {
                        "inner": 37
                    }
                })
                .into(),
            ),
            parameters: BTreeMap::from([
                (
                    ("search".to_string(), ParameterKind::Query),
                    "needle".to_string().into(),
                ),
                (
                    ("widget_id".to_string(), ParameterKind::Path),
                    "abc123".to_string().into(),
                ),
                (
                    ("x-trace".to_string(), ParameterKind::Header),
                    "trace-id".to_string().into(),
                ),
                (
                    ("session".to_string(), ParameterKind::Cookie),
                    "cookie-value".to_string().into(),
                ),
            ]),
        };

        feedback.process_request(0, &request);

        assert_eq!(
            feedback
                .get(0, &ParameterAccess::request_query("search".to_string()))
                .map(ParameterContents::to_value),
            Some(serde_json::json!("needle"))
        );
        assert_eq!(
            feedback
                .get(0, &ParameterAccess::request_path("widget_id".to_string()))
                .map(ParameterContents::to_value),
            Some(serde_json::json!("abc123"))
        );
        assert_eq!(
            feedback
                .get(0, &ParameterAccess::request_header("x-trace".to_string()))
                .map(ParameterContents::to_value),
            Some(serde_json::json!("trace-id"))
        );
        assert_eq!(
            feedback
                .get(0, &ParameterAccess::request_cookie("session".to_string()))
                .map(ParameterContents::to_value),
            Some(serde_json::json!("cookie-value"))
        );
        assert_eq!(
            feedback
                .get(
                    0,
                    &ParameterAccess::request_body(ParameterAccessElements::from_elements(&[
                        ParameterAccessElement::Name("outer".to_string()),
                        ParameterAccessElement::Name("inner".to_string()),
                    ])),
                )
                .map(ParameterContents::to_value),
            Some(serde_json::json!(37))
        );
    }

    #[test]
    fn resolve_parameter_references_uses_recorded_request_values() {
        let first_request = OpenApiRequest {
            method: Method::Post,
            path: "/widgets".to_string(),
            body: Body::ApplicationJson(
                serde_json::json!({
                    "outer": {
                        "inner": "recorded-value"
                    }
                })
                .into(),
            ),
            parameters: BTreeMap::from([(
                ("search".to_string(), ParameterKind::Query),
                "needle".to_string().into(),
            )]),
        };
        let mut second_request = OpenApiRequest {
            method: Method::Get,
            path: "/widgets/{widget_id}".to_string(),
            body: Body::Empty,
            parameters: BTreeMap::from([
                (
                    ("widget_id".to_string(), ParameterKind::Path),
                    ParameterContents::IReference(IReference {
                        request_index: 0,
                        parameter_access: ParameterAccess::request_body(
                            ParameterAccessElements::from_elements(&[
                                ParameterAccessElement::Name("outer".to_string()),
                                ParameterAccessElement::Name("inner".to_string()),
                            ]),
                        ),
                    }),
                ),
                (
                    ("search_copy".to_string(), ParameterKind::Query),
                    ParameterContents::IReference(IReference {
                        request_index: 0,
                        parameter_access: ParameterAccess::request_query("search".to_string()),
                    }),
                ),
            ]),
        };
        let mut feedback = ParameterFeedback::new(2);

        feedback.process_request(0, &first_request);
        second_request
            .resolve_parameter_references(&feedback)
            .expect("request references should resolve from earlier recorded requests");

        assert_eq!(
            second_request
                .parameters
                .get(&("widget_id".to_string(), ParameterKind::Path))
                .map(ParameterContents::to_value),
            Some(serde_json::json!("recorded-value"))
        );
        assert_eq!(
            second_request
                .parameters
                .get(&("search_copy".to_string(), ParameterKind::Query))
                .map(ParameterContents::to_value),
            Some(serde_json::json!("needle"))
        );
    }
}
