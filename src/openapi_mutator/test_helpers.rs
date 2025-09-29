//! Helper functions that generate commonly used test requests

use std::collections::BTreeMap;

use crate::{
    input::{
        Body, Method, OpenApiInput, OpenApiRequest, ParameterContents, parameter::ParameterKind,
    },
    parameter_access::{ParameterAccess, ParameterAccessElements},
};

/// Returns an input consisting of one request to the simple endpoint
pub fn simple_request() -> OpenApiInput {
    OpenApiInput(vec![OpenApiRequest {
        method: Method::Get,
        path: "/simple".to_string(),
        body: Body::Empty,
        parameters: BTreeMap::new(),
    }])
}

/// Returns an input consisting of two requests, where the second one uses
/// a return value from the first one as a parameter value
pub fn linked_requests() -> OpenApiInput {
    let mut parameters = BTreeMap::new();
    parameters.insert(
        ("id".into(), ParameterKind::Query),
        ParameterContents::Reference {
            request_index: 0,
            parameter_access: ParameterAccess::Body(ParameterAccessElements::from_elements(&vec![
                "id".to_string().into(),
            ])),
        },
    );
    let has_param = OpenApiRequest {
        method: Method::Get,
        path: "/with-query-parameter".to_string(),
        body: Body::Empty,
        parameters,
    };

    let has_return_value = OpenApiRequest {
        method: Method::Get,
        path: "/simple".to_string(),
        body: Body::Empty,
        parameters: BTreeMap::new(),
    };

    OpenApiInput(vec![has_return_value, has_param])
}
