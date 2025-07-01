use std::{error::Error, str::Utf8Error};

use anyhow::Result;
use openapiv3::{OpenAPI, ReferenceOr, Schema, Type};
use reqwest::StatusCode;
use serde_json::Value;

use super::JsonContent;
use crate::input::{Method, OpenApiRequest};

/// The Response object provided by Reqwest is unwieldy, since its body contents
/// can only be obtained once by consuming the object. This prevents later reading
/// the status or obtaining the body contents again in another form.
///
/// This Response is created from a `reqwest::blocking::Response` and allows accessing the
/// body contents by reference.
pub struct Response {
    status: reqwest::StatusCode,
    cookies: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    pub fn status(&self) -> reqwest::StatusCode {
        self.status
    }

    /// This returns the length of the decompressed contents, even if no content-length
    /// was sent by the server.
    pub fn content_length(&self) -> u64 {
        self.body.len() as u64
    }

    pub fn text(&self) -> Result<String, Utf8Error> {
        std::str::from_utf8(&self.body).map(|s| s.to_owned())
    }
    pub fn json<'de, T: serde::Deserialize<'de>>(&'de self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
    pub fn cookies(&mut self) -> impl Iterator<Item = (String, String)> + '_ {
        self.cookies.drain(..)
    }
}

impl From<reqwest::blocking::Response> for Response {
    fn from(resp: reqwest::blocking::Response) -> Self {
        Self {
            status: resp.status(),
            cookies: resp
                .cookies()
                .map(|c| (c.name().to_owned(), c.value().to_owned()))
                .collect(),
            body: resp
                .bytes()
                .map(|b| b.into_iter().collect())
                .unwrap_or_default(),
        }
    }
}

/// ValidationError is returned by `validate_response` if a given response should
/// not have been given by the API under test.
#[derive(Debug)]
pub enum ValidationError {
    /// The operation does not exist in the spec, which incidentally means it should
    /// not have been executed by the fuzzer to begin with.
    ///
    /// If this variant is returned, it suggests a bug in the fuzzer.
    OperationNotInSpec { path: String, method: Method },

    /// The HTTP status code returned from the API is not one of the status codes
    /// mentioned for this path in the specification.
    ///
    /// If this variant is returned, the API does not behave as specified.
    StatusNotSpecified { got: StatusCode },

    /// The specification calls for an object to be returned, and refers to the
    /// correct structure of this object using a reference (`#/example/reference`).
    /// However, the reference path is not present in the specification or contains
    /// circular references (the inner_err indicates which).
    ///
    /// If this variant is returned, the API specification is ill-formed.
    ResponseReferenceBroken {
        reference: String,
        inner_err: anyhow::Error,
    },

    /// The response body returned by the API does not match the structure specified
    /// in the API specification.
    ///
    /// If this variant is returned, the API does not behave as specified.
    ResponseObjectIncorrect { msg: String },

    /// A field in the response body object is specified as an enumeration, but
    /// the returned value is not one of the possible variants.
    ///
    /// If this variant is returned, the API does not behave as specified.
    ResponseEnumIncorrect { incorrect_variant: String },

    /// The response body returned by the API can not be parsed as JSON.
    ///
    /// If this variant is returned, the API might contain a bug, or it might
    /// return some other type of response. Only JSON responses are currently
    /// supported.
    ResponseMalformedJSON { error: serde_json::Error },

    /// The API returned a response body, but no response is specified.
    ///
    /// If this variant is returned, the API does not behave as specified.
    UnexpectedContent { content_length: u64 },

    /// The API contains a media type "application/json" with no schema for
    /// the data inside the json object. We can't validate the response if no
    /// model is given.
    MediaTypeContainsNoSchema,

    /// The schema can be anything (occurs e.g. when it does not specify a type)
    /// We cannot validate schemas that are this flexible.
    SchemaIsAny(String),
}

impl ValidationError {
    /// Validation happens recursively, and if a deeply nested field contains an
    /// error, it is nice if the validation error that is eventually returned
    /// pinpoints the path to the field that is incorrect.
    /// E.g. if field 'cow' is an array and the fifth element is incorrect, we'd
    /// like the error's `incorrect_field` field to be `cow/4`.
    fn nested(mut self, dir: &str) -> Self {
        let nest = |incorrect_key: &mut String| {
            incorrect_key.insert_str(0, dir);
            if incorrect_key.len() > dir.len() {
                incorrect_key.insert(dir.len(), '/')
            }
        };
        match self {
            Self::ResponseObjectIncorrect {
                msg: ref mut incorrect_key,
            } => nest(incorrect_key),
            Self::ResponseEnumIncorrect {
                ref mut incorrect_variant,
            } => nest(incorrect_variant),
            _ => (),
        };
        self
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            ValidationError::OperationNotInSpec { path, method } => write!(
                fmt,
                "Operation {method} {path} does not occur in specification"
            ),
            ValidationError::StatusNotSpecified { got } => {
                write!(fmt, "Returned HTTP status {got} not allowed for this path")
            }
            ValidationError::ResponseReferenceBroken {
                reference,
                inner_err,
            } => write!(fmt, "Response model {reference} unresolvable: {inner_err}"),
            ValidationError::ResponseObjectIncorrect { msg: err_msg } => {
                write!(fmt, "Response object incorrect: {err_msg}")
            }
            ValidationError::ResponseMalformedJSON { error } => {
                write!(fmt, "Error parsing response as JSON: {error}")
            }
            ValidationError::UnexpectedContent { content_length } => write!(
                fmt,
                "Unexpected response body content. content-length: {content_length}"
            ),
            ValidationError::ResponseEnumIncorrect { incorrect_variant } => write!(
                fmt,
                "Response enumeration has non-existent variant {incorrect_variant}"
            ),
            ValidationError::MediaTypeContainsNoSchema => write!(
                fmt,
                "The specification does not contain a schema for JSON responses, so the response can not be validated"
            ),
            ValidationError::SchemaIsAny(schema_str) => write!(
                fmt,
                "The specification accepts any schema for this response, which is too flexible for us to validate. \
                Make sure the schema specifies a type!\nSchema description: {schema_str}"
            ),
        }
    }
}
impl Error for ValidationError {}

// Validates whether the response matches the API.
// The return value contains a description of the particular mismatch.
pub fn validate_response(
    api: &OpenAPI,
    request: &OpenApiRequest,
    response: &Response,
) -> Result<(), ValidationError> {
    let op = super::find_operation(api, &request.path, request.method).ok_or_else(|| {
        ValidationError::OperationNotInSpec {
            path: request.path.clone(),
            method: request.method,
        }
    })?;

    let desired_response = op
        .responses
        .responses
        .get(&openapiv3::StatusCode::Code(response.status().as_u16()))
        .ok_or_else(|| ValidationError::StatusNotSpecified {
            got: response.status(),
        })?;
    let response_options =
        desired_response
            .resolve(api)
            .map_err(|err| ValidationError::ResponseReferenceBroken {
                reference: desired_response.as_ref_str().unwrap_or_default().to_owned(),
                inner_err: err,
            })?;

    // We now have a response and the list of valid response_options.
    // If there is no valid option for application/json, the response should also be empty.
    let media_type = match response_options.content.get_json_content() {
        Some(media_type) => media_type,
        None => {
            let content_length = response.content_length();
            return if content_length > 0 {
                Err(ValidationError::UnexpectedContent { content_length })
            } else {
                Ok(())
            };
        }
    };

    // Extract the schema for a correct response. If none exists, we can't really check
    // anything, and we consider that a specification error.
    let response_schema = media_type
        .schema
        .as_ref()
        .ok_or_else(|| ValidationError::MediaTypeContainsNoSchema)?
        .resolve(api);

    let response_contents = response
        .json()
        .map_err(|e| ValidationError::ResponseMalformedJSON { error: e })?;

    validate_object_against_schema(api, response_schema, &response_contents)
}

/// Validates whether an object is correct according to a schema.
fn validate_object_against_schema(
    api: &OpenAPI,
    schema: &Schema,
    response_contents: &Value,
) -> Result<(), ValidationError> {
    match &schema.kind {
        openapiv3::SchemaKind::Type(expected_type) => {
            validate_object_against_type(api, expected_type, response_contents)
        }

        // AnyOf: the response must validate against at least one of the schemas
        openapiv3::SchemaKind::AnyOf {
            any_of: expected_schemas,
        } => expected_schemas
            .iter()
            .map(|ref_or_schema| {
                validate_object_against_ref_or_schema(api, ref_or_schema, response_contents)
            })
            // If any schema validates the response, return Ok(())
            .reduce(Result::or)
            // If there were no schemas (AnyOf(empty set) ??), return Ok(())
            .unwrap_or(Ok(())),

        // OneOf: the response must validate against exactly one of the schemas
        openapiv3::SchemaKind::OneOf {
            one_of: expected_schemas,
        } => {
            if expected_schemas
                .iter()
                .filter_map(|ref_or_schema| {
                    validate_object_against_ref_or_schema(api, ref_or_schema, response_contents)
                        .ok()
                })
                // Count the Ok(())s, must be exactly one
                .count()
                == 1
            {
                Ok(())
            } else {
                Err(ValidationError::ResponseObjectIncorrect {
                    msg: format!(
                        "Response content {response_contents:?} did not match against exactly one expected schema"
                    ),
                })
            }
        }

        // AllOf: the response must validate against all of the schemas
        openapiv3::SchemaKind::AllOf {
            all_of: expected_schemas,
        } => expected_schemas.iter().try_for_each(|ref_or_schema| {
            validate_object_against_ref_or_schema(api, ref_or_schema, response_contents)
        }),

        // Not: the response must fail to validate the given schema
        openapiv3::SchemaKind::Not { not: ref_or_schema } => {
            match validate_object_against_ref_or_schema(api, ref_or_schema, response_contents) {
                Ok(()) => Err(ValidationError::ResponseObjectIncorrect {
                    msg: format!(
                        "Response content {response_contents} matched schema when it should not."
                    ),
                }),
                Err(_) => Ok(()),
            }
        }
        openapiv3::SchemaKind::Any(schema) => {
            Err(ValidationError::SchemaIsAny(format!("{schema:?}")))
        }
    }
}

/// Validates whether an object is correct by attempting to resolve a `reference_or`
/// containing a schema, and if it resolves, validating the object against the contained
/// schema
fn validate_object_against_ref_or_schema(
    api: &OpenAPI,
    ref_or_schema: &ReferenceOr<Schema>,
    response_contents: &Value,
) -> Result<(), ValidationError> {
    // First resolve the ReferenceOr object using the API ... and then use the schema to validate the given response
    validate_object_against_schema(api, ref_or_schema.resolve(api), response_contents)
}

/// Validates whether an object is correct according to a concrete type
fn validate_object_against_type(
    api: &OpenAPI,
    expected_type: &Type,
    response_contents: &Value,
) -> Result<(), ValidationError> {
    let make_err = |err_str| Err(ValidationError::ResponseObjectIncorrect { msg: err_str });

    match (expected_type, response_contents) {
        (Type::Boolean { .. }, Value::Bool(_)) => Ok(()),
        (Type::Integer(_), Value::Number(n)) => match n.as_i64() {
            Some(_) => Ok(()),
            None => make_err(
                format!("Response number {n} does not match expected type Integer (as i64)"),
            ),
        },
        (Type::Number(_), Value::Number(n)) => match n.as_f64() {
            Some(_) => Ok(()),
            None => make_err(
                format!("Response number {n} does not match expected type Number (as f64)"),
            ),
        },
        (Type::String(s_type), Value::String(a_string)) => {
            // If the type is an enum, check that the value is one of the correct variants.
            if !s_type.enumeration.is_empty() && !s_type.enumeration.iter().any(|v| v == a_string) {
                return Err(ValidationError::ResponseEnumIncorrect {
                    incorrect_variant: a_string.clone(),
                });
            }
            Ok(())
        }
        (Type::Array(a_type), Value::Array(a_vec)) => {
            // Find the schema for the array items. If there is no schema, we accept
            // any item we find
            let item_schema: &Schema = match a_type.items {
                Some(ref ref_or) => ref_or.resolve(api),
                None => return Ok(()),
            };
            // Check for each item that it matches the schema
            for (index, value) in a_vec.iter().enumerate() {
                validate_object_against_schema(api, item_schema, value)
                    .map_err(|v| v.nested(&format!("{index}")))?;
            }

            Ok(())
        }
        (Type::Object(o_type), Value::Object(o_map)) => {
            // Check for each field in the response object if it should be there,
            // and if it matches the schema. If we find no schema, we assume that is
            // because the field shouldn't be there
            for (key, value) in o_map.iter() {
                let item_schema: &Schema = match o_type.properties.get(key) {
                    Some(ref_or) => ref_or.resolve(api),
                    None => {
                        return make_err(format!(
                            "Object property \"{key}\" in response not expected \
                            in specified object schema. Expected properties: {:?}",
                            o_type.properties,
                        )).map_err(|err| err.nested(key));
                    }
                };
                validate_object_against_schema(api, item_schema, value)
                    .map_err(|err| err.nested(key))?;
            }

            // Check for each required field in the schema whether it is contained
            // in the response object
            for key in &o_type.required {
                if !o_map.contains_key(key) {
                    return make_err(
                        format!("Response object does not contain specified property \"{key}\"."),
                    )
                    .map_err(|err| err.nested(key));
                }
            }

            Ok(())
        }

        _ => make_err(format!("Expected type {expected_type:?} and actual response type {response_contents:?} do not match.").to_owned()),
    }
}
