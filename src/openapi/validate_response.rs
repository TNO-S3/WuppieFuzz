use std::{error::Error, str::Utf8Error};

use anyhow::Result;
use oas3::spec::{
    BooleanSchema, ObjectOrReference, ObjectSchema, Schema, SchemaType, SchemaTypeSet,
};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::Value;
use strum::{EnumDiscriminants, EnumString, VariantArray};

use super::JsonContent;
use crate::{
    input::{Method, OpenApiRequest},
    openapi::spec::Spec,
};

/// The Response object provided by Reqwest is unwieldy, since its body contents
/// can only be obtained once by consuming the object. This prevents later reading
/// the status or obtaining the body contents again in another form.
///
/// This Response is created from a `reqwest::blocking::Response` and allows accessing the
/// body contents by reference.
#[derive(Clone)]
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
    pub fn cookies(&self) -> Vec<(String, String)> {
        self.cookies.clone()
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
#[derive(Debug, EnumDiscriminants)]
#[strum_discriminants(derive(EnumString, VariantArray, Deserialize))]
pub enum ValidationError {
    /// The operation does not exist in the spec, which incidentally means it should
    /// not have been executed by the fuzzer to begin with.
    ///
    /// If this variant is returned, it suggests a bug in the fuzzer.
    OperationNotInSpec { path: String, method: Method },

    /// The 5xx HTTP status code returned from the API is not one of the status codes
    /// mentioned for this path in the specification.
    ///
    /// If this variant is returned, the API does not behave as specified. This error is
    /// only captures 5xx status codes; for other status codes, see `ValidationError::StatusNon5xxNotSpecified`.
    /// This distinction can be helpful because a 5xx status code often indicates a more
    /// severe or 'real' crash.
    Status5xxNotSpecified { got: StatusCode },

    /// The HTTP status code (1xx - 4xx) returned from the API is not one of the status codes
    /// mentioned for this path in the specification.
    ///
    /// If this variant is returned, the API does not behave as specified. This error is
    /// only captures status codes from 1xx to 4xx; for 5xx codes, see `ValidationError::Status5xxNotSpecified`.
    /// This distinction can be helpful because a 5xx status code often indicates a more
    /// severe or 'real' crash.
    OtherStatusNotSpecified { got: StatusCode },

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

    /// The schema is BooleanSchema::false, which does not describe any response.
    /// https://json-schema.org/draft/2020-12/draft-bhutton-json-schema-01#name-boolean-json-schemas
    SchemaIsFalse,
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

/// Resolves the reference, wrapping any error in a ValidationError.
/// Returns a clone of T since this is also how oas3 works.
fn resolve_ref_or_validation_error<T>(
    ref_or_obj: &ObjectOrReference<T>,
    api: &Spec,
) -> Result<T, ValidationError>
where
    T: oas3::spec::FromRef,
{
    Ok(match ref_or_obj {
        oas3::spec::ObjectOrReference::Ref { ref_path, .. } => {
            ref_or_obj
                .resolve(api)
                .map_err(|err| ValidationError::ResponseReferenceBroken {
                    reference: ref_path.clone(), // Hopefully moved by the compiler :(
                    inner_err: err.into(),
                })?
        }
        oas3::spec::ObjectOrReference::Object(object) => object.clone(),
    })
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            ValidationError::OperationNotInSpec { path, method } => write!(
                fmt,
                "Operation {method} {path} does not occur in specification"
            ),
            ValidationError::Status5xxNotSpecified { got }
            | ValidationError::OtherStatusNotSpecified { got } => {
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
            ValidationError::SchemaIsFalse => write!(
                fmt,
                "The specification contains the `false` schema for this response, which must never validate."
            ),
        }
    }
}
impl Error for ValidationError {}

// Validates whether the response matches the API.
// The return value contains a description of the particular mismatch.
pub fn validate_response(
    api: &Spec,
    request: &OpenApiRequest,
    response: &Response,
) -> Result<(), ValidationError> {
    let op = super::find_operation(api, &request.path, request.method).ok_or_else(|| {
        ValidationError::OperationNotInSpec {
            path: request.path.clone(),
            method: request.method,
        }
    })?;

    let ref_or_desired_response = op
        .responses
        .as_ref()
        .and_then(|map| map.get(response.status().as_str()))
        .ok_or_else(|| {
            if response.status().is_server_error() {
                ValidationError::Status5xxNotSpecified {
                    got: response.status(),
                }
            } else {
                ValidationError::OtherStatusNotSpecified {
                    got: response.status(),
                }
            }
        })?;

    let response_options = resolve_ref_or_validation_error(ref_or_desired_response, api)?;

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
    let ref_or_response_schema = media_type
        .schema
        .as_ref()
        .ok_or_else(|| ValidationError::MediaTypeContainsNoSchema)?;
    let response_schema = resolve_ref_or_validation_error(ref_or_response_schema, api)?;

    let response_contents = response
        .json()
        .map_err(|e| ValidationError::ResponseMalformedJSON { error: e })?;

    validate_object_against_object_schema(api, &response_schema, &response_contents)
}

/// Validates whether an object is correct according to a schema.
/// This special variant `Schema` of the schema object `ObjectSchema`
/// allows boolean schemas, which are assertion-only.
fn validate_object_against_schema(
    api: &Spec,
    schema: &Schema,
    response_contents: &Value,
) -> Result<(), ValidationError> {
    match schema {
        Schema::Boolean(BooleanSchema(true)) => Ok(()),
        Schema::Boolean(BooleanSchema(false)) => Err(ValidationError::SchemaIsFalse),
        Schema::Object(object_or_reference) => validate_object_against_object_schema(
            api,
            &resolve_ref_or_validation_error(object_or_reference, api)?,
            response_contents,
        ),
    }
}

/// Validates whether an object is correct according to a schema.
fn validate_object_against_object_schema(
    api: &Spec,
    schema: &ObjectSchema,
    response_contents: &Value,
) -> Result<(), ValidationError> {
    if schema.schema_type.is_some() {
        return validate_object_against_type_set(api, schema, response_contents);
    }

    if !schema.any_of.is_empty() {
        // AnyOf: the response must validate against at least one of the schemas
        schema
            .any_of
            .iter()
            .map(|ref_or_schema| {
                validate_object_against_ref_or_schema(api, ref_or_schema, response_contents)
            })
            // If any schema validates the response, return Ok(())
            .reduce(Result::or)
            .expect("any_of was checked to be nonempty")?;
    }

    if !schema.one_of.is_empty() {
        if schema
            .one_of
            .iter()
            .filter_map(|ref_or_schema| {
                validate_object_against_ref_or_schema(api, ref_or_schema, response_contents).ok()
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
        }?;
    }

    if !schema.all_of.is_empty() {
        schema.all_of.iter().try_for_each(|ref_or_schema| {
            validate_object_against_ref_or_schema(api, ref_or_schema, response_contents)
        })?;
    }

    Ok(())
}

/// Validates whether an object is correct by attempting to resolve a `reference_or`
/// containing a schema, and if it resolves, validating the object against the contained
/// schema
fn validate_object_against_ref_or_schema(
    api: &Spec,
    ref_or_schema: &ObjectOrReference<ObjectSchema>,
    response_contents: &Value,
) -> Result<(), ValidationError> {
    // First resolve the ReferenceOr object using the API ... and then use the schema to validate the given response
    validate_object_against_object_schema(
        api,
        &resolve_ref_or_validation_error(ref_or_schema, api)?,
        response_contents,
    )
}

/// Validates whether an object is correct according to a type set
fn validate_object_against_type_set(
    api: &Spec,
    schema: &ObjectSchema,
    response_contents: &Value,
) -> Result<(), ValidationError> {
    match &schema.schema_type {
        None => Ok(()),
        Some(SchemaTypeSet::Single(schema_type)) => {
            validate_object_against_type(api, schema_type, schema, response_contents)
        }
        Some(SchemaTypeSet::Multiple(schema_types)) => {
            for schema_type in schema_types {
                if validate_object_against_type(api, schema_type, schema, response_contents).is_ok()
                {
                    return Ok(());
                }
            }
            Err(ValidationError::ResponseObjectIncorrect {
                msg: format!(
                    "Expected the response to be one of {schema_types:?}, but it was {response_contents:?}"
                ),
            })
        }
    }
}

/// Validates whether an object is correct according to a concrete type.
/// The SchemaType given should be an element of the schema_type member.
fn validate_object_against_type(
    api: &Spec,
    expected_type: &SchemaType,
    schema: &ObjectSchema,
    response_contents: &Value,
) -> Result<(), ValidationError> {
    let make_err = |err_str| Err(ValidationError::ResponseObjectIncorrect { msg: err_str });

    match (expected_type, response_contents) {
        (SchemaType::Boolean, Value::Bool(_)) => Ok(()),
        (SchemaType::Integer, Value::Number(n)) => match n.as_i64() {
            Some(_) => Ok(()),
            None => make_err(
                format!("Response number {n} does not match expected type Integer (as i64)"),
            ),
        },
        (SchemaType::Number, Value::Number(n)) => match n.as_f64() {
            Some(_) => Ok(()),
            None => make_err(
                format!("Response number {n} does not match expected type Number (as f64)"),
            ),
        },
        (SchemaType::String, Value::String(a_string)) => {
            // If the type is an enum, check that the value is one of the correct variants.
            if !schema.enum_values.is_empty() && !schema.enum_values.iter().any(|v| v == a_string) {
                return Err(ValidationError::ResponseEnumIncorrect {
                    incorrect_variant: a_string.clone(),
                });
            }
            Ok(())
        }
        (SchemaType::Array, Value::Array(a_vec)) => {
            // Find the schema for the array items. If there is no schema, we accept
            // any item we find
            let item_schema: &Schema = match schema.items {
                Some(ref schema) => schema,
                None => return Ok(()),
            };
            // Check for each item that it matches the schema
            for (index, value) in a_vec.iter().enumerate() {
                validate_object_against_schema(api, item_schema, value)
                    .map_err(|v| v.nested(&format!("{index}")))?;
            }

            Ok(())
        }
        (SchemaType::Object, Value::Object(o_map)) => {
            // Check for each field in the response object if it should be there,
            // and if it matches the schema. If we find no schema, we assume that is
            // because the field shouldn't be there
            for (key, value) in o_map.iter() {
                let item_schema: ObjectSchema = match schema.properties.get(key) {
                    Some(ref_or) => resolve_ref_or_validation_error(ref_or,api).map_err(|err| err.nested(key))?,
                    None => {
                        return make_err(format!(
                            "Object property \"{key}\" in response not expected \
                            in specified object schema. Expected properties: {:?}",
                            schema.properties,
                        )).map_err(|err| err.nested(key));
                    }
                };
                validate_object_against_object_schema(api, &item_schema, value)
                    .map_err(|err| err.nested(key))?;
            }

            // Check for each required field in the schema whether it is contained
            // in the response object
            for key in &schema.required {
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
