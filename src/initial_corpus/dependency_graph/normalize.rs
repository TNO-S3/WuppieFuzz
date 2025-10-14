//! When making a dependency graph, it's common (unfortunately) to come across field names
//! and parameters that have the same meaning but not the same name. The normalization
//! module attempts to deal with this by deriving a normalized variant for each parameter's
//! name.
//!
//! When doing so, we incorporate the context into the normalized name. For instance, a
//! parameter 'id' in a request to a path ending in 'artist/' suggests that this is the ID
//! of an artist, and so the normalization is something like 'artist|id'. When an album
//! later refers to an 'artist_id', there is an opportunity to match it to the 'id' found
//! earlier.

use openapiv3::{
    MediaType, ObjectType, OpenAPI, Operation, Parameter, RequestBody, Response, Schema, SchemaKind,
};

use crate::{
    openapi::JsonContent,
    parameter_access::{ParameterAccess, ParameterAccessElement, ParameterAccessElements},
};

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ReqResp {
    Req,
    Resp,
}

fn deduplicate_context_from_name(name: &str, context: Option<&str>) -> String {
    // If the name ends in a magic string, consider that the name, and the part before it the context.
    if let Some(context_str) = context {
        let last = name.len() - 1;
        let no_context_name = if let Some(i) = name.find(['-', '_'])
            && (i != 0 && i != last && stem(context_str) == stem(&name[..i]))
        {
            &name[i + 1..]
        } else if ["id", "Id", "ID"].iter().any(|id| name.ends_with(id))
            && stem(context_str) == stem(&name[..name.len() - 2])
        {
            "id"
        } else {
            name
        };
        no_context_name.to_string()
    } else {
        name.to_string()
    }
}

/// A parameter name saved in two variants: the canonical name appearing in the spec,
/// and the normalized form used for matching input and output parameters
#[derive(Debug, Clone, PartialEq)]
pub struct ParameterNormalization {
    pub name: String,
    pub normalized: String,
    pub context: Option<String>,
    pub(crate) parameter_access: ParameterAccess,
}

impl ParameterNormalization {
    /// Creates a new ParameterNormalization based on the parameter name given as `name`
    /// and an optional context. The context is understood to be the name of the object
    /// and the parameter name is then one of its properties. The normalization of
    /// "color" for context "widget" might then be "widget|color", whereas "color" without
    /// context just normalizes to color.
    /// Both the name and the context are 'stemmed', i.e. reduced to a base grammatical
    /// form, so the normalization is the same if a word is sometimes plural, or British
    /// and American spellings are mixed.
    ///
    /// What constitutes the name and especially the context depends on the ParameterKind,
    /// see the factory methods query_header_cookie(...), path(...) and body(...) how they
    /// are derived in each case.
    ///
    pub fn new(name: String, context: Option<String>, parameter_access: ParameterAccess) -> Self {
        // Remove any duplicated context from the name (pet_id in pet-context => id)
        let dedup_name = deduplicate_context_from_name(&name, context.as_deref());
        // Normalization is created from stemmed versions of context and name
        Self {
            normalized: if let Some(ref context_str) = context
                && !context_str.is_empty()
            {
                stem(context_str) + "|" + &stem(&dedup_name)
            } else {
                stem(&dedup_name)
            },
            name: dedup_name,
            context,
            parameter_access,
        }
    }

    fn query_header_cookie(access: ParameterAccess, path: Vec<&str>) -> Self {
        // Query, Header and Cookie are all treated the same for normalization;
        // the context is the last element of the URL-path, if present.
        let access_name = access.get_non_body_access_element().unwrap();
        let context = path
            .last()
            .map(|last_path_element| last_path_element.to_string());
        Self::new(access_name, context, access)
    }

    fn path(access: ParameterAccess, path: Vec<&str>) -> Result<Self, String> {
        // For a (templated) path parameter, the context is the last part of the
        // path before the parameter: /shop/pet/{name} => context = pet
        let access_name = access.get_non_body_access_element().unwrap();
        // Use the last part of the path before the templated parameter as context
        let context = {
            path.iter()
                .position(|path_part| path_part == &format!("{{{access_name}}}"))
                .map(|start_of_parameter| path[..start_of_parameter].to_vec())
                .ok_or_else(|| {
                    format!(
                        "Parameter {} must be templated in path {}",
                        access_name,
                        path.join("/")
                    )
                })?
                .last()
                .map(|last_path_element| last_path_element.to_string())
        };
        Ok(Self::new(access_name, context, access))
    }

    fn body(access: ParameterAccess, path: Vec<String>) -> Self {
        // Context for a body parameter is either the named field in the body,
        // one level higher than the parameter itself, or if this is not suitable,
        // the last element of the path.
        let access_elements = access.get_body_access_elements().unwrap();
        // Discard offsets for name- and context-determination
        let named_access_elements: Vec<_> = access_elements
            .0
            .iter()
            .filter_map(|e| {
                if let ParameterAccessElement::Name(name) = e {
                    Some(name.to_owned())
                } else {
                    None
                }
            })
            .collect();
        let access_len = named_access_elements.len();
        let (name, context) = match access_len {
            // Get name and context from path
            0 => match path.len() {
                0 => ("".into(), None),
                1 => (path[0].clone(), None),
                _ => (
                    path[path.len() - 1].clone(),
                    Some(path[path.len() - 2].clone()),
                ),
            },
            // Name from body, context from path
            1 => match path.len() {
                0 => (named_access_elements[0].clone(), None),
                _ => (named_access_elements[0].clone(), Some(path[0].clone())),
            },
            // Name and context both from body
            _ => (
                named_access_elements[access_len - 1].clone(),
                Some(named_access_elements[access_len - 2].clone()),
            ),
        };
        Self::new(name, context, access)
    }
}

/// Finds all request parameters used in an operation and returns their normalized name.
/// See `normalize_parameter` for treatment of parameters named 'id'.
pub fn normalize_parameters<'a>(
    api: &'a OpenAPI,
    path: &str,
    operation: &'a Operation,
) -> Vec<ParameterNormalization> {
    operation
        .parameters
        .iter()
        // Keep only concrete values and valid references
        .filter_map(|ref_or_param| ref_or_param.resolve(api).ok())
        .filter_map(|param| {
            let normalization_attempt = normalize_parameter(path, param);
            if normalization_attempt.is_err() {
                log::error!("Cannot normalize parameter {param:?}: {normalization_attempt:?}")
            }
            normalization_attempt.ok()
        })
        .collect()
}

/// Normalizes a request parameter name.
///
/// If the parameter is in the path but the path does not contain a templated
/// parameter with that name, an error is returned.
fn normalize_parameter(
    path: &str,
    parameter: &Parameter,
) -> Result<ParameterNormalization, String> {
    let parameter_name = parameter.data.name.clone();
    let path_parts: Vec<_> = path.split('/').collect();

    match &parameter.kind {
        openapiv3::ParameterKind::Query { .. } => Ok(ParameterNormalization::query_header_cookie(
            ParameterAccess::request_query(parameter_name.clone()),
            path_parts,
        )),
        openapiv3::ParameterKind::Header { .. } => Ok(ParameterNormalization::query_header_cookie(
            ParameterAccess::request_header(parameter_name.clone()),
            path_parts,
        )),
        openapiv3::ParameterKind::Cookie { .. } => Ok(ParameterNormalization::query_header_cookie(
            ParameterAccess::request_cookie(parameter_name.clone()),
            path_parts,
        )),
        openapiv3::ParameterKind::Path { .. } => ParameterNormalization::path(
            ParameterAccess::request_path(parameter_name.clone()),
            path_parts,
        ),
    }
}

/// Normalizes response parameters.
///
/// For the given response, any application/json content is extracted, and
/// the field names of any top-level object are returned in stemmed form.
/// The URL is used to add context to parameters named "id": those are prepended
/// with the stem of the last non-parameter component of the URL. For example,
/// an "id" parameter returned from `PATCH /tank/{id}` is renamed to "tankid".
pub fn normalize_response<'a>(
    api: &'a OpenAPI,
    response: &'a Response,
    path: Vec<String>,
) -> Option<Vec<ParameterNormalization>> {
    normalize_media_type(
        api,
        response.content.get_json_content()?,
        path,
        ReqResp::Resp,
    )
}

/// Normalizes request body parameters.
///
/// For the given body, any application/json content is extracted, and
/// the field names of any top-level object are returned in stemmed form.
/// The URL is used to add context to parameters named "id": those are prepended
/// with the stem of the last non-parameter component of the URL. For example,
/// an "id" parameter sent to `POST /tank` is renamed to "tankid".
pub fn normalize_request_body<'a>(
    api: &'a OpenAPI,
    body: &'a RequestBody,
    path: Vec<String>,
) -> Option<Vec<ParameterNormalization>> {
    normalize_media_type(api, body.content.get_json_content()?, path, ReqResp::Req)
}

/// Schema describes contents of objects and arrays. This function normalizes field
/// names in a schema if it contains an object or an array of objects.
fn normalize_schema<'a>(
    api: &'a OpenAPI,
    schema: &'a Schema,
    path: Vec<String>,
    access: ParameterAccess,
) -> Option<Vec<ParameterNormalization>> {
    match &schema.kind {
        SchemaKind::Type(openapiv3::Type::Object(o)) => {
            Some(normalize_object_type(api, o, path, access))
        }
        SchemaKind::Type(openapiv3::Type::Array(a)) => {
            let inner_schema = a.items.as_ref()?.resolve(api);
            match inner_schema.kind {
                SchemaKind::Type(openapiv3::Type::Object(ref o)) => {
                    Some(normalize_object_type(api, o, path, access))
                }
                // No support for nested arrays - semantic meaning not obvious
                _ => None,
            }
        }
        SchemaKind::Type(_) => {
            // Other types do not have a name, return an empty vec so their key in the
            // enclosing object/array is still included.
            Some(vec![])
        }
        openapiv3::SchemaKind::AllOf { all_of } if all_of.len() == 1 => {
            // If only a single property is in this AllOf, return an example from it.
            normalize_schema(api, all_of[0].resolve(api), path, access)
        }
        openapiv3::SchemaKind::Any(_) => {
            log::warn!(
                "Normalizing example parameters for this schema is not supported, it's too flexible."
            );
            None
        }
        SchemaKind::AnyOf { any_of } if any_of.len() == 1 => {
            normalize_schema(api, any_of[0].resolve(api), path, access)
        }
        openapiv3::SchemaKind::Not { not: _ } => {
            log::warn!(concat!(
                "Normalizing example parameters for negated schemas is not supported, it is unclear what to generate. ",
                "See https://swagger.io/docs/specification/v3_0/data-models/oneof-anyof-allof-not/#not"
            ));
            None
        }
        _ => None,
    }
}

/// MediaType is the internal type used for objects, both input (POST) and
/// output (GET). This function normalizes the field names.
fn normalize_media_type<'a>(
    api: &'a OpenAPI,
    media_type: &'a MediaType,
    path: Vec<String>,
    req_or_resp: ReqResp,
) -> Option<Vec<ParameterNormalization>> {
    let schema = media_type.schema.as_ref()?.resolve(api);
    let access = match req_or_resp {
        ReqResp::Req => ParameterAccess::request_body(ParameterAccessElements::new()),
        ReqResp::Resp => ParameterAccess::response_body(ParameterAccessElements::new()),
    };
    normalize_schema(api, schema, path, access)
}

/// Returns ParameterNormalizations for all fields in the object.
fn normalize_object_type<'a>(
    api: &'a OpenAPI,
    object_type: &'a ObjectType,
    path: Vec<String>,
    parameter_access: ParameterAccess,
) -> Vec<ParameterNormalization> {
    object_type
        .properties
        .keys()
        .flat_map(|key| {
            let new_parameter_access =
                parameter_access.with_new_element(ParameterAccessElement::Name(key.clone()));
            let mut normalized_params = vec![ParameterNormalization::body(
                new_parameter_access.clone(),
                path.clone(),
            )];
            let nested_schema = object_type.properties[key].resolve(api);
            let nested_params =
                normalize_schema(api, nested_schema, path.clone(), new_parameter_access)
                    .unwrap_or_default();
            normalized_params.extend(nested_params);
            normalized_params
        })
        .collect()
}

fn stem(name: &str) -> String {
    porter_stemmer::stem(name).to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_normalization_new() {
        let context = None;
        let parameter_access =
            ParameterAccess::request_query("for_now_unused_parameter_access".into());
        // No context
        assert_eq!(
            ParameterNormalization {
                name: "widget".into(),
                normalized: "widget".into(),
                context: context.clone(),
                parameter_access: parameter_access.clone()
            },
            ParameterNormalization::new("widget".into(), context.clone(), parameter_access.clone())
        );
        // No context + stemming
        assert_eq!(
            ParameterNormalization {
                name: "widgets".into(),
                normalized: "widget".into(),
                context: context.clone(),
                parameter_access: parameter_access.clone()
            },
            ParameterNormalization::new(
                "widgets".into(),
                context.clone(),
                parameter_access.clone()
            )
        );
        // Context
        let context = Some("aircraft".into());
        assert_eq!(
            ParameterNormalization {
                name: "widget".into(),
                normalized: "aircraft|widget".into(),
                context: context.clone(),
                parameter_access: parameter_access.clone()
            },
            ParameterNormalization::new("widget".into(), context, parameter_access.clone())
        );
        // Context stemming
        let context = Some("aircrafts".into());
        assert_eq!(
            ParameterNormalization {
                name: "widget".into(),
                normalized: "aircraft|widget".into(),
                context: context.clone(),
                parameter_access: parameter_access.clone()
            },
            ParameterNormalization::new("widget".into(), context, parameter_access.clone())
        );
        // Context from before underscore
        let context = Some("countries".into());
        let full_name = "country_id";
        assert_eq!(
            "countri|id",
            ParameterNormalization::new(full_name.to_string(), context, parameter_access.clone())
                .normalized
        );
        let context = Some("pet".into());
        assert_eq!(
            ParameterNormalization {
                name: "id".into(),
                normalized: "pet|id".into(),
                context: context.clone(),
                parameter_access: parameter_access.clone()
            },
            ParameterNormalization::new("petid".into(), context.clone(), parameter_access.clone())
        );
        assert_eq!(
            ParameterNormalization {
                name: "id".into(),
                normalized: "pet|id".into(),
                context: context.clone(),
                parameter_access: parameter_access.clone()
            },
            ParameterNormalization::new("PetID".into(), context, parameter_access.clone())
        );
    }
}
