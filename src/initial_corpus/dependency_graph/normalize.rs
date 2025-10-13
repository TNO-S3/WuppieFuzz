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
    /// In general, the context is the URL-path and the name is the name of the parameter.
    /// For Body parameters, the name is a '/'-separated list of names and indices
    /// to identify a parameter (like in ParameterAccess).
    ///
    /// TODO: make clear decisions how about exact meaning of context and document this.
    pub fn new(name: String, context: Option<String>, parameter_access: ParameterAccess) -> Self {
        match context {
            Some(ref context) => {
                // Catch the case where the context word is also included in the name,
                // like `widget_id` for context `widgets`. Often, this same value is then
                // called `id` in other context, such as when part of a `Widget` object
                // in a body.
                let last = name.len() - 1;
                let no_context_name = if let Some(i) = name.find(['-', '_'])
                    && (i != 0 && i != last && stem(context) == stem(&name[..i]))
                {
                    &name[i + 1..]
                } else if ["id", "Id", "ID"].iter().any(|id| name.ends_with(id))
                    && stem(context) == stem(&name[..name.len() - 2])
                {
                    "id"
                } else {
                    &name
                };
                Self {
                    normalized: stem(context) + "|" + &stem(no_context_name),
                    name,
                    context: Some(context.to_string()),
                    parameter_access,
                }
            }
            None => Self {
                normalized: stem(&name),
                name,
                context,
                parameter_access,
            },
        }
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
        // Convert to (parameter_normalization, parameter_kind) tuples
        .map(|param| normalize_parameter(path, param))
        .collect()
}

/// Normalizes a parameter name.
///
/// A suitable context word is taken from the corresponding operation, and
/// its stem is prepended to the stemmed parameter name.
fn normalize_parameter(path: &str, parameter: &Parameter) -> ParameterNormalization {
    // extract a context word if possible
    let parameter_name = parameter.data.name.clone();
    let path_context = match parameter.kind {
        openapiv3::ParameterKind::Path { .. } => {
            if let Some(end) = path.find(&format!("/{{{}}}", parameter.data.name)) {
                path_context_component(&path[..end]).unwrap_or(path.to_string())
            } else {
                path.to_string()
            }
        }
        _ => path.to_string(),
    };

    let access = match &parameter.kind {
        openapiv3::ParameterKind::Query { .. } => {
            ParameterAccess::request_query(parameter_name.clone())
        }
        openapiv3::ParameterKind::Header { .. } => {
            ParameterAccess::request_header(parameter_name.clone())
        }
        openapiv3::ParameterKind::Path { .. } => {
            ParameterAccess::request_path(parameter_name.clone())
        }
        openapiv3::ParameterKind::Cookie { .. } => {
            ParameterAccess::request_cookie(parameter_name.clone())
        }
    };
    // TODO: make path_context just a String, not an Option?
    // Or should an empty context/root path be considered a None here?
    ParameterNormalization::new(parameter_name, Some(path_context), access)
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
    context: Option<String>,
) -> Option<Vec<ParameterNormalization>> {
    normalize_media_type(
        api,
        response.content.get_json_content()?,
        context.clone(),
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
    context: Option<String>,
) -> Option<Vec<ParameterNormalization>> {
    normalize_media_type(api, body.content.get_json_content()?, context, ReqResp::Req)
}

/// Schema describes contents of objects and arrays. This function normalizes field
/// names in a schema if it contains an object or an array of objects.
fn normalize_schema<'a>(
    api: &'a OpenAPI,
    schema: &'a Schema,
    context: Option<String>,
    access: ParameterAccess,
) -> Option<Vec<ParameterNormalization>> {
    match &schema.kind {
        SchemaKind::Type(openapiv3::Type::Object(o)) => {
            Some(normalize_object_type(api, o, context, access))
        }
        SchemaKind::Type(openapiv3::Type::Array(a)) => {
            let inner_schema = a.items.as_ref()?.resolve(api);
            match inner_schema.kind {
                SchemaKind::Type(openapiv3::Type::Object(ref o)) => {
                    Some(normalize_object_type(api, o, context, access))
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
            normalize_schema(api, all_of[0].resolve(api), context, access)
        }
        openapiv3::SchemaKind::Any(_) => {
            log::warn!(
                "Normalizing example parameters for this schema is not supported, it's too flexible."
            );
            None
        }
        SchemaKind::AnyOf { any_of } if any_of.len() == 1 => {
            normalize_schema(api, any_of[0].resolve(api), context, access)
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
    context: Option<String>,
    req_or_resp: ReqResp,
) -> Option<Vec<ParameterNormalization>> {
    let schema = media_type.schema.as_ref()?.resolve(api);
    let access = match req_or_resp {
        ReqResp::Req => ParameterAccess::request_body(ParameterAccessElements::new()),
        ReqResp::Resp => ParameterAccess::response_body(ParameterAccessElements::new()),
    };
    normalize_schema(api, schema, context, access)
}

/// Returns ParameterNormalizations for all fields in the object.
fn normalize_object_type<'a>(
    api: &'a OpenAPI,
    object_type: &'a ObjectType,
    context: Option<String>,
    parameter_access: ParameterAccess,
) -> Vec<ParameterNormalization> {
    object_type
        .properties
        .keys()
        .flat_map(|key| {
            let new_parameter_access =
                parameter_access.with_new_element(ParameterAccessElement::Name(key.clone()));
            let mut normalized_params = vec![ParameterNormalization::new(
                key.to_owned(),
                context.clone(),
                new_parameter_access.clone(),
            )];
            let nested_schema = object_type.properties[key].resolve(api);
            let nested_params = normalize_schema(
                api,
                nested_schema,
                Some(key.to_owned()),
                new_parameter_access.clone(),
            )
            .unwrap_or_default();
            normalized_params.extend(nested_params);
            normalized_params
        })
        .collect()
}

/// Find the context of a request from the path.
///
/// For a path like /albums/artist/{artist_id}, you get albums, so the answer is albums.
/// For a path like /albums/{album_id}/songs, you get songs, so the answer is songs.
/// This function chooses splits the path at {parameters}, and from the last section
/// chooses the first component.
pub(crate) fn path_context_component(path: &str) -> Option<String> {
    path.rsplit('}')
        .flat_map(|series| series.split('/'))
        .map(|x| x.to_owned())
        .find(|component| !component.is_empty() && !component.starts_with('{'))
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
        assert_eq!(
            ParameterNormalization {
                name: "widget".into(),
                normalized: "widget".into(),
                context: context.clone(),
                parameter_access: parameter_access.clone()
            },
            ParameterNormalization::new("widget".into(), context.clone(), parameter_access.clone())
        );
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
        let context = Some("countries".into());
        assert_eq!(
            ParameterNormalization {
                name: "country_id".into(),
                normalized: "countri|id".into(),
                context: context.clone(),
                parameter_access: parameter_access.clone()
            },
            ParameterNormalization::new(
                "country_id".into(),
                context.clone(),
                parameter_access.clone()
            )
        );
        assert_eq!(
            ParameterNormalization {
                name: "id".into(),
                normalized: "countri|id".into(),
                context: context.clone(),
                parameter_access: parameter_access.clone()
            },
            ParameterNormalization::new("id".into(), context.clone(), parameter_access.clone())
        );
        assert_eq!(
            ParameterNormalization {
                name: "widget_id".into(),
                normalized: "countri|widget_id".into(),
                context: context.clone(),
                parameter_access: parameter_access.clone()
            },
            ParameterNormalization::new("widget_id".into(), context, parameter_access.clone())
        );
        let context = Some("pets".into());
        assert_eq!(
            ParameterNormalization {
                name: "pet-id".into(),
                normalized: "pet|id".into(),
                context: context.clone(),
                parameter_access: parameter_access.clone()
            },
            ParameterNormalization::new("pet-id".into(), context.clone(), parameter_access.clone())
        );
        assert_eq!(
            ParameterNormalization {
                name: "petId".into(),
                normalized: "pet|id".into(),
                context: context.clone(),
                parameter_access: parameter_access.clone()
            },
            ParameterNormalization::new("petId".into(), context, parameter_access.clone())
        );
        let context = Some("pet".into());
        assert_eq!(
            ParameterNormalization {
                name: "petid".into(),
                normalized: "pet|id".into(),
                context: context.clone(),
                parameter_access: parameter_access.clone()
            },
            ParameterNormalization::new("petid".into(), context.clone(), parameter_access.clone())
        );
        assert_eq!(
            ParameterNormalization {
                name: "PetID".into(),
                normalized: "pet|id".into(),
                context: context.clone(),
                parameter_access: parameter_access.clone()
            },
            ParameterNormalization::new("PetID".into(), context, parameter_access.clone())
        );
    }

    #[test]
    fn test_path_last_component() {
        assert_eq!(Some("aaa".to_owned()), path_context_component("/aaa/bbb"));
        assert_eq!(Some("aaa".to_owned()), path_context_component("/aaa/bbb/"));
        assert_eq!(Some("bbb".to_owned()), path_context_component("/bbb"));
        assert_eq!(Some("bbb".to_owned()), path_context_component("/bbb/"));
        assert_eq!(
            Some("aaa".to_owned()),
            path_context_component("/aaa/bbb/{ccc}")
        );
        assert_eq!(
            Some("aaa".to_owned()),
            path_context_component("/aaa/bbb/{ccc}/")
        );
        assert_eq!(
            Some("ccc".to_owned()),
            path_context_component("/aaa/{bbb}/ccc")
        );
        assert_eq!(
            Some("ccc".to_owned()),
            path_context_component("/aaa/{bbb}/ccc/")
        );
        assert_eq!(
            Some("aaa".to_owned()),
            path_context_component("/aaa/bbb/{ccc}")
        );
        assert_eq!(
            Some("aaa".to_owned()),
            path_context_component("/aaa/bbb/{ccc}/")
        );
        assert_eq!(None, path_context_component(""));
        assert_eq!(None, path_context_component("/"));
        assert_eq!(None, path_context_component("/{aaa}"));
        assert_eq!(None, path_context_component("/{aaa}/"));
    }
}
