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
use porter_stemmer::stem;

use crate::{
    input::parameter::{ParameterAccess, ParameterAccessElement, ParameterKind},
    openapi::JsonContent,
};

/// A parameter name saved in two variants: the canonical name appearing in the spec,
/// and the normalized form used for matching input and output parameters
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ParameterNormalization {
    pub name: String,
    pub normalized: String,
    pub path_context: Option<String>,
    pub nested_context: ParameterAccess,
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
    pub fn new(nested_access: ParameterAccess, path_context: Option<String>) -> Self {
        let normal_name = nested_access
            .elements
            .last()
            .unwrap_or(&ParameterAccessElement::Name("".to_owned()))
            .to_string();
        Self {
            name: normal_name.clone(),
            normalized: stem(&normal_name),
            path_context,
            nested_context: nested_access,
        }
    }
}

/// Finds all parameters used in an operation and returns their normalized name.
/// See `normalize_parameter` for treatment of parameters named 'id'.
pub fn normalize_parameters<'a>(
    api: &'a OpenAPI,
    path: &str,
    operation: &'a Operation,
) -> Vec<(ParameterNormalization, ParameterKind)> {
    operation
        .parameters
        .iter()
        // Keep only concrete values and valid references
        .filter_map(|ref_or_param| ref_or_param.resolve(api).ok())
        // Convert to (parameter_normalization, parameter_kind) tuples
        .map(|param| (normalize_parameter(path, param), param.into()))
        .collect()
}

/// Normalizes a parameter name.
///
/// A suitable context word is taken from the corresponding operation, and
/// its stem is prepended to the stemmed parameter name.
fn normalize_parameter(path: &str, parameter: &Parameter) -> ParameterNormalization {
    // extract a context word if possible
    match parameter.kind {
        // For a query parameter /resource?id=18, we want to extract
        // the 'resource' part as the context word, and return as the name
        // stem('resource') + "id"
        openapiv3::ParameterKind::Query { .. } => {
            return ParameterNormalization::new(
                parameter.data.name.clone().into(),
                path_context_component(path),
            );
        }
        // For a path parameter /resource/{id}/..., we want to extract
        // the 'resource' part as the context word, and return as the name
        // stem('resource') + "id".
        // Some APIs use urls like `/resource/name/{name}`, in which case we
        // should detect that the final path component is not useful and take the
        // one before.
        openapiv3::ParameterKind::Path { .. } => {
            if let Some(end) = path.find(&format!("/{{{}}}", parameter.data.name)) {
                return ParameterNormalization::new(
                    parameter.data.name.clone().into(),
                    path_context_component(&path[..end]),
                );
            }
        }
        _ => (),
    };

    // If we reach this point, either the spec didn't contain the data we
    // expect based on the OpenAPI specification, or it's a parameter kind
    // we can't find context for. Just return the "id" string.
    ParameterNormalization::new(parameter.data.name.clone().into(), None)
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
    path: &str,
    response: &'a Response,
    parent_context: ParameterAccess,
) -> Option<Vec<ParameterNormalization>> {
    normalize_media_type(
        api,
        path,
        response.content.get_json_content()?,
        parent_context,
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
    path: &str,
    body: &'a RequestBody,
    parent_context: ParameterAccess,
) -> Option<Vec<ParameterNormalization>> {
    normalize_media_type(api, path, body.content.get_json_content()?, parent_context)
}

/// MediaType is the internal type used for objects, both input (POST) and
/// output (GET). This function normalizes the field names.
fn normalize_media_type<'a>(
    api: &'a OpenAPI,
    path: &str,
    media_type: &'a MediaType,
    parent_context: ParameterAccess,
) -> Option<Vec<ParameterNormalization>> {
    let schema = media_type.schema.as_ref()?.resolve(api);
    normalize_schema(api, path, schema, parent_context)
}

fn normalize_schema<'a>(
    api: &'a OpenAPI,
    path: &str,
    schema: &'a Schema,
    parent_context: ParameterAccess,
) -> Option<Vec<ParameterNormalization>> {
    match &schema.kind {
        SchemaKind::Type(openapiv3::Type::Object(o)) => {
            Some(normalize_object_type(api, path, o, parent_context))
        }
        SchemaKind::Type(openapiv3::Type::Array(a)) => {
            let inner_schema = a.items.as_ref()?.resolve(api);
            match inner_schema.kind {
                SchemaKind::Type(openapiv3::Type::Object(ref o)) => {
                    Some(normalize_object_type(api, path, o, parent_context))
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
        openapiv3::SchemaKind::AllOf { all_of } => {
            // If only a single property is in this AllOf, return an example from it.
            if all_of.len() == 1 {
                normalize_schema(api, path, all_of[0].resolve(api), parent_context)
            } else {
                log::warn!(concat!(
                    "Normalizing example parameters for the allOf keyword with more than one schema is not supported. ",
                    "See https://swagger.io/docs/specification/v3_0/data-models/oneof-anyof-allof-not/#allof"
                ));
                None
            }
        }
        openapiv3::SchemaKind::Any(_) => {
            log::warn!(
                "Normalizing example parameters for this schema is not supported, it's too flexible."
            );
            None
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

fn normalize_object_type<'a>(
    api: &'a OpenAPI,
    path: &str,
    object_type: &'a ObjectType,
    parent_context: ParameterAccess,
) -> Vec<ParameterNormalization> {
    object_type
        .properties
        .keys()
        .flat_map(|key| {
            let mut normalized_params = vec![ParameterNormalization::new(
                parent_context
                    .clone()
                    .with_new_element(key.to_owned().into()),
                path_context_component(path),
            )];
            let nested_schema = object_type.properties[key].resolve(api);
            let nested_params = normalize_schema(
                api,
                path,
                nested_schema,
                parent_context
                    .clone()
                    .with_new_element(key.to_owned().into()),
            )
            .unwrap_or_default();
            // log::error!("Nested params:\n{:#?}", nested_params);
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
fn path_context_component(path: &str) -> Option<String> {
    path.rsplit('}')
        .flat_map(|series| series.split('/'))
        .map(|x| x.to_owned())
        .find(|component| !component.is_empty() && !component.starts_with('{'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_normalization_new() {
        assert_eq!(
            ParameterNormalization {
                name: "widget".into(),
                normalized: "widget".into(),
                ..Default::default()
            },
            ParameterNormalization::new("widget".into(), None)
        );
        assert_eq!(
            ParameterNormalization {
                name: "widgets".into(),
                normalized: "widget".into(),
                ..Default::default()
            },
            ParameterNormalization::new("widgets".into(), None)
        );
        assert_eq!(
            ParameterNormalization {
                name: "widget".into(),
                normalized: "aircraft|widget".into(),
                ..Default::default()
            },
            ParameterNormalization::new("widget".into(), Some("aircraft".to_owned()))
        );
        assert_eq!(
            ParameterNormalization {
                name: "widget".into(),
                normalized: "aircraft|widget".into(),
                ..Default::default()
            },
            ParameterNormalization::new("widget".into(), Some("aircrafts".to_owned()))
        );
        assert_eq!(
            ParameterNormalization {
                name: "country_id".into(),
                normalized: "countri|id".into(),
                ..Default::default()
            },
            ParameterNormalization::new("country_id".into(), Some("countries".to_owned()))
        );
        assert_eq!(
            ParameterNormalization {
                name: "id".into(),
                normalized: "countri|id".into(),
                ..Default::default()
            },
            ParameterNormalization::new("id".into(), Some("countries".to_owned()))
        );
        assert_eq!(
            ParameterNormalization {
                name: "widget_id".into(),
                normalized: "countri|widget_id".into(),
                ..Default::default()
            },
            ParameterNormalization::new("widget_id".into(), Some("countries".to_owned()))
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
