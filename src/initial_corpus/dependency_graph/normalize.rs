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
) -> Option<Vec<ParameterNormalization>> {
    normalize_media_type(api, path, response.content.get_json_content()?)
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
) -> Option<Vec<ParameterNormalization>> {
    normalize_media_type(api, path, body.content.get_json_content()?)
}

/// MediaType is the internal type used for objects, both input (POST) and
/// output (GET). This function normalizes the field names.
fn normalize_media_type<'a>(
    api: &'a OpenAPI,
    path: &str,
    media_type: &'a MediaType,
) -> Option<Vec<ParameterNormalization>> {
    let schema = media_type.schema.as_ref()?.resolve(api);
    normalize_schema(api, path, schema)
}

fn normalize_schema<'a>(
    api: &'a OpenAPI,
    path: &str,
    schema: &'a Schema,
) -> Option<Vec<ParameterNormalization>> {
    match schema.kind {
        SchemaKind::Type(openapiv3::Type::Object(ref o)) => {
            Some(normalize_object_type(api, path, o))
        }
        SchemaKind::Type(openapiv3::Type::Array(ref a)) => {
            let inner_schema = a.items.as_ref()?.resolve(api);
            match inner_schema.kind {
                SchemaKind::Type(openapiv3::Type::Object(ref o)) => {
                    Some(normalize_object_type(api, path, o))
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
        _ => None,
    }
}

fn normalize_object_type<'a>(
    api: &'a OpenAPI,
    path: &str,
    object_type: &'a ObjectType,
) -> Vec<ParameterNormalization> {
    object_type
        .properties
        .keys()
        .flat_map(|key| {
            let mut normalized_params = vec![ParameterNormalization::new(
                key.to_owned().into(),
                path_context_component(path),
            )];
            let nested_schema = object_type.properties[key].resolve(api);
            match nested_schema.kind {
                SchemaKind::Type(openapiv3::Type::Object(ref _o )) => {
                    for (subkey, subschema) in nested_schema.properties() {
                        let subschema_resolved = subschema.resolve(api);
                        let normalized_subs = normalize_schema(api, path, subschema_resolved).unwrap_or_default();
                        normalized_params.push(ParameterNormalization::new(ParameterAccess::new(vec![key.to_owned().into(), subkey.to_owned().into()]), path_context_component(path)));
                        normalized_params.extend(
                            normalized_subs.into_iter().map(
                                |item| ParameterNormalization::new(
                                    ParameterAccess::new([key, subkey, &item.normalized].iter().map(|s| s.to_string().into()).collect()),
                                    path_context_component(path))
                            )
                        )
                    }
                }
                _ => {
                    log::debug!("Ignoring schema {nested_schema:#?} during normalize_object_type, only SchemaKind::Type with Object inside is considered.");
                },
            }
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
