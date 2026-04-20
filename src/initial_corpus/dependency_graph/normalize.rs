//! Parameter name normalization for dependency-graph edge construction.
//!
//! # Purpose
//!
//! To detect that two operations share a parameter — and therefore that one
//! should precede the other — we need a canonical form for parameter names
//! that abstracts over superficial naming differences.  This module derives
//! that canonical form, called the **normalized name**, for each parameter in
//! a request or response.
//!
//! # Normalized name format
//!
//! A normalized name is either just a stemmed word (e.g. `"widget"` from
//! `"widgets"`) or a `context|name` pair (e.g. `"artist|id"`) when a context
//! can be inferred.  Context provides the "namespace" that disambiguates bare
//! `"id"` fields: an `id` returned by `GET /artists` and an `id` returned by
//! `GET /albums` are different things, even though both fields are named `id`.
//!
//! Both the context and the name are **stemmed** with a Porter stemmer so that
//! plurals, British/American spellings, and common suffixes do not prevent
//! matching.
//!
//! # How context is determined
//!
//! The context rules differ by where the parameter lives:
//!
//! | Parameter kind | Name source | Context source |
//! |---|---|---|
//! | Path (`/artists/{id}`) | `id` | last non-templated path segment (`artists`) |
//! | Query / Header / Cookie | parameter name | last URL path segment |
//! | Body (JSON object field) — depth 1 | field name | last URL path segment |
//! | Body (JSON object field) — depth ≥ 2 | leaf field name | parent field name |
//!
//! # Context deduplication
//!
//! When the parameter name already encodes the context (e.g. `artist_id` under
//! the `/artists/` path, or `artistId`), the context prefix is stripped before
//! forming the normalized name.  See [`deduplicate_context_from_name`] for the
//! exact rules.
//!
//! # Entry points
//!
//! - [`normalize_parameters`] — normalizes all URL parameters for a request.
//! - [`normalize_request_body`] — normalizes all fields in a POST/PUT body.
//! - [`normalize_response`] — normalizes all fields in a response body.
//!
//! All three functions return a [`Vec<ParameterNormalization>`]; each entry
//! holds both the raw name (for display) and the normalized name (for
//! matching), together with a [`ParameterAccess`] that identifies the field's
//! exact location so a back-reference can be inserted later.

use std::collections::BTreeMap;

use oas3::spec::{
    MediaType, ObjectOrReference, ObjectSchema, Operation, Parameter, RequestBody, Response,
};

use crate::{
    openapi::spec::Spec,
    parameter_access::{ParameterAccess, ParameterAccessElement, ParameterAccessElements},
};

/// Marker for whether a parameter belongs to a request or a response.
///
/// Used to determine the correct [`ParameterAccess`] variant when
/// constructing normalizations from a body schema.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ReqResp {
    Req,
    Resp,
}

/// Strips a context prefix already embedded in `name`, if one is present.
///
/// When the parameter name duplicates its context (e.g. the field `artist_id`
/// under the `/artists/` path, where the context is already `artist`), we
/// reduce the name to just the meaningful suffix (`id`) before forming the
/// normalized name.  This ensures `artist_id` and the path parameter `id`
/// from `/artists/{id}` both normalize to `artist|id`.
///
/// # Strategy
///
/// Separator characters (`_` and `-`) are scanned **left-to-right**; the first
/// one whose left-hand prefix stem-matches the context is used as the split
/// point, and the remainder is returned.  For example:
///
/// - `"cat_names"` with context `"cat"` → `"names"` (first prefix matches)
/// - `"cat_name_id"` with context `"cat"` → `"name_id"` (first prefix matches; full remainder kept)
/// - `"user_cat_id"` with context `"user_cat"` → `"id"` (first prefix `"user"` doesn't match;
///   second prefix `"user_cat"` does)
///
/// If no separator-based match is found, the function also checks whether
/// `name` ends in the literal strings `"id"`, `"Id"`, or `"ID"` and whether
/// stripping those two characters leaves a stem that matches the context.
/// This handles the camelCase pattern `"PetID"` → `"id"` (context `"pet"`).
fn deduplicate_context_from_name(name: &str, context: Option<&str>) -> String {
    // If the name ends in a magic string, consider that the name, and the part before it the context.
    if let Some(context_str) = context {
        let last = name.len() - 1;
        // Search all separator positions left-to-right and use the first prefix that
        // stem-matches the context. This correctly handles:
        //   "cat_names"    context "cat"      → "names"    (first prefix matches)
        //   "cat_name_id"  context "cat"      → "name_id"  (first prefix matches, full remainder kept)
        //   "user_cat_id"  context "user_cat" → "id"       (first prefix "user" doesn't match,
        //                                                    second prefix "user_cat" does)
        // Using rfind or plain find alone cannot handle all three cases correctly.
        let separator_stripped = name
            .match_indices(['-', '_'])
            .find(|&(i, _)| i != 0 && i != last && stem(context_str) == stem(&name[..i]))
            .map(|(i, _)| &name[i + 1..]);
        let no_context_name = if let Some(stripped) = separator_stripped {
            stripped
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
        // Query, Header and Cookie parameters all use the last URL path segment
        // as context.  E.g. the query parameter `limit` on `GET /artists/` gets
        // context `"artists"`, normalizing to `"artist|limit"`.
        let access_name = access.get_non_body_access_element().unwrap();
        let context = path
            .last()
            .map(|last_path_element| last_path_element.to_string());
        Self::new(access_name, context, access)
    }

    fn path(access: ParameterAccess, path: Vec<&str>) -> Result<Self, String> {
        // For path parameters like `/shop/pet/{name}`, the context is the last
        // non-templated segment immediately before the `{…}` placeholder, i.e.
        // `"pet"` in this example.  This means `{name}` normalizes to `"pet|name"`
        // and can match a `pet_name` response field.
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
        // For body (JSON) parameters the context depends on nesting depth:
        //   - depth 0 (the body root itself): no name; use path as fallback.
        //   - depth 1 (top-level field): use the last URL path segment as context
        //     so `{"id": …}` in a POST to `/pets/` gets context `"pets"`.
        //   - depth ≥ 2 (nested field): use the immediate parent field name as
        //     context so `owner.id` normalizes to `"owner|id"`.
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
                _ => (
                    named_access_elements[0].clone(),
                    Some(path[path.len() - 1].clone()),
                ),
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

/// Normalizes all URL (query, path, header, cookie) parameters for an operation.
///
/// Iterates over the parameter list in the OpenAPI spec, resolves any `$ref`
/// pointers, and returns one [`ParameterNormalization`] per successfully
/// resolved parameter.  Parameters that fail to resolve or cannot be
/// normalized are logged and skipped.
pub fn normalize_parameters<'a>(
    api: &'a Spec,
    path: &str,
    operation: &'a Operation,
) -> Vec<ParameterNormalization> {
    operation
        .parameters
        .iter()
        // Keep only concrete values and valid references
        .filter_map(|ref_or_param| ref_or_param.resolve(api).ok())
        .filter_map(|param| {
            let normalization_attempt = normalize_parameter(path, &param);
            if normalization_attempt.is_err() {
                log::error!("Cannot normalize parameter {param:?}: {normalization_attempt:?}")
            }
            normalization_attempt.ok()
        })
        .collect()
}

/// Normalizes a single request parameter (non-body).
///
/// Routes to [`ParameterNormalization::query_header_cookie`] or
/// [`ParameterNormalization::path`] depending on the parameter location.  Path
/// parameters must appear as a `{name}` template in the path string; an error
/// is returned if they do not.
fn normalize_parameter(
    path: &str,
    parameter: &Parameter,
) -> Result<ParameterNormalization, String> {
    let path_parts: Vec<_> = path.split('/').collect();

    match &parameter.location {
        oas3::spec::ParameterIn::Query => Ok(ParameterNormalization::query_header_cookie(
            ParameterAccess::request_query(parameter.name.clone()),
            path_parts,
        )),
        oas3::spec::ParameterIn::Header => Ok(ParameterNormalization::query_header_cookie(
            ParameterAccess::request_header(parameter.name.clone()),
            path_parts,
        )),
        oas3::spec::ParameterIn::Cookie => Ok(ParameterNormalization::query_header_cookie(
            ParameterAccess::request_cookie(parameter.name.clone()),
            path_parts,
        )),
        oas3::spec::ParameterIn::Path => ParameterNormalization::path(
            ParameterAccess::request_path(parameter.name.clone()),
            path_parts,
        ),
    }
}

/// Normalizes the JSON fields of an HTTP response body.
///
/// Extracts the `application/json` [`MediaType`] from the response (if
/// present), resolves its schema, and returns normalized names for all fields
/// using [`normalize_schema`].  Returns `None` if the response has no JSON
/// content or the schema cannot be resolved.
///
/// `path` should be the URL path split by `/`, used to supply context for
/// top-level fields named `"id"`.
pub fn normalize_response<'a>(
    api: &'a Spec,
    response: &'a Response,
    path: Vec<String>,
) -> Option<Vec<ParameterNormalization>> {
    normalize_media_type(
        api,
        response.content.get("application/json")?,
        path,
        ReqResp::Resp,
        0,
    )
}

/// Normalizes the JSON fields of an HTTP request body.
///
/// Mirrors [`normalize_response`] for request bodies: extracts
/// `application/json` content, resolves the schema, and returns normalized
/// names for all fields.  Returns `None` if no JSON body is present.
///
/// `path` is used as context for top-level body fields; for a `POST /pets`
/// endpoint, a top-level field `id` gets context `"pets"` and normalizes to
/// `"pet|id"`.
pub fn normalize_request_body<'a>(
    api: &'a Spec,
    body: &'a RequestBody,
    path: Vec<String>,
) -> Option<Vec<ParameterNormalization>> {
    normalize_media_type(
        api,
        body.content.get("application/json")?,
        path,
        ReqResp::Req,
        0,
    )
}

fn normalization_recursion_limit_exceeded(recursion_depth: usize) -> bool {
    if recursion_depth >= 20 {
        log::warn!(
            "Schema resolution exceeds {recursion_depth} steps, this parameter will not be handled properly. Try to avoid circular/deep schema references."
        );
        true
    } else {
        false
    }
}

/// Normalizes all fields in a JSON schema, recursively.
///
/// Returns one [`ParameterNormalization`] per named field reachable from the
/// schema root, or `None` if the schema type is not an object or array-of-objects
/// (e.g. a bare string or integer has no meaningful field name).
///
/// Handles the following schema structures:
/// - `allOf` with one entry: delegates directly to that sub-schema.
/// - `allOf` with multiple entries (OpenAPI inheritance): collects and merges
///   normalizations from **all** sub-schemas.
/// - `oneOf` with one entry: delegates directly.
/// - `type: object`: normalizes each property via [`normalize_object_type`].
/// - `type: array` with an object item type: normalizes the item's properties.
/// - Any other scalar type: returns an empty `Vec` (the key in the enclosing
///   object is still registered by the parent call).
///
/// `access` tracks the [`ParameterAccess`] path from the schema root to the
/// current node; `recursion_depth` guards against circular schema references.
fn normalize_schema(
    api: &Spec,
    schema: ObjectSchema,
    path: Vec<String>,
    access: ParameterAccess,
    recursion_depth: usize,
) -> Option<Vec<ParameterNormalization>> {
    // SchemaKind::AllOf { all_of } if all_of.len() == 1 => {
    //     // If only a single property is in this AllOf, return an example from it.
    //     normalize_schema(api, all_of[0].resolve(api).ok(), path, access)
    // }
    // SchemaKind::Any(_) => {
    //     // Normalizing example parameters for the "Any" schema is not supported, it's too flexible.
    //     None
    // }
    // SchemaKind::AnyOf { any_of } if any_of.len() == 1 => {
    //     normalize_schema(api, any_of[0].resolve(api), path, access)
    // }
    // SchemaKind::Not { not: _ } => {
    //     // Normalizing example parameters for negated schemas is not supported, it is unclear what to generate.
    //     // See https://swagger.io/docs/specification/v3_0/data-models/oneof-anyof-allof-not/#not
    //     None
    // }
    if normalization_recursion_limit_exceeded(recursion_depth) {
        return None;
    }
    let result;
    if schema.all_of.len() == 1 {
        // Normalize the single schema in this all_of.
        result = normalize_schema(
            api,
            schema.all_of[0]
                .resolve(api)
                .expect("Could not resolve schema reference."),
            path,
            access,
            recursion_depth + 1,
        )
    } else if schema.all_of.len() > 1 {
        // Collect normalizations from all sub-schemas and merge them.
        // This is the common OpenAPI inheritance pattern:
        //   allOf: [BaseObject, {properties: {id: integer}}]
        // Previously this fell through to schema_type matching, which returns None when
        // the wrapping allOf schema has no explicit type, making all its fields invisible
        // to the dependency graph.
        let merged: Vec<ParameterNormalization> = schema
            .all_of
            .iter()
            .filter_map(|sub| sub.resolve(api).ok())
            .flat_map(|sub_schema| {
                normalize_schema(
                    api,
                    sub_schema,
                    path.clone(),
                    access.clone(),
                    recursion_depth + 1,
                )
                .unwrap_or_default()
            })
            .collect();
        result = if merged.is_empty() {
            None
        } else {
            Some(merged)
        }
    } else if schema.one_of.len() == 1 {
        // Normalize the single schema in this one_of.
        result = normalize_schema(
            api,
            schema.one_of[0]
                .resolve(api)
                .expect("Could not resolve schema reference."),
            path,
            access,
            recursion_depth + 1,
        )
    } else {
        result = match &schema.schema_type {
            Some(type_set) => match type_set {
                oas3::spec::SchemaTypeSet::Single(schema_type) => match schema_type {
                    oas3::spec::SchemaType::Array => {
                        // let inner_schema = a.items.as_ref()?.resolve(api);
                        let inner_schema = schema.items;
                        // SchemaKind::Type(openapiv3::Type::Object(ref o)) => {
                        //     Some(normalize_object_type(api, o, path, access))
                        // }
                        // No support for nested arrays - semantic meaning not obvious
                        // _ => None,
                        match inner_schema {
                            Some(inner_schema) => match *inner_schema {
                                oas3::spec::Schema::Boolean(_boolean_schema) => todo!(
                                    "Boolean type items for interaction with prefixItems are not yet implemented."
                                ),
                                oas3::spec::Schema::Object(object_or_reference) => {
                                    let object_schema = object_or_reference
                                        .resolve(api)
                                        .expect("Could not resolve schema reference.");
                                    Some(normalize_object_type(
                                        api,
                                        &object_schema.properties,
                                        path,
                                        access,
                                        recursion_depth + 1,
                                    ))
                                }
                            },
                            None => None,
                        }
                    }
                    oas3::spec::SchemaType::Object => Some(normalize_object_type(
                        api,
                        &schema.properties,
                        path,
                        access,
                        recursion_depth + 1,
                    )),
                    // Other types do not have a name, return an empty vec so their key in the
                    // enclosing object/array is still included.
                    _ => Some(vec![]),
                    // oas3::spec::SchemaType::Boolean => todo!(),
                    // oas3::spec::SchemaType::Integer => todo!(),
                    // oas3::spec::SchemaType::Number => todo!(),
                    // oas3::spec::SchemaType::String => todo!(),
                    // oas3::spec::SchemaType::Null => todo!(),
                },
                oas3::spec::SchemaTypeSet::Multiple(_schema_types) => {
                    todo!("Sets of multiple schemas are not yet supported.")
                }
            },
            None => None,
        };
    }
    result
}

/// Entry point that resolves a [`MediaType`] schema and normalizes its fields.
///
/// `req_or_resp` determines whether the resulting [`ParameterAccess`] values
/// use the `Request` or `Response` variant of the enum, which affects how
/// back-references are later inserted.
fn normalize_media_type<'a>(
    api: &'a Spec,
    media_type: &'a MediaType,
    path: Vec<String>,
    req_or_resp: ReqResp,
    recursion_depth: usize,
) -> Option<Vec<ParameterNormalization>> {
    if normalization_recursion_limit_exceeded(recursion_depth) {
        return None;
    }
    let schema = media_type.schema.as_ref()?.resolve(api).ok()?;
    let access = match req_or_resp {
        ReqResp::Req => ParameterAccess::request_body(ParameterAccessElements::new()),
        ReqResp::Resp => ParameterAccess::response_body(ParameterAccessElements::new()),
    };
    normalize_schema(api, schema, path, access, recursion_depth + 1)
}

/// Normalizes every property of a JSON object schema.
///
/// For each key in `object_properties`, constructs a [`ParameterNormalization`]
/// for the key itself (via [`ParameterNormalization::body`]) and then recurses
/// into the property's schema to pick up any nested fields.  The recursion
/// handles nested objects and arrays.
///
/// Two depth guards prevent runaway recursion:
/// - `recursion_depth` is incremented on every recursive call and checked
///   against the limit in [`normalization_recursion_limit_exceeded`].
/// - The length of `parameter_access` (the body access path) is capped at 20
///   elements to handle circular `$ref` chains that the recursion counter alone
///   cannot catch.
fn normalize_object_type<'a>(
    api: &'a Spec,
    object_properties: &'a BTreeMap<String, ObjectOrReference<ObjectSchema>>,
    path: Vec<String>,
    parameter_access: ParameterAccess,
    recursion_depth: usize,
) -> Vec<ParameterNormalization> {
    if normalization_recursion_limit_exceeded(recursion_depth) {
        return vec![];
    }
    // Avoid infinite recursion (by circular (including self-)references in schemas)
    if parameter_access
        .get_body_access_elements()
        .is_ok_and(|elements| elements.0.len() >= 20)
    {
        log::warn!("Schema depth exceeds 20, ignoring further nesting.");
        return vec![];
    }
    object_properties
        .keys()
        .flat_map(|key| {
            let new_parameter_access =
                parameter_access.with_new_element(ParameterAccessElement::Name(key.clone()));
            let mut normalized_params = vec![ParameterNormalization::body(
                new_parameter_access.clone(),
                path.clone(),
            )];
            let nested_schema = object_properties[key]
                .resolve(api)
                .unwrap_or_else(|_| panic!("Could not resolve nested schema {}", key));
            let nested_params = normalize_schema(
                api,
                nested_schema,
                path.clone(),
                new_parameter_access,
                recursion_depth + 1,
            )
            .unwrap_or_default();
            normalized_params.extend(nested_params);
            normalized_params
        })
        .collect()
}

/// Reduces an English word to its grammatical stem using the Porter algorithm.
///
/// Used to make matching insensitive to plurals and common suffixes:
/// `"artists"` and `"artist"` both stem to `"artist"`.
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

        // Multi-separator: first prefix matches context, full remainder is kept.
        // "cat_name_id" with context "cat" should strip "cat_" and keep "name_id",
        // not strip "cat_name_" leaving only "id" (rfind) or fail to strip at all.
        let context = Some("cat".into());
        assert_eq!(
            "cat|name_id",
            ParameterNormalization::new(
                "cat_name_id".into(),
                context.clone(),
                parameter_access.clone()
            )
            .normalized
        );

        // Multi-separator: first prefix does NOT match; a later one does.
        // "user_cat_id" with context "user_cat" should strip "user_cat_" → "id".
        let context = Some("user_cat".into());
        assert_eq!(
            "user_cat|id",
            ParameterNormalization::new("user_cat_id".into(), context, parameter_access.clone())
                .normalized
        );
    }
}
