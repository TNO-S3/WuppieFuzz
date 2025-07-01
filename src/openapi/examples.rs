//! The functions in this file are used to generate http requests which are sent to the
//! fuzzing target during normal fuzzing operation. These functions need an OpenAPI struct
//! to generate realistic requests for the given target.

use std::{borrow::Cow, collections::VecDeque, f64::consts::PI};

use indexmap::IndexMap;
use openapiv3::{
    OpenAPI, Operation, Parameter, ParameterData, RefOr, Schema, SchemaKind, StringFormat, Type,
};
use petgraph::{csr::DefaultIx, graph::DiGraph, prelude::NodeIndex, visit::EdgeRef};
use rand::{Rng, prelude::Distribution};
use regex::Regex;
use serde_json::Value;
use unicode_truncate::UnicodeTruncateStr;

use super::{JsonContent, QualifiedOperation, WwwForm};
use crate::{
    initial_corpus::dependency_graph::ParameterMatching,
    input::{Body, OpenApiInput, OpenApiRequest, ParameterContents, parameter::ParameterKind},
};

/// Takes a (path, method, operation) tuple and produces an OpenApiRequest
/// filled with example values from the API specification, and default values
/// for parameters with no explicit examples.
pub fn example_from_qualified_operation(
    api: &OpenAPI,
    operation: QualifiedOperation,
) -> OpenApiRequest {
    OpenApiRequest {
        method: operation.method,
        path: operation.path.to_owned(),
        body: Body::build(
            api,
            operation.operation,
            example_body_contents(api, operation.operation),
        ),
        parameters: example_parameters(api, operation.operation),
    }
}

/// Generates body parameter values for the given operation if the operation has a supported
/// body type, otherwise None. Examples can be based on various sources, such as being
/// provided directly in the OpenAPI-spec or as defaults based on their type.
fn example_body_contents(api: &OpenAPI, operation: &Operation) -> Option<ParameterContents> {
    let body = operation.request_body.as_ref()?.resolve(api).ok()?;

    // Get either application/json or form content, if neither is present this function will return an empty body.
    let media_type = None
        .or_else(|| body.content.get_json_content())
        .or_else(|| body.content.get_www_form_content())?;

    let schema = media_type.schema.as_ref()?.resolve(api);

    match &schema.kind {
        SchemaKind::Type(Type::Object(obj)) => {
            let body_map: IndexMap<String, ParameterContents> = obj
                .properties
                .iter()
                .filter_map(|(param, ref_or_schema)| {
                    Some((
                        param.clone(),
                        ParameterContents::from(example_from_schema(
                            api,
                            ref_or_schema.resolve(api),
                        )?),
                    ))
                })
                .collect();
            Some(body_map.into())
        }
        SchemaKind::Type(Type::Array(arr)) => match &arr.items {
            Some(items) => {
                let result = items.resolve(api);
                Some(ParameterContents::from(example_from_schema(api, result)?))
            }
            None => None,
        },
        // TODO: create other body types, or document why not
        SchemaKind::Type(unimplemented_type) => {
            log::warn!(
                "Cannot create an example body for schema type {unimplemented_type:?}. Using empty body."
            );
            None
        }
        ref unimplemented_kind => {
            log::warn!(
                "Cannot create an example body for schema kind {unimplemented_kind:?}. Using empty body."
            );
            None
        }
    }
}

/// Generates all interesting body contents
fn all_interesting_body_contents(
    api: &OpenAPI,
    operation: &Operation,
) -> Option<Vec<ParameterContents>> {
    let body = operation.request_body.as_ref()?.resolve(api).ok()?;

    // Get either application/json or form content, if neither is present this function will return an empty body.
    let media_type = None
        .or_else(|| body.content.get_json_content())
        .or_else(|| body.content.get_www_form_content())?;

    Some(
        interesting_params_from_media_type(api, media_type)
            .into_iter()
            .map(ParameterContents::from)
            .collect(),
    )
}

/// Create an example body from an operation. This function is meant for requests that do
/// not have a structured body object, but a simple value.
#[allow(unused)]
fn example_plain_body(operation: &Operation, api: &OpenAPI) -> Option<ParameterContents> {
    operation
        .request_body
        .as_ref()
        .and_then(|ref_or_body| ref_or_body.resolve(api).ok())
        .and_then(|body| body.content.get_json_content())
        .and_then(|media_type| example_from_media_type(api, media_type))
        .map(ParameterContents::from)
}

fn example_parameter_value(api: &OpenAPI, par_data: &ParameterData) -> Result<Value, String> {
    let example = par_data.example.clone();
    if example.is_some() {
        example.ok_or("".to_owned())
    } else {
        // The specification allows for a theoretically infinite tower of
        // media types, examples, schemas and references. We put in some effort
        // to extract any useful value that may exist.
        match &(par_data.format) {
            openapiv3::ParameterSchemaOrContent::Schema(ref_or_schema) => {
                example_from_schema(api, ref_or_schema.resolve(api))
                    .ok_or("Could not create example from schema".to_owned())
            }
            openapiv3::ParameterSchemaOrContent::Content(content) => content
                .get_json_content()
                .and_then(|media_type| example_from_media_type(api, media_type))
                .ok_or("Could not create example from content".to_owned()),
        }
    }
}

fn example_parameters(
    api: &OpenAPI,
    operation: &Operation,
) -> IndexMap<(String, ParameterKind), ParameterContents> {
    operation
        .parameters
        .iter()
        .filter_map(|ref_or_parameter| ref_or_parameter.resolve(api).ok())
        .map(|parameter| (parameter.into(), &parameter.data))
        .filter_map(|(par_kind, par_data)| {
            example_parameter_value(api, par_data)
                .map(|value| {
                    (
                        (par_data.name.clone(), par_kind),
                        ParameterContents::from(value),
                    )
                })
                .ok()
        })
        .collect()
}

/// Returns all combinations of interesting values for parameters
/// for this operation, as well as the examples that may be provided by the spec.
/// Parameters that should only get a single value may be specified in
/// `single_valued`, which we use to avoid generating multiple values that
/// would be replaced by references later.
fn all_interesting_parameters(
    operation: &Operation,
    api: &OpenAPI,
    single_valued: &[&Parameter],
) -> Vec<IndexMap<(String, ParameterKind), ParameterContents>> {
    // For each parameter in the operation, generate a list of plausible values
    let param_combinations: IndexMap<(String, ParameterKind), Vec<ParameterContents>> = operation
        .parameters
        .iter()
        .filter_map(|ref_or_parameter| ref_or_parameter.resolve(api).ok())
        .map(|parameter| {
            let par_kind: ParameterKind = parameter.into();
            let par_data = &parameter.data;
            let mut interesting_combinations: Vec<Value> = vec![];
            if single_valued.contains(&parameter) {
                if par_data.example.is_some() {
                    interesting_combinations.push(par_data.example.clone().unwrap());
                } else {
                    match example_parameter_value(api, par_data) {
                        Ok(value) => interesting_combinations.push(value),
                        Err(err) => {
                            log::warn!(
                                "Failed to create single value for parameter {}: {}",
                                par_data.name,
                                err
                            )
                        }
                    }
                }
            } else {
                // if this parameter is a reference target (it will get replaced with a reference)
                // only return a single possible value here to avoid duplication down the line.
                if let Some(example) = par_data.example.clone() {
                    interesting_combinations.push(example);
                };
                match &(par_data.format) {
                    openapiv3::ParameterSchemaOrContent::Schema(ref_or_schema) => {
                        interesting_combinations.extend(interesting_params_from_schema(
                            api,
                            ref_or_schema,
                            &[],
                        ));
                    }
                    openapiv3::ParameterSchemaOrContent::Content(content) => {
                        if let Some(media_type) = content.get("application/json") {
                            interesting_combinations
                                .extend(interesting_params_from_media_type(api, media_type));
                        }
                    }
                };
            }
            let possible_values = interesting_combinations
                .into_iter()
                .map(ParameterContents::from)
                .collect();
            ((par_data.name.clone(), par_kind), possible_values)
        })
        .collect();

    // Now, attempt to create *every possible combination* of these possible values.
    // This means if the possible values are x=1, 2; y=3, 4; you get [1,3] [1,4] [2,3]
    // and [2,4]. This is represented as a list of IndexMaps. Each IndexMap would map
    // a parameter to a value, e.g. {x->2, y->3}.
    // We'd like this to be sort-of bounded. Experimentally, that means a maximum of
    // 100 combinations. So each `param_values` must have a len such that the
    // product of all lengths is less than this 100.
    let max_param_values = 100f64.powf(1.0 / param_combinations.len() as f64).floor() as usize;
    let mut maps = vec![IndexMap::new()];
    for (key, param_values) in param_combinations.into_iter() {
        let mut new_maps = vec![];
        for map in maps {
            // To each map that we have so far, add each of the possible new key-value pairs.
            // E.g., we have {x->1} and {x->2}, and want to add the possible values of
            // y (3 and 4) which should give us 4 maps. So a lot of cloning takes place.
            for param_value in param_values.iter().take(max_param_values) {
                let mut new_map = map.clone();
                new_map.insert(key.clone(), param_value.clone());
                new_maps.push(new_map);
            }
        }
        maps = new_maps;
    }
    maps
}

fn example_from_media_type(api: &OpenAPI, contents: &openapiv3::MediaType) -> Option<Value> {
    contents.example.clone().or_else(|| {
        contents
            .schema
            .as_ref()
            .and_then(|ref_or_schema| example_from_schema(api, ref_or_schema.resolve(api)))
    })
}

fn interesting_params_from_media_type(
    api: &OpenAPI,
    contents: &openapiv3::MediaType,
) -> Vec<Value> {
    let mut result = vec![];
    if contents.example.is_some() {
        result.push(contents.example.clone().unwrap());
    }
    if let Some(more_examples) = contents
        .schema
        .as_ref()
        .map(|ref_or_schema| interesting_params_from_schema(api, ref_or_schema, &[]))
    {
        result.extend(more_examples);
    }
    result
}

// Attempts to build a value that matches the given schema using default values
fn example_from_schema(api: &OpenAPI, schema: &Schema) -> Option<Value> {
    if schema.data.read_only {
        return None;
    }
    if schema.data.default.is_some() {
        return schema.data.default.clone();
    }
    if schema.data.example.is_some() {
        return schema.data.example.clone();
    }
    match &schema.kind {
        openapiv3::SchemaKind::Type(t) => example_from_type(api, t),
        openapiv3::SchemaKind::OneOf { one_of }
        | openapiv3::SchemaKind::AnyOf { any_of: one_of } => one_of
            .iter()
            .filter_map(|ref_or_schema| example_from_schema(api, ref_or_schema.resolve(api)))
            .next(),
        _ => None,
    }
}

// Returns all interesting (default, example) values for the given schema.
// ignore_reference may specify a reference that is not followed, this is used
// when resolving discriminator variants, which may refer back to their parent object
// circularly.
fn interesting_params_from_schema(
    api: &OpenAPI,
    schema: &RefOr<Schema>,
    ignore_names: &[&str],
) -> Vec<Value> {
    // Add the current schema name to the list of names not to descend into again, to prevent cycles
    let mut ignore_reference = ignore_names.to_owned();
    if let RefOr::Reference { reference } = schema {
        ignore_reference.push(reference);
    }
    let schema = schema.resolve(api);

    if schema.data.read_only {
        // schema property may only be sent in responses, never in requests.
        return vec![];
    }
    let mut result = vec![];
    if schema.data.default.is_some() {
        result.push(schema.data.default.clone().unwrap());
    }
    if schema.data.example.is_some() {
        result.push(schema.data.example.clone().unwrap());
    }
    if schema.data.discriminator.is_some() {
        result.extend(all_discriminator_variants(api, schema, &ignore_reference));
    } else {
        match &schema.kind {
            openapiv3::SchemaKind::Type(t) => {
                result.extend(interesting_params_from_type(api, t));
            }
            openapiv3::SchemaKind::OneOf { one_of }
            | openapiv3::SchemaKind::AnyOf { any_of: one_of } => {
                // For each OneOf variant, generate the list of examples, and then merge
                // the lists of examples into one big list (flat_map) and add them to the
                // result-ing list of examples
                result.extend(one_of.iter().flat_map(|ref_or_schema| {
                    match ref_or_schema {
                        // If this is a reference, and it's the one we want to ignore, return empty vec
                        RefOr::Reference { reference }
                            if ignore_reference.contains(&reference.as_str()) =>
                        {
                            Vec::new()
                        }
                        _ => interesting_params_from_schema(api, ref_or_schema, &ignore_reference),
                    }
                }));
            }
            openapiv3::SchemaKind::AllOf { all_of } => {
                // For each AllOf variant, generate the list of examples. Then, to get the
                // full set of examples, merge them in every possible way!
                // all_examples will be a vec of vecs: for each variant in allOf, many examples.
                let all_examples: Vec<Vec<Value>> = all_of
                    .iter()
                    .filter_map(|ref_or_schema| {
                        match ref_or_schema {
                            // If this is a reference, and it's the one we want to ignore, return empty vec
                            RefOr::Reference { reference }
                                if ignore_reference.contains(&reference.as_str()) =>
                            {
                                None
                            }
                            _ => Some(interesting_params_from_schema(
                                api,
                                ref_or_schema,
                                &ignore_reference,
                            )),
                        }
                    })
                    .collect();
                let all_combinations: Vec<Value> = all_examples
                    .into_iter()
                    .reduce(carthesian_product_values)
                    .unwrap_or_default();
                result.extend(all_combinations)
            }
            _ => (),
        }
    }
    result
}

/// Moves all fields from `right` into `left`.
/// If either Value is not an Object, nothing happens.
/// Fields from the `right` object take precendence
fn merge_object_values(mut left: Value, mut right: Value) -> Value {
    if let (Value::Object(map_left), Value::Object(map_right)) = (&mut left, &mut right) {
        map_left.append(map_right)
    }
    left
}

/// Carthesian product of two vectors of Values.
/// Merges the Values using merge_object_values.
///
/// For example, &[v1, v2], &[w1, w2] result in a vec containing
/// - a value containing all fields in v1 and all fields in w1,
/// - a value containing all fields in v1 and all fields in w2,
/// - a value containing all fields in v2 and all fields in w1,
/// - a value containing all fields in v2 and all fields in w2.
///
/// Inspiration from https://stackoverflow.com/a/74805365
fn carthesian_product_values(xs: Vec<Value>, ys: Vec<Value>) -> Vec<Value> {
    xs.into_iter()
        .flat_map(|x| std::iter::repeat(x).zip(&ys))
        .map(|(left, right)| merge_object_values(left, right.clone()))
        .collect()
}

/// Generates all variants of a discrminator-based schema; i.e. one that has a
/// Discrminator in the schema_data.
/// Supports both OAPI3.0 style discrminators, which have `OneOf`/`AnyOf` as the
/// SchemaType and combine it with mappings to select the correct one (sometimes),
///
/// * https://swagger.io/docs/specification/data-models/inheritance-and-polymorphism/
///
/// and also OAPI3.1 style discriminators, which have `Type` and combine it with
/// mappings to select the correct one (always), but then may refer back to the
/// parent schema in a cirular way so each variant contains the common mandatory
/// discriminator parameter.
///
/// * https://swagger.io/specification/#discriminator-object
fn all_discriminator_variants(api: &OpenAPI, schema: &Schema, ignore_names: &[&str]) -> Vec<Value> {
    // There is a strong assumption from here on that we're dealing with an
    // object schema, with the fields collected from the variant specified by
    // the discriminator, and merged with the fields from the parent type.
    let discriminator = match &schema.data.discriminator {
        Some(discriminator) => discriminator,
        None => unreachable!(), // Should not be called if there is no discriminator
    };

    // Make a mapping "path to api schema" -> "variant name" for the variants
    let mut mapping: IndexMap<String, String> = IndexMap::new();
    // Collect variants and default names from OneOf/AnyOf
    if let openapiv3::SchemaKind::OneOf { one_of: variants }
    | openapiv3::SchemaKind::AnyOf { any_of: variants } = &schema.kind
    {
        // Only references are allowed by the spec, no inline schemas
        for variant in variants {
            if let RefOr::Reference { reference } = variant {
                // Select the Dog in '#/components/schemas/Dog'
                if let Some(name) = reference.split('/').next_back() {
                    mapping.insert(reference.clone(), name.to_string());
                }
            }
        }
    }
    // Overwrite variant names with specifically defined mapping keys
    for (name, path) in &discriminator.mapping {
        mapping.insert(path.clone(), name.clone());
    }

    // For each of the variants, make objects with the discriminant field
    // (discriminator.property_name) set to the name and other fields from
    // an example of this variant. Variants can have multiple examples.
    let mut all_examples = Vec::new();
    for (path, name) in mapping {
        let mut discriminant_field = serde_json::Map::new();
        // Discriminant field needs to contain property_name: variant name as Value
        discriminant_field.insert(
            discriminator.property_name.clone(),
            Value::String(name.clone()),
        );
        // Take the example values and add the property name field
        all_examples.extend(
            interesting_params_from_schema(
                api,
                &RefOr::Reference::<Schema> { reference: path },
                ignore_names,
            )
            .into_iter()
            // Values from the base object take precendence, as we want
            .map(|value| merge_object_values(value, Value::Object(discriminant_field.clone()))),
        );
    }

    all_examples
}

/// Gives a slice of example string references based on the StringFormat given.
/// The examples are correct values for their type, if perhaps surprising.
fn strings_from_format(str_format: &openapiv3::VariantOrUnknownOrEmpty<StringFormat>) -> &[&str] {
    match str_format {
        openapiv3::VariantOrUnknownOrEmpty::Item(StringFormat::Date) => {
            &["1981-09-05", "0000-01-01", "9999999-12-31"]
        }
        openapiv3::VariantOrUnknownOrEmpty::Item(StringFormat::DateTime) => &[
            "1981-09-05T10:00:00Z",    // Regular date
            "0000-01-01T00:00:00Z",    // Used to crash MySQL servers
            "9999999-12-31T20:00:00Z", // At the end of the universe
            "2016-12-31T23:59:60Z",    // Valid leap second
        ],
        openapiv3::VariantOrUnknownOrEmpty::Item(StringFormat::Byte) => &["V3VwcGllRnV6elROTyE=="],
        // Though the specification allows for other StringFormats, like email,
        // the openapi crate does not. Just in case, we default to an email-like
        // value.
        openapiv3::VariantOrUnknownOrEmpty::Unknown(s) if s == "email" => {
            &["leaf@example.com", "a+b@c.onion"]
        }
        openapiv3::VariantOrUnknownOrEmpty::Unknown(s) if s == "uuid" => &[
            "550e8400-e29b-41d4-a716-446655440000",
            "00000000-0000-0000-0000-000000000000",
        ],
        openapiv3::VariantOrUnknownOrEmpty::Unknown(s) if s == "ipv4" => {
            &["1.1.1.1", "0.0.0.0", "127.0.0.1"]
        }
        openapiv3::VariantOrUnknownOrEmpty::Unknown(s) if s == "hostname" => {
            &["example.com", "localhost", "router.local"]
        }
        _ => &["", "A", "🎵"],
    }
}

/// Enforces the given minimum and maximum length on the input, by padding it
/// with "A"s or truncating it.
fn enforce_length_bounds(
    string: &str,
    min_length: Option<usize>,
    max_length: Option<usize>,
) -> Cow<str> {
    let mut result = Cow::from(string);
    if let Some(min) = min_length {
        *result.to_mut() += &"A".repeat(min);
    }
    if let Some(max) = max_length {
        result.to_mut().unicode_truncate(max);
    }
    result
}

/// Generate parameters based on the type specified. The values returned
/// should adhere to any constraints from the spec, any deviations to
/// test robustness of the server should be introduced by fuzzing.
fn interesting_params_from_type(api: &OpenAPI, openapi_type: &Type) -> Vec<Value> {
    // For numeric types, take exclusive_minimum and -maximum bools into account.
    match openapi_type {
        Type::String(string) => interesting_params_from_string_type(string),
        Type::Number(number) => {
            let interesting = match (number.minimum, number.maximum, number.multiple_of) {
                (Some(min), Some(max), Some(base)) => {
                    let mut constrained = vec![];
                    let range = min..=max;
                    for val in [-base, 0., base] {
                        if range.contains(&val) {
                            constrained.push(val);
                        }
                    }
                    constrained
                }
                (Some(min), Some(max), None) => {
                    let mut constrained = vec![min, max];
                    let range = min..=max;
                    for val in [-1., 0., 1., PI] {
                        if range.contains(&val) {
                            constrained.push(val);
                        }
                    }
                    constrained
                }
                (Some(min), None, Some(base)) => {
                    let mut constrained = vec![];
                    for val in [-base, 0., base] {
                        if min <= val {
                            constrained.push(val);
                        }
                    }
                    constrained
                }
                (Some(min), None, None) => {
                    let mut constrained = vec![min];
                    for val in [-1., 0., 1., PI] {
                        if min <= val {
                            constrained.push(val);
                        }
                    }
                    constrained
                }
                (None, Some(max), Some(base)) => {
                    let mut constrained = vec![max];
                    for val in [-base, 0., base] {
                        if max >= val {
                            constrained.push(val);
                        }
                    }
                    constrained
                }
                (None, Some(max), None) => {
                    let mut constrained = vec![max];
                    for val in [-PI, -1., 0., 1.] {
                        if max >= val {
                            constrained.push(val);
                        }
                    }
                    constrained
                }
                (None, None, Some(base)) => {
                    vec![-base, 0., base]
                }
                (None, None, None) => vec![-1., 0., 1., PI],
            };
            // For simplicity we unwrap the Number; if this would panic, we will consider this a bug in the code above.
            interesting
                .iter()
                .map(|num| Value::Number(serde_json::Number::from_f64(*num).unwrap()))
                .collect()
        }
        Type::Integer(integer) => {
            let interesting = match (integer.minimum, integer.maximum, integer.multiple_of) {
                (Some(min), Some(max), Some(base)) => {
                    let mut constrained = vec![];
                    let range = min..=max;
                    for val in [-base, 0, base] {
                        if range.contains(&val) {
                            constrained.push(val);
                        }
                    }
                    constrained
                }
                (Some(min), Some(max), None) => {
                    let mut constrained = vec![min, max];
                    let range = min..=max;
                    for val in [min, -1, 0, 1, max] {
                        if range.contains(&val) {
                            constrained.push(val);
                        }
                    }
                    constrained
                }
                (Some(min), None, Some(base)) => {
                    let mut constrained = vec![];
                    for val in [-base, 0, base] {
                        if min <= val {
                            constrained.push(val);
                        }
                    }
                    constrained
                }
                (Some(min), None, None) => {
                    let mut constrained = vec![min];
                    for val in [min, -1, 0, 1] {
                        if min <= val {
                            constrained.push(val);
                        }
                    }
                    constrained
                }
                (None, Some(max), Some(base)) => {
                    let mut constrained = vec![max];
                    for val in [-base, 0, base] {
                        if max >= val {
                            constrained.push(val);
                        }
                    }
                    constrained
                }
                (None, Some(max), None) => {
                    let mut constrained = vec![max];
                    for val in [-1, 0, 1, max] {
                        if max >= val {
                            constrained.push(val);
                        }
                    }
                    constrained
                }
                (None, None, Some(base)) => {
                    vec![-base, 0, base]
                }
                (None, None, None) => {
                    vec![-1, 0, 1]
                }
            };
            // For simplicity we unwrap the Number; if this would panic, we will consider this a bug in the code above.
            interesting
                .iter()
                .map(|num| Value::Number(serde_json::Number::from(*num)))
                .collect()
        }
        Type::Object(object) => vec![Value::Object(
            object
                .properties
                .iter()
                .filter_map(|(k, v)| Some((k.clone(), example_from_schema(api, v.resolve(api))?)))
                .collect(),
        )],
        Type::Array(array) => {
            // The 'items' specification is required according to the spec, but
            // we still get an Option and a possibly broken reference and what not.
            // Extract any usable specification of an item, and make an example.
            let item =
                example_from_schema(api, array.items.as_ref().unwrap().resolve(api)).unwrap();
            // Repeat the example. If a maximum number of array elements is specified,
            // we use that many, otherwise the minimum number, otherwise 3.
            vec![Value::Array(vec![
                item;
                array
                    .max_items
                    .or(array.min_items)
                    .unwrap_or(3)
            ])]
        }
        Type::Boolean {} => vec![Value::Bool(true), Value::Bool(false)],
    }
}

fn example_from_type(api: &OpenAPI, t: &Type) -> Option<Value> {
    match t {
        Type::String(string) => interesting_params_from_string_type(string).pop(),
        Type::Number(number) => {
            let value = match (number.minimum, number.maximum, number.multiple_of) {
                (Some(min), Some(max), Some(base)) => ((min + max) / 2.0 / base).round() * base,
                (Some(min), Some(max), None) => (min + max) / 2.0,
                (Some(min), None, Some(base)) => (min / base).ceil() * base,
                (Some(min), None, None) => min,
                (None, Some(max), Some(base)) => (max / base).floor() * base,
                (None, Some(max), None) => max,
                (None, None, Some(base)) => 1.0 * base,
                (None, None, None) => 0.0,
            };
            Some(Value::Number(serde_json::Number::from_f64(value)?))
        }
        Type::Integer(integer) => {
            let value = match (integer.minimum, integer.maximum, integer.multiple_of) {
                (Some(min), Some(max), Some(base)) => ((min + max) / 2 / base) * base,
                (Some(min), Some(max), None) => (min + max) / 2,
                (Some(min), None, Some(base)) => ((min + base - 1) / base) * base,
                (Some(min), None, None) => min,
                (None, Some(max), Some(base)) => (max / base) * base,
                (None, Some(max), None) => max,
                (None, None, Some(base)) => base,
                (None, None, None) => 0,
            };
            Some(Value::Number(serde_json::Number::from(value)))
        }
        Type::Object(object) => Some(Value::Object(
            object
                .properties
                .iter()
                .filter_map(|(k, v)| Some((k.clone(), example_from_schema(api, v.resolve(api))?)))
                .collect(),
        )),
        Type::Array(array) => {
            // The 'items' specification is required according to the spec, but
            // we still get an Option and a possibly broken reference and what not.
            // Extract any usable specification of an item, and make an example.
            let item = example_from_schema(api, array.items.as_ref()?.resolve(api))?;
            // Repeat the example. If a maximum number of array elements is specified,
            // we use that many, otherwise the minimum number, otherwise 2.
            Some(Value::Array(vec![
                item;
                array
                    .max_items
                    .or(array.min_items)
                    .unwrap_or(2)
            ]))
        }
        Type::Boolean {} => Some(Value::Bool(true)),
    }
}

/// We return all variants if an enumeration is present, try the pattern regex if one is present,
/// or fall back to some defaults based on the StringFormat. Returns a serde_json::Value::String.
fn interesting_params_from_string_type(string: &openapiv3::StringType) -> Vec<serde_json::Value> {
    // Enumeration present? Return the first variant
    if !string.enumeration.is_empty() {
        return string
            .enumeration
            .iter()
            .cloned()
            .map(serde_json::Value::String)
            .collect();
    }

    // Regex (without anchors) present? Attempt to compile it, and generate a string that matches it
    if let Some(pattern) = &string.pattern {
        if let Ok(compiled_regex) = rand_regex::Regex::compile(pattern, 100) {
            return vec![serde_json::Value::String(
                compiled_regex.sample(&mut rand::rng()),
            )];
        }

        // The regex does have anchors, which the generator can not work with
        // Remove anchors from the pattern for the generator
        let pattern_without_anchors = pattern.replace("^", "").replace("$", "");

        match rand_regex::Regex::compile(&pattern_without_anchors, 100) {
            Ok(compiled_regex) => {
                // Define the filter regex with the original pattern including anchors
                let filter_regex = Regex::new(pattern).unwrap();

                // Generate 1000 sample strings from the regex pattern without anchors
                // and test if one matches the regex with the anchors
                if let Some(sample) = rand::rng()
                    .sample_iter::<String, _>(&compiled_regex)
                    .take(1000)
                    .find(|s| filter_regex.is_match(s))
                {
                    return vec![serde_json::Value::String(sample)];
                }
                log::warn!(
                    "Could not generate an example string that matches the regex {}",
                    pattern
                );
            }
            Err(err) => {
                log::warn!("Broken regex pattern {}, Error message: {}", pattern, err);
            }
        }
    }

    // Attempt to generate a string based on other format hints
    strings_from_format(&string.format)
        .iter()
        .map(|&example| {
            serde_json::Value::String(
                enforce_length_bounds(example, string.min_length, string.max_length).into_owned(),
            )
        })
        .collect()
}

/// Creates a set of OpenApiInputs for the given sequence of QualifiedOperations based on a number of interesting
/// values for each of the parameters found in the OpenApiInputs. Specifically, it returns the cartesian product
/// of all these parameter choices, i.e. for a single-request OpenApiInput with parameters A: bool and B: usize
/// it may for example return (true, 0), (true, 1), (false, 0) and (false, 1).
///
/// This allows the fuzzer to start with all the inputs that we might a priori consider promising, and then
/// continue with random mutations (picking seeds based on coverage feedback).
pub fn openapi_inputs_from_ops<'a>(
    api: &OpenAPI,
    ops_iter: impl Iterator<Item = QualifiedOperation<'a>>,
    subgraph: &DiGraph<QualifiedOperation, ParameterMatching, DefaultIx>,
    sorted_nodes: &[NodeIndex],
) -> Result<Vec<OpenApiInput>, String> {
    // First create all interesting requests per QualifiedOperation independently.
    // We will create request chains from their cartesian product in the next step.
    let mut concrete_requests: VecDeque<Vec<OpenApiRequest>> = ops_iter
        .enumerate()
        .map(|(request_idx, op)| {
            let single_valued: Vec<&Parameter> = subgraph
                .edge_references()
                .filter(|edge| edge.target() == sorted_nodes[request_idx])
                .flat_map(|edge| {
                    op.operation
                        .parameters
                        .iter()
                        .filter_map(|ref_or_parameter| ref_or_parameter.resolve(api).ok())
                        .filter(move |parameter| {
                            let par_kind: ParameterKind = (*parameter).into();
                            let par_data = &parameter.data;
                            edge.weight().name_input == par_data.name
                                && par_kind == edge.weight().kind_input
                        })
                })
                .collect();
            all_interesting_inputs_for_qualified_operation(api, op, &single_valued)
        })
        .collect();
    // deduplicate_same_reference_requests(&mut concrete_requests, &subgraph, &sorted_nodes);
    let total_combinations: usize = concrete_requests
        .iter()
        .fold(1, |acc, elem| acc * elem.len());
    if total_combinations > 10000 {
        return Err(format!(
            "Corpus generation would try to create {} inputs, fall back to simple examples.",
            total_combinations
        ));
    }
    if concrete_requests.is_empty() {
        log::warn!("Trying to create OpenApiInputs from QualifiedOperations gave empty result.");
        return Ok(vec![]);
    }
    // Now take the cartesian product
    // Initialize "chains" of only the first request, then combine all chains built so far
    // with each of the OpenApiRequests in the next request (iteratively).
    let mut all_chains: Vec<Vec<OpenApiRequest>> = concrete_requests
        .pop_front()
        .unwrap()
        .into_iter()
        .map(|instance_of_first_request| vec![instance_of_first_request])
        .collect();
    for all_nth_requests in concrete_requests.iter() {
        let mut new_all_chains: Vec<Vec<OpenApiRequest>> = vec![];
        for chain in all_chains.clone() {
            for next_request in all_nth_requests {
                let mut old_chain = chain.clone();
                old_chain.push(next_request.clone());
                new_all_chains.push(old_chain);
            }
        }
        if !new_all_chains.is_empty() {
            all_chains = new_all_chains;
        }
        let chain_len = all_chains[0].len();
        for chain in all_chains.iter() {
            assert_eq!(chain.len(), chain_len);
        }
    }
    Ok(all_chains.into_iter().map(OpenApiInput).collect())
}

/// Returns a NON-EMPTY vector of interesting requests that can be made for the given operation.
fn all_interesting_inputs_for_qualified_operation(
    api: &OpenAPI,
    operation: QualifiedOperation,
    single_valued: &[&Parameter],
) -> Vec<OpenApiRequest> {
    // There may be multiple parameters, create an OpenApiRequest for each combination
    // of interesting values for these parameters.
    let combinations = all_interesting_parameters(operation.operation, api, single_valued);
    if combinations.is_empty() {
        // There are no parameters, return the interesting bodies.
        match all_interesting_body_contents(api, operation.operation) {
            Some(bodies) => bodies
                .into_iter()
                .map(|body| OpenApiRequest {
                    method: operation.method,
                    path: operation.path.to_owned(),
                    body: Body::build(api, operation.operation, Some(body)),
                    parameters: IndexMap::default(),
                })
                .collect(),
            None => vec![OpenApiRequest {
                method: operation.method,
                path: operation.path.to_owned(),
                body: Body::build(api, operation.operation, None),
                parameters: IndexMap::default(),
            }],
        }
    } else {
        match all_interesting_body_contents(api, operation.operation) {
            Some(bodies) => bodies
                .into_iter()
                .flat_map(|body| std::iter::repeat(body).zip(&combinations))
                .map(|(body, param_combination)| OpenApiRequest {
                    method: operation.method,
                    path: operation.path.to_owned(),
                    body: Body::build(api, operation.operation, Some(body)),
                    parameters: param_combination.clone(),
                })
                .collect(),
            None => combinations
                .into_iter()
                .map(|combination| OpenApiRequest {
                    method: operation.method,
                    path: operation.path.to_owned(),
                    body: Body::build(api, operation.operation, None),
                    parameters: combination,
                })
                .collect(),
        }
    }
}
