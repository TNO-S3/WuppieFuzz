//! The functions in this file are used to generate http requests which are sent to the
//! fuzzing target during normal fuzzing operation. These functions need an OpenAPI struct
//! to generate realistic requests for the given target.

use std::{
    borrow::Cow,
    collections::{BTreeMap, VecDeque},
    f64::consts::PI,
};

use oas3::spec::{MediaType, ObjectOrReference, ObjectSchema, Operation, Parameter, SchemaType};
use petgraph::{csr::DefaultIx, graph::DiGraph, prelude::NodeIndex, visit::EdgeRef};
use rand::{Rng, prelude::Distribution};
use regex::Regex;
use serde_json::{Number, Value, json};
use unicode_truncate::UnicodeTruncateStr;

use super::{JsonContent, QualifiedOperation, WwwForm};
use crate::{
    input::{Body, OpenApiInput, OpenApiRequest, ParameterContents, parameter::ParameterKind},
    openapi::spec::Spec,
    parameter_access::ParameterMatching,
};

/// Takes a (path, method, operation) tuple and produces an OpenApiRequest
/// filled with example values from the API specification, and default values
/// for parameters with no explicit examples.
pub fn example_from_qualified_operation(
    api: &Spec,
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
fn example_body_contents(api: &Spec, operation: &Operation) -> Option<ParameterContents> {
    let body = operation.request_body.as_ref()?.resolve(api).ok()?;

    // Get either application/json or form content, if neither is present return None.
    let media_type = None
        .or_else(|| body.content.get("application/json"))
        .or_else(|| body.content.get("application/x-www-form-urlcontent"))?;

    // Return None if the schema cannot be resolved
    let schema = media_type.schema.as_ref()?.resolve(api).ok()?;

    if schema
        .schema_type
        .as_ref()
        .is_some_and(|st| st.contains(SchemaType::Object))
    {
        let body_map: BTreeMap<String, ParameterContents> = schema
            .properties
            .iter()
            .filter_map(|(param, ref_or_schema)| {
                Some((
                    param.clone(),
                    ParameterContents::from(example_from_schema(
                        api,
                        &ref_or_schema.resolve(api).ok()?,
                        0,
                    )?),
                ))
            })
            .collect();
        return Some(body_map.into());
    }
    if schema
        .schema_type
        .is_some_and(|st| st.contains(SchemaType::Array))
    {
        return match &schema.items {
            Some(items) => match &**items {
                oas3::spec::Schema::Boolean(boolean_schema) => {
                    // Boolean schemas only serve to signal whether something will (true) or will not (false) validate against it.
                    // For the true variant any example will do, and we choose to return an empty object as an example.
                    // For the false variant no examples will validate, so we choose to not return any example.
                    match boolean_schema.0 {
                        true => Some(ParameterContents::Object(Default::default())),
                        false => None,
                    }
                }
                oas3::spec::Schema::Object(object_or_reference) => Some(ParameterContents::from(
                    example_from_schema(api, &object_or_reference.resolve(api).ok()?, 0)?,
                )),
            },
            None => None,
        };
    }
    // TODO this is a bit lackluster
    log::warn!("Cannot create an example body. Using empty body.");
    None
}

/// Generates all interesting body contents
fn all_interesting_body_contents(
    api: &Spec,
    operation: &Operation,
) -> Option<Vec<ParameterContents>> {
    let body = operation.request_body.as_ref()?.resolve(api).ok()?;

    // Get either application/json or form content, if neither is present this function will return an empty body.
    let media_type = None
        .or_else(|| body.content.get_json_content())
        .or_else(|| body.content.get_www_form_content())?;

    let values = interesting_params_from_media_type(api, media_type);
    if values.is_empty() {
        return None;
    }
    Some(values.into_iter().map(ParameterContents::from).collect())
}

/// Create an example body from an operation. This function is meant for requests that do
/// not have a structured body object, but a simple value.
#[allow(unused)]
fn example_plain_body(operation: &Operation, api: &Spec) -> Option<ParameterContents> {
    operation
        .request_body
        .as_ref()
        .and_then(|ref_or_body| ref_or_body.resolve(api).ok())
        .and_then(|body| body.content.get_json_content().cloned())
        .and_then(|media_type| example_from_media_type(api, &media_type, 0))
        .map(ParameterContents::from)
}

fn example_parameter_value(api: &Spec, param: &Parameter) -> Result<Value, String> {
    if let Some(example_value) = &param.example {
        Ok(example_value.clone())
    } else {
        // The specification allows for a theoretically infinite tower of
        // media types, examples, schemas and references. We put in some effort
        // to extract any useful value that may exist.
        if let Some(schema) = param.schema.as_ref() {
            example_from_schema(
                api,
                &schema.resolve(api).expect("Could not resolve schema"),
                0,
            )
            .ok_or("Could not create example from schema".to_owned())
        } else if let Some(content) = param.content.as_ref() {
            content
                .get_json_content()
                .and_then(|media_type| example_from_media_type(api, media_type, 0))
                .ok_or("Could not create example from content".to_owned())
        } else {
            Err(format!(
                "Parameter {} must contain either schema or content.",
                param.name
            ))
        }
    }
}

fn example_parameters(
    api: &Spec,
    operation: &Operation,
) -> BTreeMap<(String, ParameterKind), ParameterContents> {
    operation
        .parameters
        .iter()
        .filter_map(|ref_or_parameter| ref_or_parameter.resolve(api).ok())
        .filter_map(|parameter| {
            example_parameter_value(api, &parameter)
                .map(|value| {
                    (
                        (parameter.name.clone(), parameter.into()),
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
    api: &Spec,
    single_valued: &[Parameter],
) -> Vec<BTreeMap<(String, ParameterKind), ParameterContents>> {
    // For each parameter in the operation, generate a list of plausible values
    let param_combinations: BTreeMap<(String, ParameterKind), Vec<ParameterContents>> = operation
        .parameters
        .iter()
        .filter_map(|ref_or_parameter| ref_or_parameter.resolve(api).ok())
        .map(|mut parameter| {
            let par_kind: ParameterKind = parameter.clone().into();
            let mut interesting_combinations: Vec<Value> = vec![];
            if single_valued.contains(&parameter) {
                if let Some(example) = parameter.example {
                    interesting_combinations.push(example.clone());
                } else if let Some(example) = parameter.examples.first_entry()
                    && let Ok(exvalue) = example.get().resolve(api)
                    && let Some(value) = exvalue.value
                {
                    interesting_combinations.push(value)
                } else {
                    match example_parameter_value(api, &parameter) {
                        Ok(value) => interesting_combinations.push(value),
                        Err(err) => {
                            log::warn!(
                                "Failed to create single value for parameter {}: {}",
                                parameter.name,
                                err
                            )
                        }
                    }
                }
            } else {
                // if this parameter is a reference target (it will get replaced with a reference)
                // only return a single possible value here to avoid duplication down the line.
                if let Some(ref example) = parameter.example {
                    interesting_combinations.push(example.clone());
                };
                interesting_combinations.extend(
                    parameter
                        .examples
                        .iter()
                        .filter_map(|(_, ref_or)| ref_or.resolve(api).ok())
                        .filter_map(|ex| ex.value),
                );
                if let Ok(value) = example_parameter_value(api, &parameter) {
                    interesting_combinations.push(value);
                }
            }
            let possible_values = interesting_combinations
                .into_iter()
                .map(ParameterContents::from)
                .collect();
            ((parameter.name.clone(), par_kind), possible_values)
        })
        .collect();

    // Now, attempt to create *every possible combination* of these possible values.
    // This means if the possible values are x=1, 2; y=3, 4; you get [1,3] [1,4] [2,3]
    // and [2,4]. This is represented as a list of BTreeMaps. Each BTreeMap would map
    // a parameter to a value, e.g. {x->2, y->3}.
    // We'd like this to be sort-of bounded. Experimentally, that means a maximum of
    // 100 combinations. So each `param_values` must have a len such that the
    // product of all lengths is less than this 100.
    let max_param_values = 100f64.powf(1.0 / param_combinations.len() as f64).floor() as usize;
    let mut maps = vec![BTreeMap::new()];
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

/// Produces one example (or none) based on the given MediaType
fn example_from_media_type(
    api: &Spec,
    contents: &MediaType,
    recursion_limit: usize,
) -> Option<Value> {
    contents
        .examples
        .as_ref()
        .and_then(|examples| {
            examples
                .resolve_all(api)
                .into_iter()
                .filter_map(|(_, val)| val.value)
                .next()
        })
        .or_else(|| {
            contents.schema.as_ref().and_then(|ref_or_schema| {
                example_from_schema(api, &ref_or_schema.resolve(api).ok()?, recursion_limit + 1)
            })
        })
}

/// Produces all examples for the given MediaType
fn interesting_params_from_media_type(api: &Spec, contents: &MediaType) -> Vec<Value> {
    let mut result = vec![];
    if let Some(examples) = &contents.examples {
        result.extend(
            examples
                .resolve_all(api)
                .into_iter()
                .filter_map(|(_, ex)| ex.value),
        );
    };
    if let Some(more_examples) = contents
        .schema
        .as_ref()
        .map(|ref_or_schema| interesting_params_from_schema(api, ref_or_schema, &[]))
    {
        result.extend(more_examples);
    }
    result
}

fn log_schema_debug(schema: &ObjectSchema) {
    if !log::log_enabled!(log::Level::Debug) {
        log::warn!("To output the schema, run with --log-level=debug.");
    }
    log::debug!("{schema:?}");
}

fn example_recursion_limit_exceeded(recursion_depth: usize) -> bool {
    if recursion_depth >= 20 {
        log::warn!(
            "Example resolution exceeds {recursion_depth} steps, this will result in bad examples. Please provide manual examples or avoid circular/deep references."
        );
        true
    } else {
        false
    }
}

// Attempts to build a value that matches the given schema using default values
fn example_from_schema(api: &Spec, schema: &ObjectSchema, recursion_depth: usize) -> Option<Value> {
    // TODO: Probably remove this read_only check.
    // Returning None below is likely because we misinterpreted read_only as pertaining to a type, rather than a schema.
    // The documentation of schema explains readOnly as meaning:
    //
    // "the value of the instance is managed exclusively by the owning authority, and attempts by an application to modify the
    // value of this property are expected to be ignored or rejected by that owning authority."
    //
    // and refers to the json-schema definition. By contrast, readOnly on types means they should only be used in responses
    // as defined here: https://swagger.io/docs/specification/v3_0/data-models/data-types/
    // (hence returning None here, since we generate examples for requests only)
    if example_recursion_limit_exceeded(recursion_depth) {
        return None;
    }
    if Some(true) == schema.read_only {
        return None;
    }
    if schema.default.is_some() {
        return schema.default.clone();
    }
    if schema.example.is_some() {
        return schema.example.clone();
    }
    if !schema.examples.is_empty() {
        return Some(schema.examples[0].clone());
    }
    // Return an example from all_of if it has exactly one entry
    match schema.all_of.len() {
        0 => (),
        1 => {
            return example_from_schema(
                api,
                &schema.all_of[0].resolve(api).ok()?,
                recursion_depth + 1,
            );
        }
        _ => {
            log::warn!(concat!(
                "Generating example parameters for the allOf keyword with more than one schema is not supported. ",
                "See https://swagger.io/docs/specification/v3_0/data-models/oneof-anyof-allof-not/#allof"
            ));
            log_schema_debug(schema);
            return None;
        }
    }
    // Return the first schema that produces an example if one_of is populated
    let one_of_example = schema
        .one_of
        .iter()
        .filter_map(|ref_or_schema| {
            example_from_schema(api, &ref_or_schema.resolve(api).ok()?, recursion_depth + 1)
        })
        .next();
    if one_of_example.is_some() {
        if schema.one_of.len() > 1 {
            log::warn!(
                "Schema has more than one entry in one_of - an example is generated but exclusiveness is not guaranteed."
            )
        }
        return one_of_example;
    }
    let any_of_example = schema
        .any_of
        .iter()
        .filter_map(|ref_or_schema| {
            example_from_schema(api, &ref_or_schema.resolve(api).ok()?, recursion_depth + 1)
        })
        .next();
    if any_of_example.is_some() {
        return any_of_example;
    }
    // Returning None explicitly if no example could be generated.
    if let Some(type_set) = &schema.schema_type {
        match type_set {
            oas3::spec::SchemaTypeSet::Single(single_type) => {
                return example_from_type(api, single_type, schema, recursion_depth + 1);
            }
            oas3::spec::SchemaTypeSet::Multiple(multiple_types) => {
                if let Some(first_type) = multiple_types.first() {
                    return example_from_type(api, first_type, schema, recursion_depth + 1);
                }
            }
        }
    }
    None
}

// Returns all interesting (default, example) values for the given schema.
// ignore_reference may specify a reference that is not followed, this is used
// when resolving discriminator variants, which may refer back to their parent object
// circularly.
fn interesting_params_from_schema(
    api: &Spec,
    schema: &ObjectOrReference<ObjectSchema>,
    ignore_reference_names: &[&str],
) -> Vec<Value> {
    // Add the current schema name to the list of names not to descend into again, to prevent cycles
    let mut ignore_references = ignore_reference_names.to_owned();
    if let ObjectOrReference::Ref { ref_path, .. } = schema {
        ignore_references.push(ref_path);
    }
    let schema = schema.resolve(api).expect("Failed to resolve schema.");
    if schema.read_only.is_some_and(|x| x) {
        // schema property may only be sent in responses, never in requests.
        return vec![];
    }
    let mut result = vec![];
    if let Some(default_schema) = schema.default.clone() {
        result.push(default_schema);
    }
    if let Some(example_schema) = schema.example.clone() {
        result.push(example_schema);
    }
    result.extend(schema.examples.clone());
    if schema.discriminator.is_some() {
        result.extend(all_discriminator_variants(api, &schema, &ignore_references));
    } else {
        // INTERESTING ALL_OF VALUES
        // Creates the union of fields of all interesting values we find for each schema,
        // which might blow up quite a bit depending on the schema.
        let all_examples: Vec<Vec<Value>> = schema
            .all_of
            .iter()
            .filter_map(|ref_or_schema| match ref_or_schema {
                ObjectOrReference::Ref { ref_path, .. }
                    if ignore_references.contains(&ref_path.as_str()) =>
                {
                    None
                }
                _ => Some(interesting_params_from_schema(
                    api,
                    ref_or_schema,
                    &ignore_references,
                )),
            })
            .collect();
        // By combining fields like this, we ensure each example satisfies
        // all of the all_of entries.
        let all_combinations: Vec<Value> = all_examples
            .into_iter()
            .reduce(cartesian_product_values)
            .unwrap_or_default();
        result.extend(all_combinations);
        // INTERESTING ONE_OF AND ANY_OF VALUES
        if schema.one_of.len() > 1 {
            log::warn!("Schema has more than one_of schema: conflicting examples may be generated.")
        }
        result.extend(
            [schema.one_of, schema.any_of]
                .iter()
                .flat_map(|schema_vec| {
                    schema_vec
                        .iter()
                        .flat_map(|ref_or_schema| match ref_or_schema {
                            ObjectOrReference::Ref { ref_path, .. }
                                if ignore_references.contains(&ref_path.as_str()) =>
                            {
                                Vec::new()
                            }
                            _ => interesting_params_from_schema(
                                api,
                                ref_or_schema,
                                &ignore_references,
                            ),
                        })
                }),
        );
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

/// Cartesian product of two vectors of Values.
/// Merges the Values using merge_object_values.
///
/// For example, &[v1, v2], &[w1, w2] result in a vec containing
/// - a value containing all fields in v1 and all fields in w1,
/// - a value containing all fields in v1 and all fields in w2,
/// - a value containing all fields in v2 and all fields in w1,
/// - a value containing all fields in v2 and all fields in w2.
///
/// Inspiration from https://stackoverflow.com/a/74805365
fn cartesian_product_values(xs: Vec<Value>, ys: Vec<Value>) -> Vec<Value> {
    xs.into_iter()
        .flat_map(|x| std::iter::repeat(x).zip(&ys))
        .map(|(left, right)| merge_object_values(left, right.clone()))
        .collect()
}

/// Generates all variants of a discrminator-based schema; i.e. one that has a
/// Discrminator in the schema_data.
/// Supports both OAPI3.0 style discriminators, which have `OneOf`/`AnyOf` as the
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
fn all_discriminator_variants(
    api: &Spec,
    schema: &ObjectSchema,
    ignore_names: &[&str],
) -> Vec<Value> {
    // There is a strong assumption from here on that we're dealing with an
    // object schema, with the fields collected from the variant specified by
    // the discriminator, and merged with the fields from the parent type.
    let discriminator = &schema
        .discriminator
        .as_ref()
        .expect("Should not be called if there is no discriminator");

    // Make a mapping "path to api schema" -> "variant name" for the variants
    let mut mapping: BTreeMap<String, String> = BTreeMap::new();
    // Collect variants and default names from OneOf/AnyOf
    // Only references are allowed by the spec, no inline schemas
    for variant in schema.one_of.iter().chain(schema.any_of.iter()) {
        if let ObjectOrReference::Ref { ref_path, .. } = variant {
            // Select the Dog in '#/components/schemas/Dog'
            if let Some(name) = ref_path.split('/').next_back() {
                mapping.insert(ref_path.clone(), name.to_string());
            }
        }
    }

    // Overwrite variant names with specifically defined mapping keys
    for (name, path) in discriminator.mapping.iter().flatten() {
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
                &ObjectOrReference::Ref {
                    ref_path: path,
                    summary: None,
                    description: None,
                },
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
/// String formats are essentially free-form, but there are some values that
/// "SHOULD" be implemented according to https://json-schema.org/draft/2020-12/json-schema-validation#section-7.2
/// See section 7.3 on that page for defined formats, which are implemented below.
fn strings_from_format(str_format: &str) -> &[&str] {
    match str_format {
        "date" => &["1981-09-05", "0000-01-01", "9999999-12-31"],
        "date-time" => &[
            "1981-09-05T10:00:00Z",    // Regular date
            "0000-01-01T00:00:00Z",    // Used to crash MySQL servers
            "9999999-12-31T20:00:00Z", // At the end of the universe
            "2016-12-31T23:59:60Z",    // Valid leap second
        ],
        "time" => &["23:59:59.999Z"],
        "duration" => &["P3Y6M4DT12H30M5.123S"],
        "email" => &["user.name+tag@example.co.uk"],
        "idn-email" => &["δοκιμή@παράδειγμα.δοκιμή"],
        "ipv4" => &["192.0.2.255"],
        "ipv6" => &["2001:0db8:85a3:0000:0000:8a2e:0370:7334"],
        "uri" => &[
            "https://user:pass@example.com:8443/path/to/resource;param?query=one%20two&flag=true#section-3",
        ],
        "uri-reference" => &["../assets/images/logo.png?size=2x#icon"],
        "iri" => &["https://例え.テスト/パス/検索?q=東京#結果"],
        "iri-reference" => &["../../資料/設計書.html#概要"],
        "uuid" => &["f47ac10b-58cc-4372-a567-0e02b2c3d479"],
        "uri-template" => &["https://api.example.com/users/{userId}/orders{?status,from,to}"],
        "json-pointer" => &["/store/book/0/author"],
        "relative-json-pointer" => &["2/highlighted/0"],
        "regex" => &["^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[!@#$%^&*])[A-Za-z\\d!@#$%^&*]{12,}$"],
        // Extra, "non-defined" formats:
        "base64" => &["V3VwcGllRnV6elROTyE=="],
        // If not matching any of the formats above:
        _ => &["WuppieFuzz", "", "🎵"],
    }
}

/// Enforces the given minimum and maximum length on the input, by padding it
/// with "A"s or truncating it.
fn enforce_length_bounds(
    string: &str,
    min_length: Option<u64>,
    max_length: Option<u64>,
) -> Cow<'_, str> {
    let mut result = Cow::from(string);
    if let Some(min) = min_length {
        *result.to_mut() += &"A".repeat(min as usize);
    }
    if let Some(max) = max_length {
        result.to_mut().unicode_truncate(max as usize);
    }
    result
}

/// Generate parameters based on the type specified. The values returned
/// should adhere to any constraints from the spec, any deviations to
/// test robustness of the server should be introduced by fuzzing.
fn interesting_params_from_type(
    api: &Spec,
    schema: &ObjectSchema,
    recursion_depth: usize,
) -> Vec<Value> {
    if example_recursion_limit_exceeded(recursion_depth) {
        return vec![];
    }
    // For numeric types, take exclusive_minimum and -maximum bools into account.
    schema.schema_type.clone().map_or(vec![], |type_set| {
        {
            let types_vec = match type_set {
                oas3::spec::SchemaTypeSet::Single(single_type) => vec![single_type],
                oas3::spec::SchemaTypeSet::Multiple(multiple_types) => multiple_types,
            };
            types_vec
                .iter()
                .flat_map(|schema_type| {
                    match schema_type {
                        SchemaType::String => interesting_params_from_string_type(
                            &schema.enum_values,
                            &schema.pattern,
                            &schema.format,
                            schema.min_length,
                            schema.max_length,
                        ),
                        SchemaType::Number | SchemaType::Integer => {
                            interesting_params_from_number_type(
                                &schema.minimum,
                                &schema.maximum,
                                &schema.multiple_of,
                            )
                        }
                        SchemaType::Object => vec![Value::Object(
                            schema
                                .properties
                                .iter()
                                .filter_map(|(k, v)| {
                                    Some((
                                        k.clone(),
                                        example_from_schema(
                                            api,
                                            &v.resolve(api).expect("Could not resolve schema."),
                                            recursion_depth + 1,
                                        )?,
                                    ))
                                })
                                .collect(),
                        )],
                        SchemaType::Array => {
                            // The 'items' specification is required according to the spec, but
                            // we still get an Option and a possibly broken reference and what not.
                            // Extract any usable specification of an item, and make an example.

                            // If examples are provided in the API, take the easy way out and use those.
                            if let Some(provided_example) = &schema.example {
                                return vec![provided_example.clone()];
                            } else if !schema.examples.is_empty() {
                                return schema.examples.clone();
                            }

                            let items_schema = *schema
                                .items
                                .clone()
                                .expect("Array-schema should have a schema for its items.");
                            let item_value = match items_schema {
                                oas3::spec::Schema::Boolean(boolean_schema) => {
                                    match &boolean_schema.0 {
                                        true => Value::Object(Default::default()),
                                        false => Value::Null,
                                    }
                                }
                                oas3::spec::Schema::Object(object_or_reference) => {
                                    example_from_schema(
                                        api,
                                        &object_or_reference
                                            .resolve(api)
                                            .expect("Could not resolve schema."),
                                        recursion_depth + 1,
                                    )
                                    .unwrap_or_default()
                                }
                            };
                            // Repeat the example. If a maximum number of array elements is specified,
                            // we use that many, otherwise the minimum number, otherwise 3.
                            vec![Value::Array(vec![
                                item_value;
                                schema.max_items.or(schema.min_items).unwrap_or(3)
                                    as usize
                            ])]
                        }
                        SchemaType::Boolean => vec![Value::Bool(true), Value::Bool(false)],
                        SchemaType::Null => vec![Value::Null],
                    }
                })
                .collect()
        }
    })
}

// We supply the schema_type separately since the schema can have a TypeSet with one or multiple schemas.
fn example_from_type(
    api: &Spec,
    schema_type: &SchemaType,
    schema: &ObjectSchema,
    recursion_depth: usize,
) -> Option<Value> {
    if example_recursion_limit_exceeded(recursion_depth) {
        return None;
    }
    match schema_type {
        SchemaType::String => interesting_params_from_string_type(
            &schema.enum_values,
            &schema.pattern,
            &schema.format,
            schema.min_length,
            schema.max_length,
        )
        .first()
        .cloned(),
        SchemaType::Number => {
            // Try to interpret all JSON numbers as f64 and then create an example based on the results.
            let (min, max, base) = match (
                schema.minimum.clone(),
                schema.maximum.clone(),
                schema.multiple_of.clone(),
            ) {
                (Some(min), Some(max), Some(base)) => (min.as_f64(), max.as_f64(), base.as_f64()),
                (Some(min), Some(max), None) => (min.as_f64(), max.as_f64(), None),
                (Some(min), None, Some(base)) => (min.as_f64(), None, base.as_f64()),
                (Some(min), None, None) => (min.as_f64(), None, None),
                (None, Some(max), Some(base)) => (None, max.as_f64(), base.as_f64()),
                (None, Some(max), None) => (None, max.as_f64(), None),
                (None, None, Some(base)) => (None, None, base.as_f64()),
                (None, None, None) => (None, None, None),
            };
            let value = match (min, max, base) {
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
        SchemaType::Integer => {
            // Try to interpret all JSON-numbers as i128 and then create an example based on the results.
            let (min, max, base) = match (
                schema.minimum.clone(),
                schema.maximum.clone(),
                schema.multiple_of.clone(),
            ) {
                (Some(min), Some(max), Some(base)) => {
                    (min.as_i128(), max.as_i128(), base.as_i128())
                }
                (Some(min), Some(max), None) => (min.as_i128(), max.as_i128(), None),
                (Some(min), None, Some(base)) => (min.as_i128(), None, base.as_i128()),
                (Some(min), None, None) => (min.as_i128(), None, None),
                (None, Some(max), Some(base)) => (None, max.as_i128(), base.as_i128()),
                (None, Some(max), None) => (None, max.as_i128(), None),
                (None, None, Some(base)) => (None, None, base.as_i128()),
                (None, None, None) => (None, None, None),
            };
            let value = match (min, max, base) {
                (Some(min), Some(max), Some(base)) => {
                    ((min + max) as f64 / 2.0 / (base as f64)).round() as i128 * base
                }
                (Some(min), Some(max), None) => (min + max) / 2,
                (Some(min), None, Some(base)) => (min as f64 / base as f64).ceil() as i128 * base,
                (Some(min), None, None) => min,
                (None, Some(max), Some(base)) => (max as f64 / base as f64).floor() as i128 * base,
                (None, Some(max), None) => max,
                (None, None, Some(base)) => base,
                (None, None, None) => 0,
            };
            Some(json![value])
        }
        SchemaType::Object => Some(Value::Object(
            schema
                .properties
                .iter()
                .filter_map(|(k, v)| {
                    Some((
                        k.clone(),
                        example_from_schema(
                            api,
                            &v.resolve(api).expect("Could not resolve schema."),
                            recursion_depth + 1,
                        )?,
                    ))
                })
                .collect(),
        )),
        SchemaType::Array => {
            // The 'items' specification is required according to the spec, but
            // we still get an Option and a possibly broken reference and what not.
            // Extract any usable specification of an item, and make an example.
            interesting_params_from_type(api, schema, recursion_depth + 1)
                .first()
                .cloned()
        }
        SchemaType::Boolean => Some(Value::Bool(true)),
        SchemaType::Null => Some(Value::Null),
    }
}

/// We return all variants if an enumeration is present, try the pattern regex if one is present,
/// or fall back to some defaults based on the StringFormat. Returns a serde_json::Value::String.
fn interesting_params_from_string_type(
    enumeration: &[Value],
    pattern: &Option<String>,
    format: &Option<String>,
    min_length: Option<u64>,
    max_length: Option<u64>,
) -> Vec<serde_json::Value> {
    // Enumeration present? Return all String values.
    let enum_strings: Vec<&Value> = enumeration.iter().filter(|val| val.is_string()).collect();
    if !enum_strings.is_empty() {
        return enum_strings.into_iter().cloned().collect();
    }
    // Regex (without anchors) present? Attempt to compile it, and generate a string that matches it
    if let Some(pattern) = pattern {
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
                log::warn!("Could not generate an example string that matches the regex {pattern}");
            }
            Err(err) => {
                log::warn!("Broken regex pattern {pattern}, Error message: {err}");
            }
        }
    }

    // Attempt to generate a string based on other format hints
    if let Some(format) = format {
        let result: Vec<Value> = strings_from_format(format)
            .iter()
            .map(|&example| {
                serde_json::Value::String(
                    enforce_length_bounds(example, min_length, max_length).into_owned(),
                )
            })
            .collect();
        if !result.is_empty() {
            return result;
        }
    };

    // Return generic string examples
    vec!["WuppieFuzz".into(), "".into(), "🎵".into()]
}

fn interesting_params_from_number_type(
    minimum: &Option<Number>,
    maximum: &Option<Number>,
    multiple_of: &Option<Number>,
) -> Vec<Value> {
    match (minimum, maximum, multiple_of) {
        (Some(min), Some(max), Some(base)) => {
            let mut constrained = vec![];
            let (base128, min128, max128) = (base.as_i128(), min.as_i128(), max.as_i128());
            if let (Some(base128), Some(min128), Some(max128)) = (base128, min128, max128) {
                for candidate in [-base128, 0, base128] {
                    if min128 <= candidate && candidate <= max128 {
                        constrained.push(json![candidate]);
                    }
                }
                constrained
            } else {
                log::warn!("Base, Min or Max could not be converted to 128-bits signed integer.");
                vec![]
            }
        }
        (Some(min), Some(max), None) => {
            let mut constrained = vec![json![min], json![max]];
            if let (Some(minfloat), Some(maxfloat)) = (min.as_f64(), max.as_f64()) {
                let range = minfloat..=maxfloat;
                for val in [-1., 0., 1., PI] {
                    if range.contains(&val) {
                        constrained.push(json![val]);
                    }
                }
            }
            constrained
        }
        (Some(min), None, Some(base)) => {
            let (base128, min128) = (base.as_i128(), min.as_i128());
            if let (Some(base128), Some(min128)) = (base128, min128) {
                let mut constrained = vec![];
                if base128 > 0 {
                    let smallest_multiple = base128 * (min128 / base128);
                    constrained.push(json![smallest_multiple]);
                }
                for candidate in [-base128, 0, base128] {
                    if min128 <= candidate {
                        constrained.push(json![candidate]);
                    }
                }
                constrained
            } else {
                log::warn!("Base or Min could not be converted to 128-bits signed integer.");
                vec![]
            }
        }
        (Some(min), None, None) => {
            let mut constrained = vec![json![min]];
            if let Some(min) = min.as_f64() {
                for val in [-1., 0., 1., PI] {
                    if min <= val {
                        constrained.push(json![val]);
                    }
                }
            }
            constrained
        }
        (None, Some(max), Some(base)) => {
            if let (Some(max), Some(base)) = (max.as_f64(), base.as_f64()) {
                let mut constrained = vec![json![max]];
                for val in [-base, 0., base] {
                    if max >= val {
                        constrained.push(json![val]);
                    }
                }
                constrained
            } else {
                log::warn!("Base or Max could not be converted to 128-bits signed integer.");
                vec![]
            }
        }
        (None, Some(max), None) => {
            if let Some(max) = max.as_f64() {
                let mut constrained = vec![json![max]];
                for val in [-PI, -1., 0., 1.] {
                    if max >= val {
                        constrained.push(json![val]);
                    }
                }
                constrained
            } else {
                log::warn!("Max could not be converted to 128-bits signed integer.");
                vec![]
            }
        }
        (None, None, Some(base)) => {
            let mut result = vec![];
            if let Some(min_base) = base.as_i64() {
                result.push(json![-min_base])
            }
            result.push(json![0]);
            result.push(Value::Number(base.clone()));
            result
        }
        (None, None, None) => vec![json![-1.], json![0.], json![1.], json![PI]],
    }
    // For simplicity we unwrap the Number; if this would panic, we will consider this a bug in the code above.
}

/// Creates a set of OpenApiInputs for the given sequence of QualifiedOperations based on a number of interesting
/// values for each of the parameters found in the OpenApiInputs. Specifically, it returns the cartesian product
/// of all these parameter choices, i.e. for a single-request OpenApiInput with parameters A: bool and B: usize
/// it may for example return (true, 0), (true, 1), (false, 0) and (false, 1).
///
/// This allows the fuzzer to start with all the inputs that we might a priori consider useful, and then
/// continue with random mutations (picking seeds based on coverage feedback).
pub fn openapi_inputs_from_ops<'a>(
    api: &Spec,
    ops_iter: impl Iterator<Item = QualifiedOperation<'a>>,
    subgraph: &DiGraph<QualifiedOperation, ParameterMatching, DefaultIx>,
    sorted_nodes: &[NodeIndex],
) -> Result<Vec<OpenApiInput>, String> {
    // First create all interesting requests per QualifiedOperation independently.
    // We will create request chains from their cartesian product in the next step.
    let mut concrete_requests: VecDeque<Vec<OpenApiRequest>> = ops_iter
        .enumerate()
        .map(|(request_idx, op)| {
            let single_valued: Vec<Parameter> = subgraph
                .edge_references()
                .filter(|edge| edge.target() == sorted_nodes[request_idx])
                .flat_map(|edge| {
                    op.operation
                        .parameters
                        .iter()
                        .filter_map(|ref_or_parameter| ref_or_parameter.resolve(api).ok())
                        .filter(move |parameter| {
                            edge.weight().input_access().matches(parameter.clone())
                        })
                })
                .collect();
            all_interesting_inputs_for_qualified_operation(api, op, &single_valued)
        })
        .collect();

    assert_eq!(sorted_nodes.len(), concrete_requests.len());

    // deduplicate_same_reference_requests(&mut concrete_requests, &subgraph, &sorted_nodes);
    let total_combinations: usize = concrete_requests
        .iter()
        .try_fold(1, |acc: usize, elem| acc.checked_mul(elem.len()))
        .ok_or(
            "Corpus generation would generate billions of inputs, fall back to simple examples.",
        )?;
    if total_combinations > 10000 {
        return Err(format!(
            "Corpus generation would try to create {total_combinations} inputs, fall back to simple examples."
        ));
    }
    if concrete_requests.is_empty() {
        log::warn!("Trying to create OpenApiInputs from QualifiedOperations gave empty result.");
        return Ok(vec![]);
    }
    // Now calculate combinations of requests:
    // Initialize "chains" of only the first request, then combine all chains built so far
    // with each of the OpenApiRequests in the next request (iteratively).
    // TODO: improve this, see #36
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
    for chain in &all_chains {
        assert_eq!(chain.len(), sorted_nodes.len());
    }
    Ok(all_chains.into_iter().map(OpenApiInput).collect())
}

/// Returns a NON-EMPTY vector of interesting requests that can be made for the given operation.
fn all_interesting_inputs_for_qualified_operation(
    api: &Spec,
    operation: QualifiedOperation,
    single_valued: &[Parameter],
) -> Vec<OpenApiRequest> {
    // There may be multiple parameters, create an OpenApiRequest for each combination
    // of interesting values for these parameters.
    let combinations = all_interesting_parameters(operation.operation, api, single_valued);
    let rv = if combinations.is_empty() {
        // There are no parameters, return the interesting bodies.
        match all_interesting_body_contents(api, operation.operation) {
            Some(bodies) => bodies
                .into_iter()
                .map(|body| OpenApiRequest {
                    method: operation.method,
                    path: operation.path.to_owned(),
                    body: Body::build(api, operation.operation, Some(body)),
                    parameters: BTreeMap::default(),
                })
                .collect(),
            None => vec![OpenApiRequest {
                method: operation.method,
                path: operation.path.to_owned(),
                body: Body::build(api, operation.operation, None),
                parameters: BTreeMap::default(),
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
    };
    assert_ne!(rv.len(), 0);
    rv
}
