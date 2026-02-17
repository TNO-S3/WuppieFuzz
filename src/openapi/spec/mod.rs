//! This module contains a representation of an OpenAPI specification as needed
//! by the fuzzer.
//!
//! Because many versions of the OpenAPI specification exist and more might be
//! on the way, we need a representation that contains everything the fuzzer uses
//! in an accessble form. We choose the `oas3` version as the one we use throughout
//! the fuzzer. Most of this module is therefore conversion code.

use std::{collections::BTreeMap, default::Default};

use indexmap::IndexMap;
use oas3::spec::{ObjectOrReference, Operation};
use serde_json::Number;

pub mod load;

/// The representation of the API specification. Internally uses the version
/// from the `oas3` crate, which is hopefully future-proof.
/// The reason to wrap it like this is so we can implement traits such as From
/// for our Spec.
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct Spec(oas3::Spec);

impl std::ops::Deref for Spec {
    type Target = oas3::Spec;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Spec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<oas3::Spec> for Spec {
    /// A v3.1 API specification can be used as-is.
    fn from(value: oas3::Spec) -> Self {
        Self(simplify(value))
    }
}

impl From<openapiv3::OpenAPI> for Spec {
    /// Converts a v2 or v3.0 API specification to the 3.1 representation.
    /// The conversion is lossy, as lots of possible fields are never used by the
    /// fuzzer, and we don't bother converting them.
    fn from(value: openapiv3::OpenAPI) -> Self {
        Self(simplify(oas3::Spec {
            openapi: String::from("3.1.0"),
            info: convert_info(value.info),
            servers: convert_servers(value.servers),
            paths: convert_paths(value.paths),
            components: convert_components(value.components),
            security: Default::default(),
            tags: Default::default(),
            webhooks: Default::default(),
            external_docs: Default::default(),
            extensions: Default::default(),
        }))
    }
}

/// Simplifies the spec structure. Currently
/// - Copies PathItem parameters into its sub-Operations
fn simplify(mut api: oas3::Spec) -> oas3::Spec {
    let mut paths = api.paths.take();
    for (_, path_item) in paths.iter_mut().flatten() {
        for operation in [
            &mut path_item.get,
            &mut path_item.put,
            &mut path_item.post,
            &mut path_item.delete,
            &mut path_item.options,
            &mut path_item.head,
            &mut path_item.patch,
            &mut path_item.trace,
        ]
        .into_iter()
        .flatten()
        {
            add_path_params_to_operation(&api, &path_item.parameters, operation);
        }
    }
    api.paths = paths;
    api
}

fn add_path_params_to_operation(
    api: &oas3::Spec,
    parameters: &[ObjectOrReference<oas3::spec::Parameter>],
    operation: &mut Operation,
) {
    let existing_parameter_names: Vec<String> = operation
        .parameters
        .iter()
        .filter_map(|ref_or_param| ref_or_param.resolve(api).ok())
        .map(|param| param.name)
        .collect();
    for ref_or_param in parameters.iter() {
        if let Ok(actual_parameter) = ref_or_param.resolve(api)
            && !existing_parameter_names.contains(&actual_parameter.name)
        {
            operation.parameters.push(ref_or_param.clone())
        }
    }
}

/// Converts the "info" key of the API spec. Only the title and version are retained.
fn convert_info(info: openapiv3::Info) -> oas3::spec::Info {
    oas3::spec::Info {
        title: info.title,
        version: info.version,
        summary: Default::default(),
        description: Default::default(),
        terms_of_service: Default::default(),
        contact: Default::default(),
        license: Default::default(),
        extensions: Default::default(),
    }
}

/// Converts the "servers" key of the API spec. Only the URL is retained, as nothing else
/// is used by the fuzzer.
fn convert_servers(servers: Vec<openapiv3::Server>) -> Vec<oas3::spec::Server> {
    servers
        .into_iter()
        .map(|s| oas3::spec::Server {
            url: s.url,
            description: Default::default(),
            variables: Default::default(),
            extensions: Default::default(),
        })
        .collect()
}

/// Converts the "paths" key of the API spec.
fn convert_paths(
    paths: openapiv3::Paths,
) -> Option<std::collections::BTreeMap<String, oas3::spec::PathItem>> {
    if paths.is_empty() {
        return None;
    }
    Some(
        paths
            .paths
            .into_iter()
            .map(|(key, value)| {
                (
                    key,
                    match value {
                        openapiv3::Ref::Reference { reference } => oas3::spec::PathItem {
                            reference: Some(reference),
                            ..Default::default()
                        },
                        openapiv3::Ref::Item(path_item) => oas3::spec::PathItem {
                            get: path_item.get.map(convert_operation),
                            put: path_item.put.map(convert_operation),
                            post: path_item.post.map(convert_operation),
                            delete: path_item.delete.map(convert_operation),
                            options: path_item.options.map(convert_operation),
                            head: path_item.head.map(convert_operation),
                            patch: path_item.patch.map(convert_operation),
                            trace: path_item.trace.map(convert_operation),
                            parameters: convert_parameters(path_item.parameters),
                            ..Default::default()
                        },
                    },
                )
            })
            .collect(),
    )
}

/// Converts the "components" key of the API spec.
fn convert_components(components: openapiv3::Components) -> Option<oas3::spec::Components> {
    Some(oas3::spec::Components {
        schemas: convert_ref_map(components.schemas, &convert_schema),
        responses: convert_ref_map(components.responses, &convert_response),
        parameters: convert_ref_map(components.parameters, &convert_parameter),
        examples: convert_ref_map(components.examples, &convert_example),
        request_bodies: convert_ref_map(components.request_bodies, &convert_request_body),
        ..Default::default()
    })
}

fn convert_operation(operation: openapiv3::Operation) -> oas3::spec::Operation {
    oas3::spec::Operation {
        parameters: convert_parameters(operation.parameters),
        request_body: operation
            .request_body
            .map(|ref_or| convert_reference(ref_or, convert_request_body)),
        responses: convert_responses(operation.responses),
        ..Default::default()
    }
}

fn convert_parameters(
    parameters: Vec<openapiv3::RefOr<openapiv3::Parameter>>,
) -> Vec<oas3::spec::ObjectOrReference<oas3::spec::Parameter>> {
    convert_vec_ref(parameters, &convert_parameter)
}

fn convert_parameter(parameter: openapiv3::Parameter) -> oas3::spec::Parameter {
    let openapiv3::Parameter { data, kind } = parameter;
    let mut new_parameter = oas3::spec::Parameter {
        name: data.name,
        location: match kind {
            openapiv3::ParameterKind::Query { .. } => oas3::spec::ParameterIn::Query,
            openapiv3::ParameterKind::Header { .. } => oas3::spec::ParameterIn::Header,
            openapiv3::ParameterKind::Path { .. } => oas3::spec::ParameterIn::Path,
            openapiv3::ParameterKind::Cookie { .. } => oas3::spec::ParameterIn::Cookie,
        },
        required: Some(data.required),
        schema: None,  // To be set later
        content: None, // To be set later
        example: data.example,
        examples: convert_ref_map(data.examples.into(), &convert_example),

        description: None,
        deprecated: None,
        allow_empty_value: None,
        style: None,
        explode: None,
        allow_reserved: None,
        extensions: Default::default(),
    };
    match data.format {
        openapiv3::ParameterSchemaOrContent::Schema(ref_schema) => {
            new_parameter.schema = Some(convert_ref_schema(ref_schema))
        }
        openapiv3::ParameterSchemaOrContent::Content(content) => {
            new_parameter.content = Some(convert_map_media_type(content))
        }
    };
    new_parameter
}

fn convert_request_body(body: openapiv3::RequestBody) -> oas3::spec::RequestBody {
    oas3::spec::RequestBody {
        description: body.description,
        content: convert_map_media_type(body.content),

        required: Some(body.required),
    }
}

fn convert_responses(
    responses: openapiv3::Responses,
) -> Option<BTreeMap<String, oas3::spec::ObjectOrReference<oas3::spec::Response>>> {
    let mut new_responses: BTreeMap<String, oas3::spec::ObjectOrReference<oas3::spec::Response>> =
        responses
            .responses
            .into_iter()
            .map(|(key, value)| (key.to_string(), convert_reference(value, convert_response)))
            .collect();
    if let Some(default_response) = responses.default {
        new_responses.insert(
            String::from("default"),
            convert_reference(default_response, convert_response),
        );
    }
    if new_responses.is_empty() {
        return None;
    }
    Some(new_responses)
}

fn convert_response(response: openapiv3::Response) -> oas3::spec::Response {
    oas3::spec::Response {
        content: convert_map_media_type(response.content),
        ..Default::default()
    }
}

fn convert_map_media_type(
    map_media: IndexMap<String, openapiv3::MediaType>,
) -> BTreeMap<String, oas3::spec::MediaType> {
    map_media
        .into_iter()
        .map(|(key, value)| (key, convert_media_type(value)))
        .collect()
}

fn convert_media_type(media_type: openapiv3::MediaType) -> oas3::spec::MediaType {
    let openapiv3::MediaType {
        schema,
        example,
        examples,
        ..
    } = media_type;
    oas3::spec::MediaType {
        schema: schema.map(convert_ref_schema),
        examples: convert_examples(example, examples),
        ..Default::default()
    }
}

/// This is really a shorthand for `convert_reference` with `convert_schema`,
/// but we use it so often that this saves space and readability.
fn convert_ref_schema(
    ref_schema: openapiv3::RefOr<openapiv3::Schema>,
) -> oas3::spec::ObjectOrReference<oas3::spec::ObjectSchema> {
    convert_reference(ref_schema, convert_schema)
}

fn convert_schema(schema: openapiv3::Schema) -> oas3::spec::ObjectSchema {
    let openapiv3::Schema { data, kind } = schema;
    match kind {
        openapiv3::SchemaKind::Type(r#type) => convert_elementary_type(r#type),
        openapiv3::SchemaKind::OneOf { one_of } => oas3::spec::ObjectSchema {
            one_of: convert_vec_ref(one_of, &convert_schema),
            ..Default::default()
        },
        openapiv3::SchemaKind::AllOf { all_of } => oas3::spec::ObjectSchema {
            all_of: convert_vec_ref(all_of, &convert_schema),
            ..Default::default()
        },
        openapiv3::SchemaKind::AnyOf { any_of } => oas3::spec::ObjectSchema {
            any_of: convert_vec_ref(any_of, &convert_schema),
            ..Default::default()
        },
        openapiv3::SchemaKind::Not { not: _ } => {
            unimplemented!("The `not` schema kind is not implemented by `oas3`.")
        }
        openapiv3::SchemaKind::Any(any_schema) => {
            // Handle 3.0 -> 3.1 min/max & exclusives
            let (minimum, exclusive_minimum, maximum, exclusive_maximum) =
                split_min_max(&any_schema);

            let mut properties: BTreeMap<
                String,
                oas3::spec::ObjectOrReference<oas3::spec::ObjectSchema>,
            > = BTreeMap::new();
            for (name, ref_or_schema) in any_schema.properties.into_iter() {
                // Assuming `RefOrMap` yields (&String, &RefOr<Schema>)
                properties.insert(name, convert_ref_schema(ref_or_schema));
            }

            // Map composition keywords
            let mut examples = Vec::new();
            if let Some(ex) = data.example {
                examples.push(ex);
            }

            // Items / prefixItems:
            // - v3.0 has `items: Option<Box<RefOr<Schema>>>`
            // - oas3 `ObjectSchema` uses `items: Option<Box<Schema>>` and `prefix_items` for tuple validation
            //
            // Without your `Schema` converter, we leave `items` as None. If you have one, plug it in here.
            let items = None::<Box<oas3::spec::Schema>>;
            let prefix_items =
                Vec::<oas3::spec::ObjectOrReference<oas3::spec::ObjectSchema>>::new();

            oas3::spec::ObjectSchema {
                // Compositions
                all_of: convert_vec_ref(any_schema.all_of, &convert_schema),
                any_of: convert_vec_ref(any_schema.any_of, &convert_schema),
                one_of: convert_vec_ref(any_schema.one_of, &convert_schema),

                // Arrays / tuples
                items,
                prefix_items,

                // Object properties
                properties,
                additional_properties: None,

                // Types
                schema_type: convert_type_set(any_schema.typ, data.nullable),

                // Enum / const
                enum_values: any_schema.enumeration,
                const_value: None, // `AnySchema` doesn’t have a `const` field (v3.0)

                // Numeric validations
                multiple_of: any_schema.multiple_of.and_then(Number::from_f64),
                maximum,
                exclusive_maximum,
                minimum,
                exclusive_minimum,

                // String validations
                max_length: any_schema.max_length.map(|v| v as u64),
                min_length: any_schema.min_length.map(|v| v as u64),
                pattern: any_schema.pattern,

                // Array validations
                max_items: any_schema.max_items.map(|v| v as u64),
                min_items: any_schema.min_items.map(|v| v as u64),
                unique_items: any_schema.unique_items,

                // Object validations
                max_properties: any_schema.max_properties.map(|v| v as u64),
                min_properties: any_schema.min_properties.map(|v| v as u64),
                required: any_schema.required,

                // Format & metadata
                format: any_schema.format,
                title: data.title,
                description: data.description,
                default: data.default,

                deprecated: Some(data.deprecated),
                read_only: Some(data.read_only),
                write_only: Some(data.write_only),

                examples,
                ..Default::default()
            }
        }
    }
}

fn convert_elementary_type(r#type: openapiv3::Type) -> oas3::spec::ObjectSchema {
    use oas3::spec::{ObjectSchema, SchemaType, SchemaTypeSet};
    match r#type {
        openapiv3::Type::String(string_type) => ObjectSchema {
            schema_type: Some(SchemaTypeSet::Single(SchemaType::String)),
            pattern: string_type.pattern,
            enum_values: string_type
                .enumeration
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
            min_length: string_type.min_length.map(|v| v as u64),
            max_length: string_type.max_length.map(|v| v as u64),
            ..Default::default()
        },
        openapiv3::Type::Number(number_type) => {
            let (minimum, exclusive_minimum, maximum, exclusive_maximum) =
                split_min_max(&number_type);
            ObjectSchema {
                schema_type: Some(SchemaTypeSet::Single(SchemaType::Number)),
                multiple_of: number_type.multiple_of.and_then(Number::from_f64),
                maximum,
                exclusive_maximum,
                minimum,
                exclusive_minimum,
                enum_values: number_type
                    .enumeration
                    .into_iter()
                    .flat_map(|of| of.and_then(Number::from_f64))
                    .map(serde_json::Value::Number)
                    .collect(),
                ..Default::default()
            }
        }
        openapiv3::Type::Integer(integer_type) => {
            let (minimum, exclusive_minimum, maximum, exclusive_maximum) =
                split_min_max(&integer_type);
            ObjectSchema {
                schema_type: Some(SchemaTypeSet::Single(SchemaType::Integer)),
                multiple_of: integer_type.multiple_of.map(Number::from),
                maximum,
                exclusive_maximum,
                minimum,
                exclusive_minimum,
                enum_values: integer_type
                    .enumeration
                    .into_iter()
                    .flat_map(|oi| oi.map(Number::from))
                    .map(serde_json::Value::Number)
                    .collect(),
                ..Default::default()
            }
        }
        openapiv3::Type::Object(object_type) => ObjectSchema {
            schema_type: Some(SchemaTypeSet::Single(SchemaType::Object)),
            properties: convert_ref_map(object_type.properties, &convert_schema),
            required: object_type.required,
            min_properties: object_type.min_properties.map(|v| v as u64),
            max_properties: object_type.max_properties.map(|v| v as u64),
            ..Default::default()
        },
        openapiv3::Type::Array(array_type) => ObjectSchema {
            schema_type: Some(SchemaTypeSet::Single(SchemaType::Array)),
            items: array_type.items.map(|boxed_ref_schema| {
                Box::new(oas3::spec::Schema::Object(Box::new(convert_ref_schema(
                    *boxed_ref_schema,
                ))))
            }),
            min_items: array_type.min_items.map(|v| v as u64),
            max_items: array_type.max_items.map(|v| v as u64),
            unique_items: Some(array_type.unique_items),
            ..Default::default()
        },
        openapiv3::Type::Boolean {} => ObjectSchema {
            schema_type: Some(SchemaTypeSet::Single(SchemaType::Boolean)),
            ..Default::default()
        },
    }
}

fn convert_type_set(typ: Option<String>, nullable: bool) -> Option<oas3::spec::SchemaTypeSet> {
    match typ {
        None => nullable.then_some(oas3::spec::SchemaTypeSet::Single(
            oas3::spec::SchemaType::Null,
        )),
        Some(description) => {
            let schema_type = match description.as_str() {
                "boolean" => oas3::spec::SchemaType::Boolean,
                "integer" => oas3::spec::SchemaType::Integer,
                "number" => oas3::spec::SchemaType::Number,
                "string" => oas3::spec::SchemaType::String,
                "array" => oas3::spec::SchemaType::Array,
                "object" => oas3::spec::SchemaType::Object,
                _ => oas3::spec::SchemaType::Null,
            };
            if nullable && schema_type != oas3::spec::SchemaType::Null {
                Some(oas3::spec::SchemaTypeSet::Multiple(vec![
                    schema_type,
                    oas3::spec::SchemaType::Null,
                ]))
            } else {
                Some(oas3::spec::SchemaTypeSet::Single(schema_type))
            }
        }
    }
}

fn convert_examples(
    example: Option<serde_json::Value>,
    examples: IndexMap<String, openapiv3::RefOr<openapiv3::Example>>,
) -> Option<oas3::spec::MediaTypeExamples> {
    if let Some(value) = example {
        return Some(oas3::spec::MediaTypeExamples::Example { example: value });
    }
    if examples.is_empty() {
        return None;
    }
    Some(oas3::spec::MediaTypeExamples::Examples {
        examples: examples
            .into_iter()
            .map(|(key, value)| (key, convert_reference(value, convert_example)))
            .collect(),
    })
}

fn convert_example(example: openapiv3::Example) -> oas3::spec::Example {
    oas3::spec::Example {
        value: example.value,
        ..Default::default()
    }
}

fn convert_reference<T, U>(
    reference: openapiv3::RefOr<T>,
    converter: impl FnOnce(T) -> U,
) -> oas3::spec::ObjectOrReference<U> {
    match reference {
        openapiv3::Ref::Item(item) => oas3::spec::ObjectOrReference::Object(converter(item)),
        openapiv3::Ref::Reference { reference } => oas3::spec::ObjectOrReference::Ref {
            ref_path: reference,
            summary: None,
            description: None,
        },
    }
}

/// This is really a shorthand for `convert_reference` called on vector elements.
fn convert_vec_ref<T, U>(
    vec_ref: Vec<openapiv3::RefOr<T>>,
    converter: &impl Fn(T) -> U,
) -> Vec<oas3::spec::ObjectOrReference<U>> {
    vec_ref
        .into_iter()
        .map(move |value| convert_reference(value, converter))
        .collect()
}

fn convert_ref_map<T, U>(
    ref_map: openapiv3::RefMap<T>,
    converter: &impl Fn(T) -> U,
) -> BTreeMap<String, oas3::spec::ObjectOrReference<U>> {
    ref_map
        .into_iter()
        .map(|(key, value)| (key, convert_reference(value, converter)))
        .collect()
}

trait HasMinMax {
    fn minimum(&self) -> Option<f64>;
    fn maximum(&self) -> Option<f64>;
    fn exclusive_minimum(&self) -> Option<bool>;
    fn exclusive_maximum(&self) -> Option<bool>;
}

fn split_min_max<T: HasMinMax>(
    schema: &T,
) -> (
    Option<serde_json::Number>,
    Option<serde_json::Number>,
    Option<serde_json::Number>,
    Option<serde_json::Number>,
) {
    let (minimum, exclusive_minimum) = match (schema.minimum(), schema.exclusive_minimum()) {
        (Some(min), Some(true)) => (None, serde_json::Number::from_f64(min)),
        (Some(min), _) => (serde_json::Number::from_f64(min), None),
        (None, _) => (None, None),
    };

    let (maximum, exclusive_maximum) = match (schema.maximum(), schema.exclusive_maximum()) {
        (Some(max), Some(true)) => (None, serde_json::Number::from_f64(max)),
        (Some(max), _) => (serde_json::Number::from_f64(max), None),
        (None, _) => (None, None),
    };

    (minimum, exclusive_minimum, maximum, exclusive_maximum)
}

impl HasMinMax for openapiv3::AnySchema {
    fn minimum(&self) -> Option<f64> {
        self.minimum
    }
    fn maximum(&self) -> Option<f64> {
        self.maximum
    }
    fn exclusive_minimum(&self) -> Option<bool> {
        self.exclusive_minimum
    }
    fn exclusive_maximum(&self) -> Option<bool> {
        self.exclusive_maximum
    }
}

impl HasMinMax for openapiv3::NumberType {
    fn minimum(&self) -> Option<f64> {
        self.minimum
    }
    fn maximum(&self) -> Option<f64> {
        self.maximum
    }
    fn exclusive_minimum(&self) -> Option<bool> {
        Some(self.exclusive_minimum)
    }
    fn exclusive_maximum(&self) -> Option<bool> {
        Some(self.exclusive_maximum)
    }
}

impl HasMinMax for openapiv3::IntegerType {
    fn minimum(&self) -> Option<f64> {
        self.minimum.map(|v| v as f64)
    }
    fn maximum(&self) -> Option<f64> {
        self.maximum.map(|v| v as f64)
    }
    fn exclusive_minimum(&self) -> Option<bool> {
        Some(self.exclusive_minimum)
    }
    fn exclusive_maximum(&self) -> Option<bool> {
        Some(self.exclusive_maximum)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use oas3::spec::{Info, ObjectOrReference, Operation, Parameter, PathItem};
    use reqwest::Method;

    // Test whether a common parameter is added to the parameters of specific operations during simplification:
    // - Common parameter is added to operation-specific parameters
    // - Common parameter is added correctly to operation with empty parameters
    // - Common parameter is not added to an operation that is not specified
    #[test]
    fn test_simplify() {
        let mut test_paths = BTreeMap::new();
        test_paths.insert(
            "test_path".to_string(),
            PathItem {
                get: Some(Operation {
                    parameters: vec![ObjectOrReference::Object(Parameter {
                        name: "parameter_in_get".to_string(),
                        location: oas3::spec::ParameterIn::Path,
                        description: Default::default(),
                        required: Default::default(),
                        deprecated: Default::default(),
                        allow_empty_value: Default::default(),
                        style: Default::default(),
                        explode: Default::default(),
                        allow_reserved: Default::default(),
                        schema: Default::default(),
                        example: Default::default(),
                        examples: Default::default(),
                        content: Default::default(),
                        extensions: Default::default(),
                    })],
                    ..Default::default()
                }),
                put: Some(Operation {
                    parameters: vec![],
                    ..Default::default()
                }),
                parameters: vec![ObjectOrReference::Object(Parameter {
                    name: "parameter_common".to_string(),
                    location: oas3::spec::ParameterIn::Path,
                    description: Default::default(),
                    required: Default::default(),
                    deprecated: Default::default(),
                    allow_empty_value: Default::default(),
                    style: Default::default(),
                    explode: Default::default(),
                    allow_reserved: Default::default(),
                    schema: Default::default(),
                    example: Default::default(),
                    examples: Default::default(),
                    content: Default::default(),
                    extensions: Default::default(),
                })],
                ..Default::default()
            },
        );
        let complicated_spec = oas3::Spec {
            openapi: String::from("3.1.0"),
            info: Info {
                title: Default::default(),
                summary: Default::default(),
                description: Default::default(),
                terms_of_service: Default::default(),
                version: Default::default(),
                contact: Default::default(),
                license: Default::default(),
                extensions: Default::default(),
            },
            servers: Default::default(),
            paths: Some(test_paths),
            components: Default::default(),
            security: Default::default(),
            tags: Default::default(),
            webhooks: Default::default(),
            external_docs: Default::default(),
            extensions: Default::default(),
        };
        let simplified_spec = super::simplify(complicated_spec.clone());
        // Added to an operation's existing parameters?
        let get_operation = simplified_spec
            .operation(&Method::GET, "test_path")
            .unwrap();
        assert!(get_operation.parameters.len() == 2);
        for obj_or_ref in get_operation.parameters.iter() {
            if let ObjectOrReference::Object(obj) = obj_or_ref {
                assert!(obj.name == "parameter_common" || obj.name == "parameter_in_get");
            } else {
                assert!(false);
            }
        }
        // Added to a specified operation's empty parameters?
        let put_operation = simplified_spec
            .operation(&Method::PUT, "test_path")
            .unwrap();
        assert!(put_operation.parameters.len() == 1);
        for obj_or_ref in put_operation.parameters.iter() {
            if let ObjectOrReference::Object(obj) = obj_or_ref {
                assert!(obj.name == "parameter_common");
            } else {
                assert!(false);
            }
        }
        // Not added to an unspecified operation?
        assert!(simplified_spec.operation(&Method::POST, "test_path") == None);
    }
}
