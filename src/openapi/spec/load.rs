//! Loads an OpenAPI specification from a file, and converts it to the format we use.

use std::path::Path;

use anyhow::{Context, Result};
use openapiv3::VersionedOpenAPI;

use super::Spec;

/// AttemptsFailed records a parallel set of errors, that result from multiple
/// strategies failing. When Displayed, it prints all error chains that resulted
/// from the different attempts, so the user can find the strategy they wanted
/// to use and fix the errors that resulted in that attempt.
#[derive(Debug)]
struct AttemptsFailed {
    errors: Vec<anyhow::Error>,
}

impl std::fmt::Display for AttemptsFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, err) in self.errors.iter().enumerate() {
            writeln!(f, "{i}. {err}")?;
            for cause in err.chain().skip(1) {
                writeln!(f, "     because: {cause}")?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for AttemptsFailed {}

pub fn openapi_from_file(filename: &Path) -> Result<Spec> {
    let file_contents = std::fs::read_to_string(filename)?;
    let mut errors = Vec::new();

    match oas3::from_yaml(&file_contents).context("Failed to parse as YAML OpenAPI v3.1") {
        Ok(spec) => {
            return Ok(spec.into());
        }
        Err(err) => errors.push(err),
    };
    match oas3::from_json(&file_contents).context("Failed to parse as JSON OpenAPI v3.1") {
        Ok(spec) => return Ok(spec.into()),
        Err(err) => errors.push(err),
    };

    match serde_yaml::from_str::<VersionedOpenAPI>(&file_contents)
        .context("Failed to parse as YAML OpenAPI v2/v3.0")
    {
        Ok(spec) => {
            return Ok(spec.upgrade().into());
        }
        Err(err) => errors.push(err),
    };

    match serde_json::from_str::<VersionedOpenAPI>(&file_contents)
        .context("Failed to parse as JSON OpenAPI v2/v3.0")
    {
        Ok(spec) => return Ok(spec.upgrade().into()),
        Err(err) => errors.push(err),
    };
    Err(AttemptsFailed { errors }.into())
}

/// Loads the OpenAPI specification from the given path
pub fn get_api_spec(path: &Path) -> Result<Box<Spec>, anyhow::Error> {
    openapi_from_file(path)
        .map(Box::new)
        .with_context(|| format!("Error parsing OpenAPI-file at {}", path.to_string_lossy()))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    /// Helper: write `contents` to a temp file and load it via `openapi_from_file`.
    fn load_spec_from_str(contents: &str) -> Spec {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        openapi_from_file(file.path()).expect("Failed to load spec")
    }

    fn schema_object(schema: &oas3::spec::Schema) -> &oas3::spec::ObjectSchema {
        match schema {
            oas3::spec::Schema::Boolean(_) => panic!("Expected object schema, got boolean schema"),
            oas3::spec::Schema::Object(schema_ref) => match schema_ref.as_ref() {
                oas3::spec::ObjectOrReference::Object(schema) => schema,
                oas3::spec::ObjectOrReference::Ref { .. } => {
                    panic!("Expected concrete schema, got $ref")
                }
            },
        }
    }

    /// Helper: given a loaded Spec, find the schema for a given component name.
    fn get_component_schema<'a>(spec: &'a Spec, name: &str) -> &'a oas3::spec::ObjectSchema {
        let components = spec.components.as_ref().expect("spec has no components");
        schema_object(components.schemas.get(name).expect("schema not found"))
    }

    /// Verifies that schema-level `example` (singular, v3.0 keyword) is preserved
    /// across all schema types when loaded via the oas3 path (v3.0 YAML).
    /// The oas3 library stores v3.0's singular `example` in the deprecated `example` field,
    /// not in the v3.1 `examples` Vec.
    #[test]
    fn upgrade_preserves_schema_examples_all_types() {
        let spec_yaml = r#"
openapi: "3.0.3"
info:
  title: Test
  version: "1.0"
paths: {}
components:
  schemas:
    Greeting:
      type: string
      example: "Hello, world!"
    Age:
      type: integer
      example: 42
    Tags:
      type: array
      items:
        type: string
      example: ["alpha", "beta"]
    User:
      type: object
      properties:
        name:
          type: string
          example: "nested@example.com"
        age:
          type: integer
      example:
        name: Alice
        age: 30
"#;
        let spec = load_spec_from_str(spec_yaml);

        // oas3 stores v3.0's singular `example` in the `example` field (deprecated but functional)
        let greeting = get_component_schema(&spec, "Greeting");
        assert_eq!(
            greeting.example,
            Some(serde_json::json!("Hello, world!")),
            "String example lost. example: {:?}",
            greeting.example
        );

        let age = get_component_schema(&spec, "Age");
        assert_eq!(
            age.example,
            Some(serde_json::json!(42)),
            "Integer example lost. example: {:?}",
            age.example
        );

        let tags = get_component_schema(&spec, "Tags");
        assert_eq!(
            tags.example,
            Some(serde_json::json!(["alpha", "beta"])),
            "Array example lost. example: {:?}",
            tags.example
        );

        let user = get_component_schema(&spec, "User");
        assert_eq!(
            user.example,
            Some(serde_json::json!({"name": "Alice", "age": 30})),
            "Object example lost. example: {:?}",
            user.example
        );

        // Nested property example
        let name_schema = schema_object(user.properties.get("name").unwrap());
        assert_eq!(
            name_schema.example,
            Some(serde_json::json!("nested@example.com")),
            "Nested property example lost. example: {:?}",
            name_schema.example
        );
    }

    /// Verifies that MediaType-level examples (on request bodies) are preserved.
    #[test]
    fn upgrade_preserves_media_type_example() {
        let spec_yaml = r#"
openapi: "3.0.3"
info:
  title: Test
  version: "1.0"
paths:
  /items:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
            example:
              name: "TestItem"
      responses:
        '200':
          description: OK
"#;
        let spec = load_spec_from_str(spec_yaml);
        let operation = spec
            .paths
            .as_ref()
            .unwrap()
            .get("/items")
            .unwrap()
            .post
            .as_ref()
            .unwrap();
        let request_body = operation
            .request_body
            .as_ref()
            .unwrap()
            .resolve(&spec)
            .expect("could not resolve request body");
        let media_type = request_body
            .content
            .get("application/json")
            .expect("missing application/json content");
        match &media_type.examples {
            Some(oas3::spec::MediaTypeExamples::Example { example }) => {
                assert_eq!(*example, serde_json::json!({"name": "TestItem"}));
            }
            other => panic!("Expected MediaTypeExamples::Example, got {:?}", other),
        }
    }

    /// Verifies that a v3.1 spec with `examples` (plural, array form) is loaded correctly.
    #[test]
    fn v31_spec_preserves_schema_examples() {
        let spec_yaml = r#"
openapi: "3.1.0"
info:
  title: Test
  version: "1.0"
paths: {}
components:
  schemas:
    Color:
      type: string
      examples:
        - "red"
        - "green"
        - "blue"
"#;
        let spec = load_spec_from_str(spec_yaml);
        let schema = get_component_schema(&spec, "Color");
        assert!(schema.examples.contains(&serde_json::json!("red")));
        assert!(schema.examples.contains(&serde_json::json!("blue")));
    }

    /// Verifies that `example` on composition schemas (allOf/oneOf/anyOf) is preserved
    /// when going through the openapiv3 upgrade path (Swagger 2.0 forces this path).
    #[test]
    fn upgrade_preserves_example_on_composition_schemas() {
        let spec_json = r#"{
  "swagger": "2.0",
  "info": { "title": "Test", "version": "1.0" },
  "host": "localhost",
  "basePath": "/",
  "paths": {},
  "definitions": {
    "Pet": {
      "allOf": [
        { "type": "object", "properties": { "name": { "type": "string" } } },
        { "type": "object", "properties": { "age": { "type": "integer" } } }
      ],
      "example": { "name": "Fido", "age": 5 }
    },
    "Shape": {
      "oneOf": [
        { "type": "object", "properties": { "radius": { "type": "number" } } },
        { "type": "object", "properties": { "width": { "type": "number" } } }
      ],
      "example": { "radius": 1.4 }
    },
    "Flexible": {
      "anyOf": [
        { "type": "string" },
        { "type": "integer" }
      ],
      "example": "hello"
    }
  }
}"#;
        let spec = load_spec_from_str(spec_json);

        let pet = get_component_schema(&spec, "Pet");
        assert!(
            pet.examples
                .contains(&serde_json::json!({"name": "Fido", "age": 5})),
            "allOf example lost. examples: {:?}",
            pet.examples
        );

        let shape = get_component_schema(&spec, "Shape");
        assert!(
            shape.examples.contains(&serde_json::json!({"radius": 1.4})),
            "oneOf example lost. examples: {:?}",
            shape.examples
        );

        let flexible = get_component_schema(&spec, "Flexible");
        assert!(
            flexible.examples.contains(&serde_json::json!("hello")),
            "anyOf example lost. examples: {:?}",
            flexible.examples
        );
    }

    /// Verifies that parameter-level `example` and parameter schema `example`
    /// are both preserved (v3.0, oas3 path).
    #[test]
    fn upgrade_preserves_parameter_examples() {
        let spec_yaml = r#"
openapi: "3.0.3"
info:
  title: Test
  version: "1.0"
paths:
  /users/{userId}:
    get:
      parameters:
        - name: userId
          in: path
          required: true
          schema:
            type: integer
            example: 123
          example: 456
      responses:
        '200':
          description: OK
"#;
        let spec = load_spec_from_str(spec_yaml);
        let operation = spec
            .paths
            .as_ref()
            .unwrap()
            .get("/users/{userId}")
            .unwrap()
            .get
            .as_ref()
            .unwrap();
        let param = operation
            .parameters
            .iter()
            .filter_map(|p| p.resolve(&spec).ok())
            .find(|p| p.name == "userId")
            .expect("userId parameter missing");

        // Parameter-level example (on the Parameter object itself)
        assert_eq!(
            param.example,
            Some(serde_json::json!(456)),
            "Parameter-level example lost"
        );

        // Schema-level example (nested inside the parameter's schema)
        // oas3 stores v3.0's singular `example` in the deprecated `example` field
        let schema = match &param.schema {
            Some(s) => schema_object(s),
            None => panic!("Expected concrete schema on parameter"),
        };
        assert_eq!(
            schema.example,
            Some(serde_json::json!(123)),
            "Parameter schema example lost. example: {:?}",
            schema.example
        );
    }

    /// Verifies that schema examples survive the openapiv3 upgrade path with
    /// deeply nested properties (Swagger 2.0 forces this path).
    #[test]
    fn upgrade_from_swagger2_preserves_schema_examples() {
        let spec_json = r#"{
  "swagger": "2.0",
  "info": { "title": "Test", "version": "1.0" },
  "host": "localhost",
  "basePath": "/",
  "paths": {
    "/search": {
      "post": {
        "parameters": [{
          "name": "body",
          "in": "body",
          "schema": {
            "type": "object",
            "properties": {
              "query": { "type": "string", "example": "search term" },
              "options": {
                "type": "object",
                "properties": {
                  "limit": { "type": "integer", "example": 50 }
                },
                "example": { "limit": 50 }
              }
            },
            "example": { "query": "test", "options": { "limit": 25 } }
          }
        }],
        "responses": { "200": { "description": "OK" } }
      }
    }
  },
  "definitions": {
    "Status": { "type": "string", "example": "active" }
  }
}"#;
        let spec = load_spec_from_str(spec_json);

        // Component schema example
        let status = get_component_schema(&spec, "Status");
        assert!(
            status.examples.contains(&serde_json::json!("active")),
            "Component schema example lost. examples: {:?}",
            status.examples
        );

        // Body schema (top-level) - The v2 upgrade wraps body params in an object,
        // so the actual schema is nested as a property named "body".
        let operation = spec
            .paths
            .as_ref()
            .unwrap()
            .get("/search")
            .unwrap()
            .post
            .as_ref()
            .unwrap();
        let body = operation
            .request_body
            .as_ref()
            .unwrap()
            .resolve(&spec)
            .expect("could not resolve body");
        let wrapper_schema = match &body.content.iter().next().unwrap().1.schema {
            Some(s) => schema_object(s),
            None => panic!("Expected concrete schema on request body"),
        };
        let body_schema = schema_object(wrapper_schema.properties.get("body").unwrap());
        assert!(
            body_schema
                .examples
                .contains(&serde_json::json!({"query": "test", "options": {"limit": 25}})),
            "Body schema example lost. examples: {:?}",
            body_schema.examples
        );

        // Nested property example
        let query_prop = schema_object(body_schema.properties.get("query").unwrap());
        assert!(
            query_prop
                .examples
                .contains(&serde_json::json!("search term")),
            "Nested property example lost. examples: {:?}",
            query_prop.examples
        );

        // Deeply nested property example (options.limit)
        let options_prop = schema_object(body_schema.properties.get("options").unwrap());
        let limit_prop = schema_object(options_prop.properties.get("limit").unwrap());
        assert!(
            limit_prop.examples.contains(&serde_json::json!(50)),
            "Deeply nested example lost. examples: {:?}",
            limit_prop.examples
        );
    }

    /// Compares loading a v3.0 spec via the oas3 path (direct) vs the openapiv3 path
    /// (upgrade). Both paths should produce the same schema data. If they diverge,
    /// it indicates one path is losing data that the other preserves.
    #[test]
    fn v30_oas3_vs_openapiv3_paths_produce_same_schema_data() {
        let spec_yaml = r#"
openapi: "3.0.3"
info:
  title: Test
  version: "1.0"
paths:
  /items/{id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
            example: 7
          example: 42
      responses:
        '200':
          description: OK
components:
  schemas:
    Item:
      type: object
      title: "An Item"
      description: "Represents an item in the store"
      default: { "name": "unnamed", "price": 0 }
      example: { "name": "Widget", "price": 9.99 }
      properties:
        name:
          type: string
          title: "Item name"
          example: "Gadget"
        price:
          type: number
          example: 4.99
    Status:
      type: string
      example: "active"
      default: "pending"
"#;
        // Path 1: oas3 directly (what openapi_from_file does for v3.0)
        let spec_via_oas3: Spec = oas3::from_yaml(spec_yaml)
            .expect("oas3 should parse v3.0")
            .into();

        // Path 2: openapiv3 parse + upgrade (what would happen if oas3 rejected it)
        let spec_via_openapiv3: Spec = serde_yaml::from_str::<VersionedOpenAPI>(spec_yaml)
            .expect("openapiv3 should parse v3.0")
            .upgrade()
            .into();

        // Compare component schemas
        let oas3_components = spec_via_oas3.components.as_ref().unwrap();
        let openapiv3_components = spec_via_openapiv3.components.as_ref().unwrap();

        for schema_name in ["Item", "Status"] {
            let oas3_schema = schema_object(oas3_components.schemas.get(schema_name).unwrap());
            let openapiv3_schema =
                schema_object(openapiv3_components.schemas.get(schema_name).unwrap());

            // oas3 path stores v3.0's singular `example` in deprecated `example` field,
            // openapiv3 conversion stores it in the v3.1 `examples` Vec.
            // Verify both paths preserve the example data (just in different fields).
            let oas3_example = oas3_schema.example.clone();
            let openapiv3_examples = &openapiv3_schema.examples;
            if let Some(ex) = &oas3_example {
                assert!(
                    openapiv3_examples.contains(ex),
                    "Schema '{schema_name}': oas3 has example={:?} but openapiv3 examples={:?}",
                    oas3_example,
                    openapiv3_examples
                );
            }
            assert_eq!(
                oas3_schema.title, openapiv3_schema.title,
                "Schema '{schema_name}' title differs between paths"
            );
            assert_eq!(
                oas3_schema.description, openapiv3_schema.description,
                "Schema '{schema_name}' description differs between paths"
            );
            assert_eq!(
                oas3_schema.default, openapiv3_schema.default,
                "Schema '{schema_name}' default differs between paths"
            );
        }

        // Compare nested property schemas
        let oas3_item = schema_object(oas3_components.schemas.get("Item").unwrap());
        let openapiv3_item = schema_object(openapiv3_components.schemas.get("Item").unwrap());
        for prop_name in ["name", "price"] {
            let oas3_prop = schema_object(oas3_item.properties.get(prop_name).unwrap());
            let openapiv3_prop = schema_object(openapiv3_item.properties.get(prop_name).unwrap());
            let oas3_example = oas3_prop.example.clone();
            let openapiv3_examples = &openapiv3_prop.examples;
            if let Some(ex) = &oas3_example {
                assert!(
                    openapiv3_examples.contains(ex),
                    "Property '{prop_name}': oas3 has example={:?} but openapiv3 examples={:?}",
                    oas3_example,
                    openapiv3_examples
                );
            }
            assert_eq!(
                oas3_prop.title, openapiv3_prop.title,
                "Property '{prop_name}' title differs between paths"
            );
        }

        // Compare parameter data
        let oas3_param = spec_via_oas3
            .paths
            .as_ref()
            .into_iter()
            .flat_map(|map| map.get("/items/{id}"))
            .flat_map(|path_item| path_item.get.as_ref())
            .flat_map(|op| op.parameters.iter())
            .filter_map(|p| p.resolve(&spec_via_oas3).ok())
            .find(|p| p.name == "id")
            .unwrap();
        let openapiv3_param = spec_via_openapiv3
            .paths
            .as_ref()
            .into_iter()
            .flat_map(|map| map.get("/items/{id}"))
            .flat_map(|path_item| path_item.get.as_ref())
            .flat_map(|op| op.parameters.iter())
            .filter_map(|p| p.resolve(&spec_via_openapiv3).ok())
            .find(|p| p.name == "id")
            .unwrap();

        assert_eq!(
            oas3_param.example, openapiv3_param.example,
            "Parameter 'id' example differs.\n  oas3: {:?}\n  openapiv3: {:?}",
            oas3_param.example, openapiv3_param.example
        );
        let oas3_param_schema = match &oas3_param.schema {
            Some(s) => schema_object(s),
            None => panic!("Expected concrete schema on id param in oas3 path"),
        };
        let openapiv3_param_schema = match &openapiv3_param.schema {
            Some(s) => schema_object(s),
            None => panic!("Expected concrete schema on id param in openapiv3 path"),
        };
        let oas3_param_example = oas3_param_schema.example.clone();
        let openapiv3_param_examples = &openapiv3_param_schema.examples;
        if let Some(ex) = &oas3_param_example {
            assert!(
                openapiv3_param_examples.contains(ex),
                "Parameter schema: oas3 has example={:?} but openapiv3 examples={:?}",
                oas3_param_example,
                openapiv3_param_examples
            );
        }
    }
}
