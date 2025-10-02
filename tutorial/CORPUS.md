# WuppieFuzz Corpus YAML Format Documentation

This document describes the structure and semantics of the YAML corpus files used by WuppieFuzz. Each file represents one "input", and contains a sequence of HTTP requests, including methods, paths, parameters, and bodies. The format enables the fuzzer to reconstruct requests and parameters, including references to earlier responses.

## Top-Level Structure

Each YAML file is a list of HTTP request definitions. Each request is represented as a dictionary with the following keys:

- `method`: HTTP method (e.g., `GET`, `POST`, `PUT`, `DELETE`)
- `path`: URI path, possibly containing path parameters (e.g., `/pet/{pet_id}`)
- `parameters`: Optional list of parameters, each defined using a special YAML syntax
- `body`: Optional request body, with structured data and type annotations

## Parameters

Parameters are defined using a YAML construct that allows a list to be used as a dictionary key. The syntax is:

```yaml
parameters:
  ? - <parameter_name>
    - <location>
  : <parameter_value_definition>
```

The second item in the key list specifies the parameter location, and is one of `Path`, `Query`, `Header` or `Cookie`.

### Value Definition

The value is a dictionary with:
- `DataType`: One of:
  - `PrimitiveValue`: A direct value, annotated by its type e.g. `!Number`, `!String`.
  - `ReferenceToEarlierResponse`: A reference to a value from a previous request
- `Contents`: The actual value or reference details

### Reference Values

Parameters and body fields can reference values from earlier requests using:

```yaml
DataType: ReferenceToEarlierResponse
Contents:
  request: <index>
  parameter_name: <name>
```

This allows chaining requests and reusing values dynamically. Requests are indexed implicitly by their order in the file (starting from 0). The parameter name is the name of the field you want to use, as it appears in the response body of the referenced request.

### Example: Primitive Parameter

```yaml
parameters:
  ? - orderId
    - Path
  : DataType: PrimitiveValue
    Contents: !Number 1
```

### Example: Reference Parameter

```yaml
parameters:
  ? - pet_id
    - Path
  : DataType: ReferenceToEarlierResponse
    Contents:
      request: 0
      parameter_name: id
```

## Request Body

The `body` field describes the payload for methods like `POST` and `PUT`. It includes:

- `DataType`: One of `Object`, `Array`, or `PrimitiveValue`
- `Contents`: Nested structure of fields and values

The body is annotated with a MIME type using e.g. `!ApplicationJson`.

### Example: Object Body

```yaml
body: !ApplicationJson
  DataType: Object
  Contents:
    id:
      DataType: PrimitiveValue
      Contents: !Number 0
    name:
      DataType: PrimitiveValue
      Contents: !String doggie
```

### Example: Array of Objects

```yaml
body: !ApplicationJson
  DataType: Array
  Contents:
    - DataType: Object
      Contents:
        username:
          DataType: PrimitiveValue
          Contents: !String 🎵
```
