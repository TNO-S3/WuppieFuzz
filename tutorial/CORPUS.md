# WuppieFuzz Corpus YAML Format Documentation

This document describes the structure and semantics of the YAML corpus (and crash) files used by WuppieFuzz. Each file represents one "input", and contains a sequence of HTTP requests, including methods, paths, parameters, and bodies. The format enables the fuzzer to reconstruct requests and parameters, including references to earlier requests and responses.

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

The value can be one of the following:
- A simple value:  a tag indicating the value's type (one of  `!Number`, `!String`, `!Bool` and `!Null`), followed by the contents of the value. Strings can be quoted if any special characters need to be escaped.
- Raw bytes: the tag `!RawBytes` followed by a base64 encoded value that is sent as the parameter value without interpretation.
- A reference to a value from an earlier request. This value is specified with the tag `!ReferenceToEarlierRequest`, with fields `request` and `parameter_access` specifying which value the reference refers to.
- A reference to a value from an earlier response. This value is specified with the tag `!ReferenceToEarlierResponse`, with fields `response` and `parameter_access` specifying which value the reference refers to.

### Reference Values

Parameters and body fields can reference values from earlier requests using:

```yaml
: !ReferenceToEarlierResponse
  request: <index>
  parameter_access: <parameter_access_definition>
```

This allows chaining requests and reusing values dynamically. Requests are indexed implicitly by their order in the file (starting from 0). The parameter access specifies which value in the response this reference refers to.

### Example: Primitive Parameter

```yaml
parameters:
  ? - orderId
    - Path
  : !Number 1
```

### Example: Reference Parameter

```yaml
parameters:
  ? - pet_id
    - Path
  : !ReferenceToEarlierResponse
    response: 0
    parameter_access: !Response
    	Body:
    	- !Name id
```

### Example: More complex parameter values

```yaml
parameters:
? - api_key
  - Header
: !String "?\x1FO'Sitz"
? - petId
  - Path
: !RawBytes IxEIRCIRSJw=
```

## Request Body

The `body` field describes the payload `POST` and `PUT` requests. It is annotated with a MIME type using e.g. `!ApplicationJson`.

### Example: Object Body

```yaml
body: !ApplicationJson
  id: !Number 0
  name: !String doggie
```

### Example: Array of Objects

```yaml
body: !ApplicationJson
- username !String 🎵
- password !String password123
```
