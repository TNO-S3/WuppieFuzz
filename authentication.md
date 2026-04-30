# Authenticating with your API server

Some API servers require authentication. At the moment, we support Bearer authentication.

You can specify your mode of authentication and the information (username and password)
required to log in, by using a command line argument of the form
`--authentication filename.yaml`.

This file should contain the configuration. See the section conforming to your mode of
authentication for guidance on its contents.

> [!WARNING]  
> If you have a logout endpoint in your API, the fuzzer will try to access it and possibly
> invalidate its authentication. We recommend removing such endpoints from the specifiation
> for the fuzzing run.

## Bearer authentication

For bearer authentication, a POST request is made to a login endpoint with a username
and password given in the request body. You can use Bearer authentication by providing
a yaml file with the following structure:

```yaml
mode: bearer
configuration:
  url: http://localhost:8081/login
  username: AdaLovelace
  password: VeryStr0ngPa$sw0rd
  scope: "first second"  # optional
  client_id: "my.client.id"  # optional
  response_type: "code id_token token"  # optional
```

## Custom authentication

If you need to work with some homebrew authentication method for which you need to send a specific request body, this is for you. The response must be in JSON-format and contain (among other things) an `access_token` (typically a JWT) which will be sent in the `AUTHORIZATION` header of subsequent requests.

```yaml
mode: custom
configuration:
  url: https://api.some-domain.io/authentication
  request_body:
    strategy: local
    email: jan.klaassen@tno.nl
    password: 12345
```

## Cookie authentication

If you know a valid session cookie that the fuzzer can use to start fuzzing, you can provide it as follows. Multiple cookies can be given.

```yaml
mode: cookie
configuration:
  set_cookie:
    XSRF-TOKEN: eyHEREisSOMENICEbase64JSONobject=
    lazarus-token: something
```

## OAuth authentication

Wuppiefuzz supports OAuth authentication. You can configure it as shown below.

The username and password are sent (as a POST body) to the `access_url` endpoint, which should then supply the access and refresh tokens by setting a cookie.

The access token is parsed under the assumption that it is a JWT, and the expiry timestamp is checked before each request the fuzzer makes. If the access token is about to expire, the `refresh_url` endpoint is sent a POST request with an empty body, and the tokens as cookies. It should set a new `access_token` cookie.

```yaml
mode: oauth
configuration:
  access_url: http://localhost:8081/token
  refresh_url: http://localhost:8081/token/refresh
  username: AdaLovelace
  password: VeryStr0ngPa$sw0rd
  extra_headers:
    - name: Referrer
      value: http://localhost:8081/
    - name: ClientID
      value: 1234abcd
  mode: Cookie
```

The `mode` parameter can be set to `cookie`, if the access token should be sent as a cookie with each request, or `authorization_header`, if it should be a Bearer token. Refreshing is done via cookie in both cases.

## Web Fuzzing Commons (WFC) authentication

WuppieFuzz also supports the [Web Fuzzing Commons (WFC) authentication file format](https://github.com/WebFuzzing/Commons), a community standard for describing API authentication. WFC files are automatically detected by the presence of an `auth` key at the top level, so no additional flags are needed.

WFC files support multiple named users; WuppieFuzz will use the first entry in the `auth` list.

### Static header authentication

If you already have a token or API key, you can provide it as a fixed `Authorization` header. The value is interpreted as Bearer, Basic, or raw depending on its prefix.

```yaml
# WFC format — static Authorization header
schemaVersion: "0.2.0"
auth:
  - name: admin
    fixedHeaders:
      - name: Authorization
        value: Basic YWRtaW46cGFzc3dvcmQ=
```

```yaml
# WFC format — API key
schemaVersion: "0.2.0"
auth:
  - name: user
    fixedHeaders:
      - name: Authorization
        value: ApiKey my-api-key
```

### Login endpoint — token in response body

If the server issues a token via a login endpoint, use `loginEndpointAuth`. An `authTemplate` can hold shared fields so they do not need to be repeated for each user.

```yaml
# WFC format — POST to a login endpoint, extract Bearer token from JSON response
schemaVersion: "0.2.0"
auth:
  - name: admin
    loginEndpointAuth:
      payloadRaw: '{"usernameOrEmail": "admin", "password": "s3cr3t"}'
  - name: regular-user
    loginEndpointAuth:
      payloadRaw: '{"usernameOrEmail": "user", "password": "s3cr3t"}'

authTemplate:
  loginEndpointAuth:
    endpoint: /api/auth/signin
    verb: POST
    contentType: application/json
    token:
      extractFrom: body
      extractSelector: /accessToken   # JSON Pointer (RFC 6901) into the response body
      sendIn: header
      sendName: Authorization
      sendTemplate: "Bearer {token}"
```

### Login endpoint — cookie-based session

If the server authenticates via cookies, set `expectCookies: true` instead of providing a `token` block.

```yaml
# WFC format — POST to a login endpoint, use cookies from the response
schemaVersion: "0.2.0"
auth:
  - name: admin
    loginEndpointAuth:
      payloadRaw: "username=admin&password=s3cr3t"

authTemplate:
  loginEndpointAuth:
    endpoint: /app/login
    verb: POST
    contentType: application/x-www-form-urlencoded
    expectCookies: true
```

> [!NOTE]
> WuppieFuzz supports WFC schema version `0.2.0`. Files declaring a newer
> `schemaVersion` will still be parsed, but a warning will be emitted.
