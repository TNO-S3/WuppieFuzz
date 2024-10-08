# Authenticating with your API server

Some API servers require authentication. At the moment, we support Bearer authentication.

You can specify your mode of authentication and the information (username and password)
required to log in, by using a command line argument of the form
`--authentication filename.yaml`.

This file should contain the configuration. See the section conforming to your mode of
authentication for guidance on its contents.

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
