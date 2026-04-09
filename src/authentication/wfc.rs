//! Support for the Web Fuzzing Commons (WFC) authentication file format.
//! See: https://github.com/WebFuzzing/Commons

use anyhow::{Context, Result, anyhow, bail};
use reqwest_cookie_store::RawCookie;
use serde::Deserialize;

use super::Authentication;

/// Top-level WFC authentication document
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WfcAuth {
    pub auth: Vec<AuthenticationInfo>,
    #[serde(default)]
    pub auth_template: Option<AuthenticationInfo>,
}

/// AuthenticationInfo represents a single authentication entry in the WFC auth file.
/// It can specify either fixed headers (e.g. a static Authorization header) or a
/// login endpoint to obtain a token/cookie.
/// AuthenticationInfo should not contain both fixed_headers and login_endpoint_auth;
/// if both are present, fixed_headers takes precedence.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationInfo {
    pub name: Option<String>,
    #[serde(default)]
    pub fixed_headers: Option<Vec<Header>>,
    #[serde(default)]
    pub login_endpoint_auth: Option<PartialLoginEndpoint>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// A `LoginEndpoint` where all fields are optional so that partial entries can
/// be deserialized and then merged with the `authTemplate` before use.
/// Call [`PartialLoginEndpoint::merge`] to combine an entry with a template, and
/// [`PartialLoginEndpoint::resolve`] to obtain a fully-populated [`LoginEndpoint`].
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct PartialLoginEndpoint {
    pub endpoint: Option<String>,
    pub external_endpoint_url: Option<String>,
    pub payload_raw: Option<String>,
    pub payload_user_pwd: Option<PayloadUsernamePassword>,
    #[serde(default)]
    pub headers: Option<Vec<Header>>,
    pub verb: Option<HttpVerb>,
    pub content_type: Option<String>,
    pub token: Option<TokenHandling>,
    #[serde(default)]
    pub expect_cookies: Option<bool>,
}

impl PartialLoginEndpoint {
    /// Merge `self` (entry) with `template`, with `self` taking precedence for
    /// every field that is `Some`.
    fn merge(self, template: PartialLoginEndpoint) -> PartialLoginEndpoint {
        PartialLoginEndpoint {
            endpoint: self.endpoint.or(template.endpoint),
            external_endpoint_url: self
                .external_endpoint_url
                .or(template.external_endpoint_url),
            payload_raw: self.payload_raw.or(template.payload_raw),
            payload_user_pwd: self.payload_user_pwd.or(template.payload_user_pwd),
            headers: self.headers.or(template.headers),
            verb: self.verb.or(template.verb),
            content_type: self.content_type.or(template.content_type),
            token: self.token.or(template.token),
            expect_cookies: self.expect_cookies.or(template.expect_cookies),
        }
    }

    /// Resolve into a [`LoginEndpoint`], returning an error if any required
    /// fields are still missing after merging.
    fn resolve(self, entry_name: &str) -> Result<LoginEndpoint> {
        Ok(LoginEndpoint {
            endpoint: self.endpoint,
            external_endpoint_url: self.external_endpoint_url,
            payload_raw: self.payload_raw,
            payload_user_pwd: self.payload_user_pwd,
            headers: self.headers,
            verb: self.verb.ok_or_else(|| {
                anyhow!(
                    "WFC authentication entry '{entry_name}' loginEndpointAuth is missing \
                     required field 'verb' (not set in entry or authTemplate)"
                )
            })?,
            content_type: self.content_type,
            token: self.token,
            expect_cookies: self.expect_cookies,
        })
    }
}

/// A fully resolved login endpoint, ready to use for making a login request.
/// Obtain this via [`PartialLoginEndpoint::resolve`].
pub struct LoginEndpoint {
    pub endpoint: Option<String>,
    pub external_endpoint_url: Option<String>,
    pub payload_raw: Option<String>,
    pub payload_user_pwd: Option<PayloadUsernamePassword>,
    pub headers: Option<Vec<Header>>,
    pub verb: HttpVerb,
    pub content_type: Option<String>,
    pub token: Option<TokenHandling>,
    pub expect_cookies: Option<bool>,
}

/// TokenHandling specifies how the login token is extracted from the login
/// response and how it is sent in subsequent requests.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TokenHandling {
    /// Extract the token from either a response header or the response body (JSON).
    pub extract_from: ExtractFrom,

    /// If ExtractFrom::Header, the name of the header to extract the token from.
    /// If ExtractFrom::Body, a JSON Pointer (RFC 6901) to the token in the
    /// response body.
    pub extract_selector: String,

    /// Where to send the token in subsequent requests.
    pub send_in: SendIn,

    /// The name to send the token under (e.g. the header name or query parameter name).
    pub send_name: String,

    /// A template for how to send the token. The default template just produces a
    /// string containing the token. This can be used to add prefixes/suffixes to the
    /// token, e.g. "Bearer {token}".
    #[serde(default = "default_send_template")]
    pub send_template: String,
}

// The default template just produces a string containing the token
fn default_send_template() -> String {
    "{token}".to_string()
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ExtractFrom {
    Body,
    Header,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SendIn {
    Header,
    Query,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HttpVerb {
    Post,
    Get,
    Patch,
    Delete,
    Put,
}

/// The PayloadUsernamePassword struct represents the username and password
/// fields for a WFC login endpoint that uses username/password authentication.
/// It includes the field names to allow flexible mapping to different API
/// requirements. Username and password are sent as `{"username_field":
/// "username", "password_field": "password"}` or the URL-encoded equivalent.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PayloadUsernamePassword {
    pub username: String,
    pub password: String,
    pub username_field: String,
    pub password_field: String,
}

impl WfcAuth {
    /// Convert a WFC auth config into an `Authentication`.
    ///
    /// Uses the first entry in the `auth` list, merging in the `authTemplate`
    /// for any fields that are not set on the entry itself.
    pub fn into_authentication(self) -> Result<Authentication> {
        let template = self.auth_template;
        let entry = self
            .auth
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("WFC authentication file has an empty 'auth' list"))?;

        // Merge template into entry (entry fields take precedence)
        let fixed_headers = entry
            .fixed_headers
            .or_else(|| template.as_ref().and_then(|t| t.fixed_headers.clone()));

        let partial_login_endpoint = {
            let entry_partial = entry.login_endpoint_auth.unwrap_or_default();
            let template_partial = template
                .and_then(|t| t.login_endpoint_auth)
                .unwrap_or_default();
            entry_partial.merge(template_partial)
        };

        // Check whether there is any login endpoint configuration at all
        let has_login_endpoint = partial_login_endpoint.verb.is_some()
            || partial_login_endpoint.endpoint.is_some()
            || partial_login_endpoint.external_endpoint_url.is_some();

        match (fixed_headers, has_login_endpoint) {
            // Static fixed headers take precedence — look for Authorization header
            (Some(headers), _) => {
                let auth_header = headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("Authorization"))
                    .ok_or_else(|| {
                        anyhow!(
                            "WFC authentication entry '{}' has fixedHeaders but no \
                             'Authorization' header. Only Authorization header authentication \
                             is currently supported for fixedHeaders.",
                            entry.name.unwrap_or_else(|| "<unnamed>".to_string())
                        )
                    })?;
                let value = &auth_header.value;
                if let Some(token) = value.strip_prefix("Bearer ") {
                    Ok(Authentication::Bearer(token.to_string()))
                } else if let Some(encoded) = value.strip_prefix("Basic ") {
                    Ok(Authentication::Basic(encoded.to_string()))
                } else {
                    Ok(Authentication::Raw(value.clone()))
                }
            }

            // Login endpoint — perform a login request and extract the token/cookie
            (None, true) => {
                if let Some(name) = &entry.name {
                    let endpoint = partial_login_endpoint.resolve(name)?;
                    login_with_endpoint(name, endpoint)
                } else {
                    Err(anyhow!(
                        "WFC authentication entry with loginEndpointAuth is missing \
                        'name' field, which is required to perform the login request"
                    ))
                }
            }

            (None, false) => Ok(Authentication::None),
        }
    }
}

/// Perform the login request described by a WFC `LoginEndpoint` and return the
/// resulting `Authentication`.
fn login_with_endpoint(name: &str, endpoint: LoginEndpoint) -> Result<Authentication> {
    let url = endpoint
        .external_endpoint_url
        .as_deref()
        .or(endpoint.endpoint.as_deref())
        .ok_or_else(|| {
            anyhow!(
                "WFC authentication entry '{name}' loginEndpointAuth has neither \
                 'endpoint' nor 'externalEndpointURL'"
            )
        })?
        .to_string();

    let client = reqwest::blocking::Client::new();

    let content_type = endpoint
        .content_type
        .as_deref()
        .unwrap_or("application/json")
        .to_string();

    // Build request body
    let body: Option<String> = if let Some(raw) = endpoint.payload_raw {
        Some(raw)
    } else if let Some(pwd) = endpoint.payload_user_pwd {
        Some(build_payload(&pwd, &content_type)?)
    } else {
        None
    };

    let mut request = match endpoint.verb {
        HttpVerb::Post => client.post(&url),
        HttpVerb::Get => client.get(&url),
        HttpVerb::Put => client.put(&url),
        HttpVerb::Patch => client.patch(&url),
        HttpVerb::Delete => client.delete(&url),
    };

    request = request.header(reqwest::header::CONTENT_TYPE, &content_type);

    // Add any extra headers
    if let Some(headers) = endpoint.headers {
        for h in headers {
            request = request.header(&h.name, &h.value);
        }
    }

    if let Some(body) = body {
        request = request.body(body);
    }

    let response = request
        .send()
        .with_context(|| format!("Error calling WFC login endpoint '{url}'"))?;

    if !response.status().is_success() {
        bail!(
            "WFC login endpoint '{url}' returned non-success status: {}",
            response.status()
        );
    }

    // Cookie-based auth
    if endpoint.expect_cookies.unwrap_or(false) {
        let cookies: Vec<RawCookie<'static>> = response
            .cookies()
            .map(|c| RawCookie::new(c.name().to_owned(), c.value().to_owned()))
            .collect();
        return Ok(Authentication::Cookie(cookies));
    }

    // Token-based auth
    let token_handling = endpoint.token.ok_or_else(|| {
        anyhow!(
            "WFC authentication entry '{name}' loginEndpointAuth has neither \
             'expectCookies: true' nor a 'token' extraction configuration"
        )
    })?;

    let token = extract_token(&token_handling, response)
        .with_context(|| format!("Failed to extract token for WFC auth entry '{name}'"))?;

    let header_value = token_handling.send_template.replace("{token}", &token);

    match token_handling.send_in {
        SendIn::Header
            if token_handling
                .send_name
                .eq_ignore_ascii_case("Authorization") =>
        {
            if let Some(bearer) = header_value.strip_prefix("Bearer ") {
                Ok(Authentication::Bearer(bearer.to_string()))
            } else if let Some(basic) = header_value.strip_prefix("Basic ") {
                Ok(Authentication::Basic(basic.to_string()))
            } else {
                Ok(Authentication::Raw(header_value))
            }
        }
        SendIn::Header => {
            // Non-Authorization header: store as Raw so it can be inserted
            Ok(Authentication::Raw(header_value))
        }
        SendIn::Query => {
            bail!(
                "WFC authentication entry '{name}' uses sendIn=query, \
                 which is not yet supported"
            )
        }
    }
}

/// Build a request body from username/password for common content types.
fn build_payload(payload: &PayloadUsernamePassword, content_type: &str) -> Result<String> {
    if content_type.contains("application/json") {
        Ok(format!(
            r#"{{"{username_field}":"{username}","{password_field}":"{password}"}}"#,
            username_field = payload.username_field,
            username = payload.username,
            password_field = payload.password_field,
            password = payload.password,
        ))
    } else if content_type.contains("application/x-www-form-urlencoded") {
        Ok(format!(
            "{}={}&{}={}",
            urlencoding::encode(&payload.username_field),
            urlencoding::encode(&payload.username),
            urlencoding::encode(&payload.password_field),
            urlencoding::encode(&payload.password),
        ))
    } else {
        bail!(
            "Unsupported content type '{content_type}' for WFC payloadUserPwd. \
             Supported types: application/json, application/x-www-form-urlencoded"
        )
    }
}

/// Extract a token string from the login response according to `TokenHandling`.
fn extract_token(
    handling: &TokenHandling,
    response: reqwest::blocking::Response,
) -> Result<String> {
    match handling.extract_from {
        ExtractFrom::Header => {
            let header_value = response
                .headers()
                .get(&handling.extract_selector)
                .ok_or_else(|| {
                    anyhow!(
                        "Response did not contain expected header '{}'",
                        handling.extract_selector
                    )
                })?
                .to_str()
                .context("Header value is not valid UTF-8")?
                .to_string();
            Ok(header_value)
        }
        ExtractFrom::Body => {
            let body: serde_json::Value = response
                .json()
                .context("Failed to parse login response body as JSON")?;
            // extract_selector is a JSON Pointer (RFC 6901)
            let pointer = &handling.extract_selector;
            let value = body.pointer(pointer).ok_or_else(|| {
                anyhow!(
                    "JSON Pointer '{}' did not match anything in the login response body",
                    pointer
                )
            })?;
            let token = value
                .as_str()
                .ok_or_else(|| anyhow!("Value at JSON Pointer '{}' is not a string", pointer))?
                .to_string();
            Ok(token)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // spring-actuator-demo-auth.yaml
    // Fixed Authorization header with a Basic token.
    // -------------------------------------------------------------------------
    const SPRING_ACTUATOR_DEMO_AUTH: &str = r#"
auth:
  - name: admin
    fixedHeaders:
      - name: Authorization
        value: Basic YWN0dWF0b3I6YWN0dWF0b3I=
"#;

    // -------------------------------------------------------------------------
    // scout-api-auth.yaml
    // Fixed Authorization header with a custom ApiKey scheme (maps to Raw).
    // Only the first entry is used.
    // -------------------------------------------------------------------------
    const SCOUT_API_AUTH: &str = r#"
auth:
  - name: user
    fixedHeaders:
      - name: Authorization
        value: ApiKey user
  - name: moderator
    fixedHeaders:
      - name: Authorization
        value: ApiKey moderator
  - name: administrator
    fixedHeaders:
      - name: Authorization
        value: ApiKey administrator
"#;

    // -------------------------------------------------------------------------
    // blogapi-auth.yaml
    // Login endpoint (POST /api/auth/signin), token extracted from JSON body,
    // sent as Bearer in Authorization header.
    // -------------------------------------------------------------------------
    const BLOGAPI_AUTH_TEMPLATE: &str = r#"
auth:
  - name: admin
    loginEndpointAuth:
      payloadRaw: "{\"usernameOrEmail\": \"admin\", \"password\": \"bar123\"}"
  - name: user
    loginEndpointAuth:
      payloadRaw: "{\"usernameOrEmail\": \"user\", \"password\": \"bar123\"}"

authTemplate:
    loginEndpointAuth:
        endpoint: /api/auth/signin
        verb: POST
        contentType: application/json
        token:
            extractFrom: body
            extractSelector: /accessToken
            sendName: Authorization
            sendIn: header
            sendTemplate: "Bearer {token}"
"#;

    // -------------------------------------------------------------------------
    // tracking-system-auth.yaml
    // Login endpoint (POST /app/login), expects cookies in response.
    // -------------------------------------------------------------------------
    const TRACKING_SYSTEM_AUTH_TEMPLATE: &str = r#"
auth:
  - name: ROLE_ADMIN
    loginEndpointAuth:
      payloadRaw: "username=admin&password=test"
  - name: ROLE_EMP
    loginEndpointAuth:
      payloadRaw: "username=selimhorri&password=test"
  - name: ROLE_MGR
    loginEndpointAuth:
      payloadRaw: "username=soumayahajjem&password=test"

authTemplate:
  loginEndpointAuth:
    endpoint: /app/login
    verb: POST
    contentType: application/x-www-form-urlencoded
    expectCookies: true
"#;

    fn parse(yaml: &str) -> WfcAuth {
        serde_yaml::from_str(yaml).expect("Failed to parse WFC YAML")
    }

    // --- Parsing tests (no HTTP) ---------------------------------------------

    #[test]
    fn spring_actuator_parses_to_basic() {
        let auth = parse(SPRING_ACTUATOR_DEMO_AUTH)
            .into_authentication()
            .unwrap();
        assert!(
            matches!(auth, Authentication::Basic(ref s) if s == "YWN0dWF0b3I6YWN0dWF0b3I="),
            "Expected Basic(...), got {auth:?}"
        );
    }

    #[test]
    fn scout_api_parses_to_raw_first_entry() {
        let auth = parse(SCOUT_API_AUTH).into_authentication().unwrap();
        assert!(
            matches!(auth, Authentication::Raw(ref s) if s == "ApiKey user"),
            "Expected Raw(\"ApiKey user\"), got {auth:?}"
        );
    }

    #[test]
    fn spring_actuator_has_one_auth_entry() {
        let wfc = parse(SPRING_ACTUATOR_DEMO_AUTH);
        assert_eq!(wfc.auth.len(), 1);
        assert_eq!(wfc.auth[0].name.as_deref(), Some("admin"));
    }

    #[test]
    fn scout_api_has_three_auth_entries() {
        let wfc = parse(SCOUT_API_AUTH);
        assert_eq!(wfc.auth.len(), 3);
        assert_eq!(wfc.auth[0].name.as_deref(), Some("user"));
        assert_eq!(wfc.auth[1].name.as_deref(), Some("moderator"));
        assert_eq!(wfc.auth[2].name.as_deref(), Some("administrator"));
    }

    #[test]
    fn blogapi_has_two_entries_and_template() {
        let wfc = parse(BLOGAPI_AUTH_TEMPLATE);
        assert_eq!(wfc.auth.len(), 2);
        assert_eq!(wfc.auth[0].name.as_deref(), Some("admin"));
        assert_eq!(wfc.auth[1].name.as_deref(), Some("user"));
        assert!(wfc.auth_template.is_some());

        let template = wfc.auth_template.unwrap();
        let endpoint = template.login_endpoint_auth.unwrap();
        assert_eq!(endpoint.endpoint.as_deref(), Some("/api/auth/signin"));
        let token = endpoint.token.unwrap();
        assert_eq!(token.extract_selector, "/accessToken");
        assert_eq!(token.send_name, "Authorization");
        assert_eq!(token.send_template, "Bearer {token}");
        assert_eq!(token.send_in, SendIn::Header);
        assert_eq!(token.extract_from, ExtractFrom::Body);
    }

    #[test]
    fn tracking_system_has_three_entries_and_template() {
        let wfc = parse(TRACKING_SYSTEM_AUTH_TEMPLATE);
        assert_eq!(wfc.auth.len(), 3);
        assert_eq!(wfc.auth[0].name, Some(String::from("ROLE_ADMIN")));
        assert!(wfc.auth_template.is_some());

        let template = wfc.auth_template.unwrap();
        let endpoint = template.login_endpoint_auth.unwrap();
        assert_eq!(endpoint.endpoint.as_deref(), Some("/app/login"));
        assert_eq!(endpoint.expect_cookies, Some(true));
    }

    // --- Integration tests (mock HTTP server) --------------------------------

    #[test]
    fn blogapi_login_endpoint_produces_bearer() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/api/auth/signin")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"accessToken":"my-secret-token"}"#)
            .create();

        // Patch the endpoint URL to point at the mock server
        let yaml = BLOGAPI_AUTH_TEMPLATE.replace(
            "endpoint: /api/auth/signin",
            &format!("endpoint: {}/api/auth/signin", server.url()),
        );

        let auth = parse(&yaml).into_authentication().unwrap();
        mock.assert();
        assert!(
            matches!(auth, Authentication::Bearer(ref t) if t == "my-secret-token"),
            "Expected Bearer(\"my-secret-token\"), got {auth:?}"
        );
    }

    #[test]
    fn tracking_system_login_endpoint_produces_cookies() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/app/login")
            .with_status(200)
            .with_header("Set-Cookie", "JSESSIONID=abc123; Path=/; HttpOnly")
            .with_body("")
            .create();

        let yaml = TRACKING_SYSTEM_AUTH_TEMPLATE.replace(
            "endpoint: /app/login",
            &format!("endpoint: {}/app/login", server.url()),
        );

        let auth = parse(&yaml).into_authentication().unwrap();
        mock.assert();
        assert!(
            matches!(auth, Authentication::Cookie(ref cookies) if
                cookies.iter().any(|c| c.name() == "JSESSIONID" && c.value() == "abc123")
            ),
            "Expected Cookie with JSESSIONID=abc123, got {auth:?}"
        );
    }

    #[test]
    fn login_endpoint_returns_error_on_non_success_status() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/api/auth/signin")
            .with_status(401)
            .with_body("Unauthorized")
            .create();

        let yaml = BLOGAPI_AUTH_TEMPLATE.replace(
            "endpoint: /api/auth/signin",
            &format!("endpoint: {}/api/auth/signin", server.url()),
        );

        let result = parse(&yaml).into_authentication();
        mock.assert();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("401"));
    }

    #[test]
    fn login_endpoint_returns_error_when_json_pointer_missing() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/api/auth/signin")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"someOtherField":"value"}"#)
            .create();

        let yaml = BLOGAPI_AUTH_TEMPLATE.replace(
            "endpoint: /api/auth/signin",
            &format!("endpoint: {}/api/auth/signin", server.url()),
        );

        let result = parse(&yaml).into_authentication();
        mock.assert();
        assert!(result.is_err());
        assert!(
            format!("{:?}", result.unwrap_err()).contains("/accessToken"),
            "Error should mention the missing JSON pointer"
        );
    }
}
