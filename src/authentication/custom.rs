use super::oauth;

/// Instructions for a custom request to an authentication server.
/// The response is expected to be a json object with the following
/// fields:
///
/// "accessToken" - contains the (OAuth) access token
/// "refreshToken" - contains the refresh token
/// "authentication" / "payload" / "exp": contains a unix timestamp
/// at which the access token expires.
///
/// The .login() method yields an OAuth authentication object.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CustomLogin {
    /// URL to send an authentication request to
    url: String,
    /// The request body can be any valid value or object, and it will be
    /// serialized to JSON to make the authentication request.
    // It's not a bug: you can deserialize from yaml into a json value!
    request_body: serde_json::Value,
}
#[derive(Debug, Clone, serde::Deserialize)]
struct Response {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "refreshToken")]
    refresh_token: String,
    authentication: Authentication,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct Authentication {
    payload: Payload,
}
#[derive(Debug, Clone, serde::Deserialize)]
struct Payload {
    // Expiry Unix timestamp
    exp: u64,
}

impl CustomLogin {
    pub fn login(self) -> anyhow::Result<oauth::Tokens> {
        let client = reqwest::blocking::Client::new();
        let response: Response = client
            .post(&self.url)
            .json(&self.request_body)
            .header("User-Agent", "wuppiefuzz/0.1.0")
            .send()?
            .json()?;

        Ok(oauth::Tokens {
            access_token: response.access_token,
            refresh_token: response.refresh_token,
            refresh_url: self.url,
            access_expiry_timestamp: response.authentication.payload.exp,
            mode: oauth::Mode::AuthorizationHeader,
        })
    }
}
