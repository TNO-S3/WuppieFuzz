use std::collections::HashMap;

/// Login configuration to be used to acquire the Bearer token.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BearerLogin {
    url: String,
    username: String,
    password: String,
    scope: Option<String>,
    client_id: Option<String>,
    response_type: Option<String>,
}

/// A result of a successful bearer login. Contains the access token.
#[derive(Debug, Clone, serde::Deserialize)]
struct BearerResponse {
    access_token: String,
}

impl BearerLogin {
    /// Uses the login configuration to attempt to log in to the server.
    pub fn login(self) -> Result<String, reqwest::Error> {
        let mut form_data = HashMap::from([
            ("grant_type", "password".to_owned()),
            ("username", self.username.clone()),
            ("password", self.password.clone()),
        ]);
        if self.scope.is_some() {
            form_data.insert("scope", self.scope.clone().unwrap());
        }
        if self.client_id.is_some() {
            form_data.insert("client_id", self.client_id.clone().unwrap());
        }
        if self.response_type.is_some() {
            form_data.insert("response_type", self.response_type.clone().unwrap());
        }
        let client = reqwest::blocking::Client::new();
        let response: BearerResponse = client.post(self.url).form(&form_data).send()?.json()?;
        Ok(response.access_token)
    }
}
