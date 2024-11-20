use anyhow::{Context, Error};
use base64::{engine::general_purpose::STANDARD as base64, Engine as _};
use itertools::Itertools;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, SET_COOKIE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, serde::Deserialize)]
struct Header {
    name: String,
    value: String,
}

#[derive(Debug, Clone, serde::Deserialize, PartialEq)]
pub(crate) enum Mode {
    AuthorizationHeader,
    Cookie,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct OauthLogin {
    username: String,
    password: String,
    access_url: String,
    refresh_url: String,
    extra_headers: Vec<Header>,
    mode: Mode,
}

impl OauthLogin {
    /// Logs in using the data from the configuration, and extracts the jwt tokens
    /// access_token and refresh_token from the cookies in the response
    pub fn login(self) -> anyhow::Result<Tokens> {
        let mut body = HashMap::new();
        body.insert("username", self.username);
        body.insert("password", self.password);

        let mut headers = HeaderMap::new();
        for header in self.extra_headers {
            headers.insert(
                HeaderName::from_bytes(header.name.as_bytes())?,
                HeaderValue::from_bytes(header.value.as_bytes())?,
            );
        }

        let client = reqwest::blocking::Client::new();
        let response = client
            .post(self.access_url)
            .json(&body)
            .header("User-Agent", "wuppiefuzz/0.1.0")
            .headers(headers)
            .send()?;

        let cookies: HashMap<&str, &str> = extract_cookies_from_response(&response);

        let access_token = cookies.get("access_token").ok_or(anyhow!(
            "No access token in the cookies in the authentication response"
        ))?;
        let refresh_token = cookies.get("refresh_token").ok_or(anyhow!(
            "No refresh token in the cookies in the authentication response"
        ))?;
        let access_expiry_timestamp = extract_expiry(access_token)? as u64;

        Ok(Tokens {
            access_token: access_token.to_string(),
            refresh_token: refresh_token.to_string(),
            access_expiry_timestamp,
            refresh_url: self.refresh_url,
            mode: self.mode,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Tokens {
    pub(crate) access_token: String,
    pub(crate) refresh_token: String,
    pub(crate) refresh_url: String,
    pub(crate) access_expiry_timestamp: u64,
    pub(crate) mode: Mode,
}

impl Tokens {
    /// Yields the access token, attempting to refresh it if (almost) expired
    pub fn access_token(&mut self) -> Result<String, Error> {
        if self.expires_soon() {
            self.refresh()?;
        }
        Ok(self.access_token.to_owned())
    }
    pub fn refresh_token(&mut self) -> Result<String, Error> {
        Ok(self.refresh_token.to_owned())
    }

    fn expires_soon(&self) -> bool {
        let start = std::time::SystemTime::now();
        let current_timestamp = start
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        current_timestamp + 10 >= self.access_expiry_timestamp
    }

    fn refresh(&mut self) -> Result<(), Error> {
        let client = reqwest::blocking::Client::new();
        let response = client
            .post(self.refresh_url.clone())
            .json(&HashMap::<String, String>::new())
            .header("User-Agent", "wuppiefuzz/0.1.0")
            .header(
                "Cookie",
                format!(
                    "access_token={}; refresh_token={}",
                    self.access_token, self.refresh_token
                ),
            )
            .send()?;

        let cookies = extract_cookies_from_response(&response);

        let access_token = cookies.get("access_token").ok_or(anyhow!(
            "No access token in the cookies in the authentication response"
        ))?;
        let access_expiry_timestamp = extract_expiry(access_token)? as u64;

        self.access_token = access_token.to_string();
        self.access_expiry_timestamp = access_expiry_timestamp;
        Ok(())
    }
}

fn extract_cookies_from_response(response: &reqwest::blocking::Response) -> HashMap<&str, &str> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|header_value| header_value.to_str().ok())
        .filter_map(|cookie_data| cookie_data.split(";").next())
        .filter_map(|cookie_keyval| cookie_keyval.split("=").next_tuple())
        .collect()
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: usize, // Expiration time (as a timestamp)
}

fn decode_base64_url(data: &str) -> Result<Vec<u8>, Error> {
    let mut base64_data = data.replace('-', "+").replace('_', "/");
    while base64_data.len() % 4 != 0 {
        base64_data.push('=');
    }
    base64
        .decode(base64_data)
        .context("Decoding JWT token from base64")
}

fn extract_expiry(jwt_token: &str) -> Result<usize, Error> {
    let parts: Vec<&str> = jwt_token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!(
            "Invalid JWT format, expected three components separated by periods"
        ));
    }

    let payload = decode_base64_url(parts[1])?;
    let claims: Claims = serde_json::from_slice(&payload)?;
    Ok(claims.exp)
}
