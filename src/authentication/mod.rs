use std::{borrow::Cow, fs::File, path::Path, sync::Arc};

use anyhow::{Context, Result};
use cookie_store::{Cookie, RawCookie};
use openapiv3::OpenAPI;
use reqwest::header::{HeaderMap, IntoHeaderName, AUTHORIZATION};
use url::Url;

use crate::{configuration::Configuration, header};

pub mod basic;
pub mod bearer;
pub mod cookie;
pub mod custom;
pub mod oauth;
pub mod raw;
pub mod verify_auth;

/// Authentication mode and configuration. The configuration data
/// contains the information necessary to authenticate with the server
/// (e.g. password).
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(tag = "mode", content = "configuration")]
pub enum Mode {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "raw")]
    Raw(raw::RawLogin),
    #[serde(rename = "basic")]
    Basic(basic::BasicLogin),
    #[serde(rename = "bearer")]
    Bearer(bearer::BearerLogin),
    #[serde(rename = "custom")]
    Custom(custom::CustomLogin),
    #[serde(rename = "cookie")]
    Cookie(cookie::CookieLogin),
}

/// Authentication details received after logging in. Depending on the
/// mode, this could be a header value or a cookie. It is meant to be used
/// when making requests against the API server.
#[derive(Debug, Clone)]
pub enum Authentication {
    /// No authentication at all
    None,
    /// Raw authentication; the contained value is literally inserted in the
    /// Authorization header
    Raw(String),
    /// Basic authentication; the contained value is the base64-encoded
    /// string `username:password` (with values for these loaded from config)
    Basic(String),
    /// Bearer authentication; the contained value is the access token obtained
    /// by logging in
    Bearer(String),
    /// Cookie; the contained value is an initial set of cookies
    Cookie(Vec<RawCookie<'static>>),
    /// OAuth authentication: the contained value is an access token and a
    /// refresh roken
    OAuth(oauth::Tokens),
}

/// This function uses the command line configuration to log in to the API
/// server. It produces an `Authentication` on success, which can be used
/// to configure a `reqwest::Client`.
pub fn initialize() -> Result<Authentication> {
    let clargs = Configuration::must_get();
    initialize_from_config(clargs.authentication.as_deref())
}

pub fn initialize_from_config(config_path: Option<&Path>) -> Result<Authentication> {
    let auth_mode = match config_path {
        None => Mode::None,
        Some(path) => serde_yaml::from_reader(File::open(path).with_context(|| {
            format!("Error opening file given for --authentication, which is {path:?}")
        })?)
        .with_context(|| {
            format!("Error parsing file given for --authentication, which is {path:?}")
        })?,
    };

    Ok(match auth_mode {
        Mode::None => Authentication::None,
        Mode::Raw(config) => Authentication::Raw(config.contents),
        Mode::Basic(config) => Authentication::Basic(config.header_value()),
        Mode::Bearer(config) => Authentication::Bearer(
            config
                .login()
                .context("Error during bearer authentication with the server")?,
        ),
        Mode::Custom(config) => Authentication::OAuth(
            config
                .login()
                .context("Error during custom authentication with the server")?,
        ),

        Mode::Cookie(config) => Authentication::Cookie(
            config
                .set_cookie
                .into_iter()
                .map(|(name, value)| RawCookie::new(name, value))
                .collect(),
        ),
    })
}

impl Authentication {
    /// Use the contained authentication data to configure a ClientBuilder.
    pub fn generate_headers(&mut self) -> HeaderMap {
        match self {
            Authentication::None => Default::default(),
            Authentication::Raw(text) => single_header_force(AUTHORIZATION, text),
            Authentication::Basic(config) => {
                single_header_force(AUTHORIZATION, &format!("Basic {config}"))
            }
            Authentication::Bearer(token) => {
                single_header_force(AUTHORIZATION, &format!("Bearer {token}"))
            }
            Authentication::OAuth(tokens) => {
                if let Ok(token) = tokens.access_token() {
                    single_header_force(AUTHORIZATION, token)
                } else {
                    Default::default()
                }
            }
            Authentication::Cookie(_) => Default::default(),
        }
    }

    pub fn cookie_store(&self, server_url: &Url) -> reqwest_cookie_store::CookieStore {
        match self {
            Authentication::Cookie(cookies) => {
                let cookies = cookies
                    .iter()
                    .map(|c| Cookie::try_from_raw_cookie(c, server_url));
                reqwest_cookie_store::CookieStore::from_cookies(cookies, true).unwrap_or_default()
            }
            _ => reqwest_cookie_store::CookieStore::default(),
        }
    }

    /// Return the last Autorization header value, without refreshing it if expired.
    pub fn last_header(&self) -> Option<Cow<str>> {
        match self {
            Authentication::Raw(text) => Some(Cow::from(text)),
            Authentication::Basic(config) => Some(Cow::from(format!("Basic {config}"))),
            Authentication::Bearer(token) => Some(Cow::from(format!("Bearer {token}"))),
            Authentication::OAuth(tokens) => Some(Cow::from(&tokens.access_token)),
            _ => None,
        }
    }
}

fn single_header_force<K>(key: K, value: &str) -> HeaderMap
where
    K: IntoHeaderName,
{
    let mut headers = HeaderMap::new();
    headers.insert(
        key,
        value.parse().expect("Could not build authorization header"),
    );
    headers
}

pub fn verify_authentication(api: OpenAPI) -> Result<()> {
    verify_auth::verify_auth(api)
}

/// Initializes the authentication module and cookie store and builds a Reqwest HTTP client
pub fn build_http_client() -> Result<
    (
        Authentication,
        Arc<reqwest_cookie_store::CookieStoreMutex>,
        reqwest::blocking::Client,
    ),
    anyhow::Error,
> {
    // Load auth information from the configuration
    let mut authentication = initialize()?;
    // Make a cookie jar for our client
    let cookie_store = std::sync::Arc::new(reqwest_cookie_store::CookieStoreMutex::new(
        reqwest_cookie_store::CookieStore::default(),
    ));
    // Construct a client with the authentication and static headers
    let client_builder =
        reqwest::blocking::Client::builder().cookie_provider(std::sync::Arc::clone(&cookie_store));
    let mut default_headers = authentication.generate_headers();
    default_headers.extend(header::get_default_headers()?);
    let client = client_builder.default_headers(default_headers).build()?;

    Ok((authentication, cookie_store, client))
}
