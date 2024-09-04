use std::collections::HashMap;

/// Cookies that should be present when the fuzzer starts.
/// Given as name: value, no expiration date or path
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CookieLogin {
    pub set_cookie: HashMap<String, String>,
}
