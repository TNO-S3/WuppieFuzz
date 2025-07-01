use base64::{Engine as _, engine::general_purpose::STANDARD as base64};

/// Login configuration to be sent with each request.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BasicLogin {
    username: String,
    password: String,
}

impl BasicLogin {
    /// Constructs the Authorization header value using the contained
    /// information, by base64-encoding the string `username:password`.
    pub fn header_value(self) -> String {
        base64.encode(format!("{}:{}", self.username, self.password).as_bytes())
    }
}
