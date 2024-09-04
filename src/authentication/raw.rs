/// Login configuration to be sent with each request.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RawLogin {
    pub contents: String,
}
