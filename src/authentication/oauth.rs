use anyhow::Error;

#[derive(Debug, Clone)]
pub struct Tokens {
    pub(crate) access_token: String,
    pub(crate) _refresh_token: String,
    pub(crate) _refresh_url: reqwest::Url,
    pub(crate) expiry_timestamp: u64,
}

impl Tokens {
    /// Yields the access token, attempting to refresh it if (almost) expired
    pub fn access_token(&mut self) -> Result<&str, Error> {
        if self.expires_soon() {
            // Refresh the tokens
            unimplemented!("Can't refresh oauth tokens yet")
        }
        Ok(&self.access_token)
    }

    fn expires_soon(&self) -> bool {
        let start = std::time::SystemTime::now();
        let current_timestamp = start
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        current_timestamp + 60 >= self.expiry_timestamp
    }
}
