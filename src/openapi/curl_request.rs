use base64::{display::Base64Display, engine::general_purpose::STANDARD};

pub struct CurlRequest<'a>(
    pub &'a reqwest::blocking::Request,
    pub &'a crate::authentication::Authentication,
);

impl<'a> CurlRequest<'a> {
    /// Gives the URL of this request (the path, but with all path and query
    /// parameters filled)
    pub fn url(&self) -> &str {
        self.0.url().as_str()
    }

    /// Gives the body of this request as byteslice
    pub fn body(&self) -> Option<&[u8]> {
        self.0.body().and_then(reqwest::blocking::Body::as_bytes)
    }
}

impl<'a> std::fmt::Display for CurlRequest<'a> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Some(body) = self.0.body() {
            let wrapper = Base64Display::new(
                body.as_bytes()
                    .expect("stream body not expected from static request"),
                &STANDARD,
            );
            writeln!(fmt, "echo {} | \\", wrapper)?;
            writeln!(fmt, "base64 --decode | \\")?;
        }

        write!(fmt, "curl {}", self.0.url())?;
        write!(fmt, " \\\n    --request {}", self.0.method())?;
        if let Some(token) = self.1.last_header() {
            write!(fmt, " \\\n    --header 'Authorization: {token}'")?;
        }
        for (key, value) in self.0.headers() {
            if let Ok(text) = value.to_str() {
                write!(fmt, " \\\n    --header '{}: {}'", key, text)?
            } else {
                write!(
                    fmt,
                    " \\\n    --header \"{}: $(echo -n {} | base64 --decode)\"",
                    key,
                    Base64Display::new(value.as_bytes(), &STANDARD)
                )?
            }
        }
        if self.0.body().is_some() {
            write!(fmt, " \\\n    --data @-")?;
        }
        Ok(())
    }
}
