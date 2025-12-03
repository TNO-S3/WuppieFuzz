use std::{convert::TryFrom, fmt::Display};

const GET: &str = "GET";
const POST: &str = "POST";
const PUT: &str = "PUT";
const PATCH: &str = "PATCH";
const DELETE: &str = "DELETE";
const HEAD: &str = "HEAD";
const TRACE: &str = "TRACE";
const OPTIONS: &str = "OPTIONS";
const CONNECT: &str = "CONNECT";

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE", try_from = "String")]
/// This enum represents the valid methods of a request made by the fuzzer,
/// and supports conversions from and to strings.
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Trace,
    Options,
    Connect,
}

impl Method {
    /// Returns a static bytes reference naming the current method.
    pub fn as_bytes(&self) -> &'static [u8] {
        self.as_str().as_bytes()
    }

    /// Returns a static str reference naming the current method.
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Get => GET,
            Method::Post => POST,
            Method::Put => PUT,
            Method::Patch => PATCH,
            Method::Delete => DELETE,
            Method::Head => HEAD,
            Method::Trace => TRACE,
            Method::Options => OPTIONS,
            Method::Connect => CONNECT,
        }
    }
}

impl From<Method> for reqwest::Method {
    fn from(m: Method) -> Self {
        match m {
            Method::Get => reqwest::Method::GET,
            Method::Post => reqwest::Method::POST,
            Method::Put => reqwest::Method::PUT,
            Method::Patch => reqwest::Method::PATCH,
            Method::Delete => reqwest::Method::DELETE,
            Method::Head => reqwest::Method::HEAD,
            Method::Trace => reqwest::Method::TRACE,
            Method::Options => reqwest::Method::OPTIONS,
            Method::Connect => reqwest::Method::CONNECT,
        }
    }
}

impl From<reqwest::Method> for Method {
    fn from(m: reqwest::Method) -> Self {
        match m {
            reqwest::Method::GET => Method::Get,
            reqwest::Method::POST => Method::Post,
            reqwest::Method::PUT => Method::Put,
            reqwest::Method::PATCH => Method::Patch,
            reqwest::Method::DELETE => Method::Delete,
            reqwest::Method::HEAD => Method::Head,
            reqwest::Method::TRACE => Method::Trace,
            reqwest::Method::OPTIONS => Method::Options,
            reqwest::Method::CONNECT => Method::Connect,
        }
    }
}

impl std::cmp::PartialEq<&str> for Method {
    /// Compares the current method to the one given in a string reference.
    /// The comparison is case insensitive, but superfluous whitespace will
    /// always result in `false`.
    fn eq(&self, other: &&str) -> bool {
        Self::try_from(*other).map(|m| *self == m).unwrap_or(false)
    }
}

impl std::cmp::PartialEq<Method> for &str {
    /// Compares the current method to the one given in a string reference.
    /// The comparison is case insensitive, but superfluous whitespace will
    /// always result in `false`.
    fn eq(&self, other: &Method) -> bool {
        other == self
    }
}

impl Ord for Method {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        fn method_index(method: Method) -> u8 {
            match method {
                Method::Post => 0,
                Method::Head => 1,
                Method::Trace => 2,
                Method::Get => 3,
                Method::Put => 4,
                Method::Patch => 5,
                Method::Delete => 6,
                Method::Options => 7,
                Method::Connect => 8,
            }
        }
        method_index(*self).cmp(&method_index(*other))
    }
}

impl PartialOrd for Method {
    fn partial_cmp(&self, other: &Method) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for Method {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Method::Get => fmt.write_str(GET),
            Method::Post => fmt.write_str(POST),
            Method::Put => fmt.write_str(PUT),
            Method::Patch => fmt.write_str(PATCH),
            Method::Delete => fmt.write_str(DELETE),
            Method::Head => fmt.write_str(HEAD),
            Method::Trace => fmt.write_str(TRACE),
            Method::Options => fmt.write_str(OPTIONS),
            Method::Connect => fmt.write_str(CONNECT),
        }
    }
}

impl TryFrom<&str> for Method {
    type Error = InvalidMethodError;

    /// Converts the given string reference to a Method, if possible.
    /// The comparison is case insensitive, but superfluous whitespace will
    /// always result in an error.
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.len() {
            3 if s.eq_ignore_ascii_case(GET) => Ok(Self::Get),
            3 if s.eq_ignore_ascii_case(PUT) => Ok(Self::Put),
            4 if s.eq_ignore_ascii_case(POST) => Ok(Self::Post),
            5 if s.eq_ignore_ascii_case(PATCH) => Ok(Self::Patch),
            6 if s.eq_ignore_ascii_case(DELETE) => Ok(Self::Delete),
            4 if s.eq_ignore_ascii_case(HEAD) => Ok(Self::Head),
            5 if s.eq_ignore_ascii_case(TRACE) => Ok(Self::Trace),
            7 if s.eq_ignore_ascii_case(OPTIONS) => Ok(Self::Options),
            7 if s.eq_ignore_ascii_case(CONNECT) => Ok(Self::Connect),
            _ => Err(InvalidMethodError(s.to_owned())),
        }
    }
}

impl TryFrom<&String> for Method {
    type Error = InvalidMethodError;

    /// Converts the given string reference to a Method, if possible.
    /// The comparison is case insensitive, but superfluous whitespace will
    /// always result in an error.
    fn try_from(s: &String) -> Result<Self, Self::Error> {
        <Method as TryFrom<&str>>::try_from(s.as_ref())
    }
}

impl TryFrom<String> for Method {
    type Error = InvalidMethodError;

    /// Converts the given string reference to a Method, if possible.
    /// The comparison is case insensitive, but superfluous whitespace will
    /// always result in an error.
    fn try_from(s: String) -> Result<Self, Self::Error> {
        <Method as TryFrom<&str>>::try_from(&s)
    }
}

/// Error type returned from `Method::try_from(_: &str)` if the given string
/// does not name a valid method.
#[derive(Debug, Clone)]
pub struct InvalidMethodError(String);
impl Display for InvalidMethodError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid method: {}", self.0)
    }
}
