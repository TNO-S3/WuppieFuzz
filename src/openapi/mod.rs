use std::{collections::BTreeMap, fmt::Debug};

use anyhow::Result;
use indexmap::IndexMap;
use oas3::spec::{MediaType, Operation, Server};

use crate::{configuration::Configuration, input::Method, openapi::spec::Spec};

pub mod build_request;
pub mod curl_request;
pub mod examples;
pub mod spec;
pub mod validate_response;

/// Load the API spec file specified in the Configuration, attempt to parse it,
/// and replace the Servers statement inside it by the Configuration's server override
pub fn parse_api_spec(config: &'static Configuration) -> Result<Box<Spec>, anyhow::Error> {
    let mut api = spec::load::get_api_spec(
        config
            .openapi_spec
            .as_ref()
            .expect("A path for the API specification file should be known at this point"),
    )?;
    if let Some(server_override) = &config.target {
        api.servers = vec![Server {
            url: server_override.as_str().trim_end_matches('/').to_string(),
            description: None,
            variables: BTreeMap::new(),
            extensions: BTreeMap::new(),
        }];
    }
    Ok(api)
}

/// A QualifiedOperation is the (path, method, operation) tuple returned from
/// `api.operations()`, and is used to identify an operation uniquely in the graph.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct QualifiedOperation<'a> {
    pub path: String,
    pub method: Method,
    pub operation: &'a Operation,
}

impl<'a> QualifiedOperation<'a> {
    /// Convenience function to create a QualifiedOperation from a reqwest/http Method
    pub fn new(path: String, method: reqwest::Method, operation: &'a Operation) -> Self {
        Self {
            path,
            method: method.into(),
            operation,
        }
    }
}

/// For a given path, gives the available methods and the operation index corresponding to them
pub fn find_method_indices_for_path<'a>(api: &'a Spec, path: &str) -> Vec<(Method, usize)> {
    api.operations()
        .enumerate()
        .filter(|(_, (this_path, _, _))| path.eq_ignore_ascii_case(this_path))
        .map(|(i, (_, this_method, _))| (this_method.into(), i))
        .collect()
}

/// Finds the Operation corresponding to a path and method
pub fn find_operation<'a>(api: &'a Spec, path: &str, method: Method) -> Option<&'a Operation> {
    api.operations()
        .find(|(p, m, _)| path.eq_ignore_ascii_case(&p) && method == Method::from(m))
        .map(|(_, _, operation)| operation)
}

pub trait JsonContent {
    fn get_json_content(&self) -> Option<&MediaType>;
}

impl JsonContent for IndexMap<String, MediaType> {
    fn get_json_content(&self) -> Option<&MediaType> {
        self.iter()
            .find_map(|(key, value)| key.starts_with("application/json").then_some(value))
    }
}

impl JsonContent for std::collections::BTreeMap<String, MediaType> {
    fn get_json_content(&self) -> Option<&MediaType> {
        self.iter()
            .find_map(|(key, value)| key.starts_with("application/json").then_some(value))
    }
}

pub trait WwwForm {
    fn get_www_form_content(&self) -> Option<&MediaType>;
}

impl WwwForm for IndexMap<String, MediaType> {
    fn get_www_form_content(&self) -> Option<&MediaType> {
        self.iter().find_map(|(key, value)| {
            key.starts_with("application/x-www-form-urlencoded")
                .then_some(value)
        })
    }
}

impl WwwForm for BTreeMap<String, MediaType> {
    fn get_www_form_content(&self) -> Option<&MediaType> {
        self.iter().find_map(|(key, value)| {
            key.starts_with("application/x-www-form-urlencoded")
                .then_some(value)
        })
    }
}

pub trait TextPlain {
    #[allow(dead_code)]
    fn get_text_plain(&self) -> Option<&MediaType>;
}

impl TextPlain for IndexMap<String, MediaType> {
    fn get_text_plain(&self) -> Option<&MediaType> {
        self.iter()
            .find_map(|(key, value)| key.starts_with("text/plain").then_some(value))
    }
}
