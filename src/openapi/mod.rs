use anyhow::{Context, Result};
use indexmap::IndexMap;
use openapiv3::{MediaType, OpenAPI, Operation, PathItem, VersionedOpenAPI};
use std::fmt::Debug;
use std::{convert::TryFrom, path::Path};

use crate::input::{method::InvalidMethodError, Method};

pub mod build_request;
pub mod curl_request;
pub mod examples;
pub mod validate_response;

/// Loads the OpenAPI specification from the given path
pub fn get_api_spec(path: &Path) -> Result<Box<OpenAPI>, anyhow::Error> {
    openapi_from_yaml_file(path)
        .map(Box::new)
        .with_context(|| format!("Error parsing OpenAPI-file at {}", path.to_string_lossy()))
}

/// A QualifiedOperation is the (path, method, operation) tuple returned from
/// `api.operations()`, and is used to identify an operation uniquely in the graph.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct QualifiedOperation<'a> {
    pub path: &'a str,
    pub method: Method,
    pub operation: &'a Operation,
    #[allow(dead_code)]
    pub path_item: &'a PathItem,
}

impl<'a> QualifiedOperation<'a> {
    pub fn new(
        path: &'a str,
        method: &'a str,
        operation: &'a Operation,
        path_item: &'a PathItem,
    ) -> Result<Self, InvalidMethodError> {
        Ok(Self {
            path,
            method: Method::try_from(method)?,
            operation,
            path_item,
        })
    }
}

pub fn openapi_from_yaml_file(filename: &Path) -> Result<OpenAPI> {
    let file = std::fs::File::open(filename)?;
    let open_api: VersionedOpenAPI = serde_yaml::from_reader(file)?;
    Ok(open_api.upgrade())
}

pub fn find_method_indices_for_path<'a>(api: &'a OpenAPI, path: &str) -> Vec<(&'a str, usize)> {
    api.operations()
        .enumerate()
        .filter(|(_, (this_path, _, _, _))| path.eq_ignore_ascii_case(this_path))
        .map(|(i, (_, this_method, _, _))| (this_method, i))
        .collect()
}

pub fn find_operation<'a>(api: &'a OpenAPI, path: &str, method: Method) -> Option<&'a Operation> {
    api.operations()
        .find(|&(p, m, _, _)| path.eq_ignore_ascii_case(p) && method == m)
        .map(|t| t.2)
}

pub trait JsonContent {
    fn get_json_content(&self) -> Option<&MediaType>;
    fn has_json_content(&self) -> bool;
}

impl JsonContent for IndexMap<String, MediaType> {
    fn get_json_content(&self) -> Option<&MediaType> {
        self.iter()
            .find_map(|(key, value)| key.starts_with("application/json").then_some(value))
    }
    fn has_json_content(&self) -> bool {
        self.iter()
            .any(|(key, _value)| key.starts_with("application/json"))
    }
}

pub trait WwwForm {
    fn get_www_form_content(&self) -> Option<&MediaType>;
    fn has_www_form_content(&self) -> bool;
}

impl WwwForm for IndexMap<String, MediaType> {
    fn get_www_form_content(&self) -> Option<&MediaType> {
        self.iter().find_map(|(key, value)| {
            key.starts_with("application/x-www-form-urlencoded")
                .then_some(value)
        })
    }
    fn has_www_form_content(&self) -> bool {
        self.iter()
            .any(|(key, _value)| key.starts_with("application/x-www-form-urlencoded"))
    }
}

pub trait TextPlain {
    #[allow(dead_code)]
    fn get_text_plain(&self) -> Option<&MediaType>;
    fn has_text_plain(&self) -> bool;
}

impl TextPlain for IndexMap<String, MediaType> {
    fn get_text_plain(&self) -> Option<&MediaType> {
        self.iter()
            .find_map(|(key, value)| key.starts_with("text/plain").then_some(value))
    }
    fn has_text_plain(&self) -> bool {
        self.iter()
            .any(|(key, _value)| key.starts_with("text/plain"))
    }
}
