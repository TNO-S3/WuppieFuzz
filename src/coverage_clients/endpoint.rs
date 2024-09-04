//! The Endpoint coverage client tracks coverage based on (API endpoint, response status code)
//! combinations reached by the fuzzer, rather than based on lines or statements touched in
//! the program under test.
//!
//! It is always available, and if no other coverage is made available to the fuzzer, endpoint
//! coverage is used as the metric that guides the fuzzer. This is a very poor approximation
//! of code coverage, especially if the responses in the specification are poorly specified.
//! Nevertheless, it is available to allow new users of the fuzzer to get started quickly:
//! attaching a coverage agent to a target is not always easy, and we do not support all types
//! of programming languages.

use super::{CoverageClient, MAP_SIZE};
use build_html::{escape_html, Container, ContainerType, Html, HtmlContainer, HtmlPage};
use indexmap::{map::Entry, IndexMap};
use openapiv3::{OpenAPI, StatusCode};
use std::{
    convert::TryFrom,
    fs::{create_dir_all, File},
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
};

use crate::input::Method;

const HIT_SYMBOL: &str = "&#x2714;&#xfe0f;";
const MISS_SYMBOL: &str = "&#x274c;";
const SUPERFLUOUS_SYMBOL: &str = "&#x26a0;&#xfe0f";

/// Endpoint coverage client.
pub struct EndpointCoverageClient {
    endpoint_cov_map: IndexMap<(Method, String, StatusCode), Coverage>,
    cov_map: [u8; MAP_SIZE],
    cov_map_total: [u8; MAP_SIZE],
    len: usize,
    max_ratio: (u64, u64),
}

#[derive(Debug, Clone)]
#[allow(clippy::enum_variant_names)]
enum Coverage {
    /// This status code occurs in the specification, but was not seen
    ExpectedNotFound,
    /// This status code occurs in the specification, and was seen
    ExpectedFound(String, String),
    /// This status code was seen but does not occur in the specification
    UnexpectedFound(String, String),
}

impl EndpointCoverageClient {
    /// Creates a new endpoint coverage client given an API specification.
    pub fn new(api: &OpenAPI) -> Self {
        let coverage_index_map: IndexMap<_, _> = api
            .operations()
            // Collect all method-path-status tuples from the API spec
            .flat_map(|(path, method, operation, _)| {
                operation.responses.responses.keys().map(move |status| {
                    (
                        Method::try_from(method).unwrap(),
                        path.to_owned(),
                        status.clone(),
                    )
                })
            })
            // Mark them all as un-covered
            .map(|key| (key, Coverage::ExpectedNotFound))
            .collect();

        let len = coverage_index_map.len();
        assert!(
            len <= MAP_SIZE,
            "Number of responses in API specification is larger than coverage MAP_SIZE"
        );

        Self {
            endpoint_cov_map: coverage_index_map,
            cov_map: [0; MAP_SIZE],
            cov_map_total: [0; MAP_SIZE],
            len,
            max_ratio: (0, len as u64),
        }
    }

    /// Update the endpoint coverage maps (`self.cov_map` and `self.cov_map_total`)
    /// based on the response code `status` after sending the request with
    /// method `method` to `path`.
    pub fn cover(
        &mut self,
        method: Method,
        path: String,
        status: reqwest::StatusCode,
        input: String,
        output: String,
    ) {
        // Get the coverage entry for the method-path-status combination.
        // The entry may be Vacant or Occupied, see below for what this means.
        let entry = self
            .endpoint_cov_map
            .entry((method, path, StatusCode::Code(status.as_u16())));
        // Must get the index before entry.insert below, which needs ownership of the entry
        let index = entry.index();

        // Only add this testcase to the endpoint coverage map if nothing was there before
        match entry {
            // No pre-existing entry for the method-path-status combination, we found an unspecified response!
            Entry::Vacant(entry) => {
                entry.insert(Coverage::UnexpectedFound(input, output));
            }
            // Occupied entry, either already found (expected or unexpected) or expected but not yet found
            Entry::Occupied(mut entry) => {
                // Only new coverage needs to be inserted.
                if matches!(entry.get(), Coverage::ExpectedNotFound) {
                    entry.insert(Coverage::ExpectedFound(input, output));
                }
            }
        }
        // Update LibAFL's coverage mappings in any case, since upon reset
        // all bits are reset to zero. Note that the index does correspond to the same
        // method-path-status triplet between runs (the nth-triplet is stored at index n).
        // For this reason it is important NOT TO REMOVE entries from the endpoint_cov_map
        // during a run: once a triplet is inserted, its index must be unique since this
        // determines the mapping into the AFL-coverage maps.
        assert!(index / 8 < MAP_SIZE, "Coverage map is full");
        self.len = std::cmp::max(self.len, index);
        // Map the method-path-status triplets via their index to *bits*, not bytes.
        // Hence the bitwise operations, the first 8 indices get mapped into the first byte
        // and since we always *add* coverage, we can OR the corresponding bit into that byte.
        self.cov_map[index / 8] |= 0b10000000 >> (index % 8);
        self.cov_map_total[index / 8] |= 0b10000000 >> (index % 8);
    }

    fn export_filesystem(&self, base_path: &Path) -> Result<(), libafl::Error> {
        // Make a tree in the same structure as the html page will contain:
        // path -> method -> status codes
        let mut operation_tree =
            IndexMap::<&String, IndexMap<Method, IndexMap<StatusCode, &Coverage>>>::new();
        for ((method, path, status), cov_entry) in &self.endpoint_cov_map {
            operation_tree
                .entry(path)
                .or_default()
                .entry(*method)
                .or_default()
                .insert(status.clone(), cov_entry);
        }
        operation_tree.sort_keys();

        // Make a nested Unordered List containing all the status codes
        let tree_container = operation_tree
            .into_iter()
            .map(|(path, mut methods)| {
                methods.sort_keys();
                let list = methods
                    .into_iter()
                    .map(|(method, statuses)| {
                        let list = statuses.into_iter().fold(
                            Container::new(ContainerType::UnorderedList),
                            // This is the actual "✔ 200" list item. We have to decide whether to
                            // make a link out of it that displays a request in the input pane.
                            // The link doesn't lead to any page, but rather it has the input
                            // request and response in a data attribute. We can then use some javascript on
                            // the "input-link" class that reads this attribute's contents and
                            // puts it into the "input-pane".
                            |list, item| match item.1 {
                                Coverage::ExpectedFound(request, response) => list.with_link_attr(
                                    "#",
                                    format!("{} {}", HIT_SYMBOL, item.0),
                                    [
                                        ("data-input", escape_html(request).as_str()),
                                        ("data-output", escape_html(response).as_str()),
                                        ("class", "input-link c-hit"),
                                    ],
                                ),
                                Coverage::UnexpectedFound(request, response) => list
                                    .with_link_attr(
                                        "#",
                                        format!("{} {}", SUPERFLUOUS_SYMBOL, item.0),
                                        [
                                            ("data-input", escape_html(request).as_str()),
                                            ("data-output", escape_html(response).as_str()),
                                            ("class", "input-link c-extra"),
                                        ],
                                    ),
                                Coverage::ExpectedNotFound => list.with_raw(format!(
                                    "<a class=\"c-miss\">{} {}</a>",
                                    MISS_SYMBOL, item.0
                                )),
                            },
                        );
                        Container::new(ContainerType::Div)
                            .with_raw(method)
                            .with_container(list)
                    })
                    .fold(
                        Container::new(ContainerType::UnorderedList)
                            .with_attributes([("class", "method")]),
                        |list, item| list.with_container(item),
                    );
                Container::new(ContainerType::Div)
                    .with_attributes([("class", "endpoint_path")])
                    .with_raw(escape_html(path))
                    .with_container(list)
            })
            .fold(
                Container::new(ContainerType::UnorderedList).with_attributes([("class", "path")]),
                |list, item| list.with_container(item),
            );

        // The entire page is just two containers: the header ("menu") listing the endpoints,
        // and the main area listing the input corresponding to a selected endpoint.
        let html: String = HtmlPage::new()
            .with_script_link_attr(
                "https://code.jquery.com/jquery-3.6.3.min.js",
                [
                    (
                        "integrity",
                        "sha256-pvPw+upLPUjgMXY0G+8O0xUf+/Im1MZjXxxgOcBQBXU=",
                    ),
                    ("crossorigin", "anonymous"),
                ],
            )
            .with_script_literal(COVERAGE_EXPORT_JAVASCRIPT)
            .with_style(COVERAGE_EXPORT_CSS)
            .with_title("Endpoint coverage report")
            .with_header(1, "Endpoint coverage report")
            .with_container(
                Container::new(ContainerType::Div)
                    .with_attributes([("class", "contents")])
                    .with_container(
                        Container::new(ContainerType::Nav)
                            .with_header(2, "Endpoints")
                            .with_container(tree_container),
                    )
                    .with_container(
                        Container::new(ContainerType::Article)
                            .with_header_attr(
                                2,
                                "Endpoint summary",
                                [("id", "title-header")],
                            )
                            .with_paragraph_attr(
                                "Click a found (hit/unspecified) status code in the list on the left to see its request + response.",
                                [("id", "title-pane")],
                            )
                            .with_header(2, "Request")
                            .with_paragraph_attr(
                                "None selected yet",
                                [("id", "input-pane")],
                            )
                            .with_header(2, "Response")
                            .with_paragraph_attr("None selected yet",
                                [("id", "output-pane")],
                            )
                    ),
            )
            .with_container(
                Container::new(ContainerType::Div)
                    .with_attributes([("id", "filters")])
                    .with_raw(
                        format!(r##"
                        <input id="f-hit" type="checkbox" checked> <label for="f-hit">{HIT_SYMBOL} Hits</label>
                        <input id="f-miss" type="checkbox" checked> <label for="f-miss">{MISS_SYMBOL} Misses</label>
                        <input id="f-extra" type="checkbox" checked> <label for="f-extra">{SUPERFLUOUS_SYMBOL} Unspecified</label>
                        "##),
                    ),
            )
            .to_html_string();

        create_dir_all(base_path)?;
        let mut handle = File::create(base_path.join("index.html"))?;
        write!(handle, "{html}")?;

        Ok(())
    }
}

impl CoverageClient for Arc<Mutex<EndpointCoverageClient>> {
    fn fetch_coverage(&mut self, _reset: bool) {}

    /// Retrieve a pointer to the coverage bitmap (this is used by LibAFL).
    fn get_coverage_ptr(&mut self) -> *mut u8 {
        self.lock().unwrap().cov_map.as_mut_ptr()
    }

    /// Retrieve the coverage ratio: nodes hit and total number of nodes.
    fn max_coverage_ratio(&mut self) -> (u64, u64) {
        let mut guard = self.lock().unwrap();
        guard.max_ratio = (
            guard
                .cov_map_total
                .iter()
                .map(|b| b.count_ones() as u64)
                .sum(),
            guard.len as u64,
        );
        guard.max_ratio
    }

    /// Write a format-dependent report to disk
    fn generate_coverage_report(&self, report_path: &Path) {
        let endpoint_path = report_path.join("endpointcoverage");
        let _ = self.lock().unwrap().export_filesystem(&endpoint_path);
    }
}

const COVERAGE_EXPORT_JAVASCRIPT: &str = r##"
// When the document is loaded, attach "onclick" events to all links of class
// 'input-link' that display the 'data-input' contents in the 'input-pane'
// and 'data-output' in the 'output-pane'.
function update_hidden() {
    $("ul.path").children().each(function(index, element) {
        $(element).show();
    });
    $("ul.method").children().each(function(index, element) {
        $(element).show();
    });

    if ($("#f-hit")[0].checked) {
        $(".c-hit").parent().show();
    } else {
        $(".c-hit").parent().hide();
    }
    if ($("#f-miss")[0].checked) {
        $(".c-miss").parent().show();
    } else {
        $(".c-miss").parent().hide();
    }
    if ($("#f-extra")[0].checked) {
        $(".c-extra").parent().show();
    } else {
        $(".c-extra").parent().hide();
    }

    $("ul.method").children().each(function(index, element) {
        if ($(element).children().children().children().filter(function(index, child) {
            return $(child).css("display") != "none";
        }).length > 0) { // has visible children?
            $(element).show();
        } else {
            $(element).hide();
        }
    });
    $("ul.path").children().each(function(index, element) {
        if ($(element).children().children().children().filter(function(index, child) {
            return $(child).css("display") != "none";
        }).length > 0) { // has visible children?
            $(element).show();
        } else {
            $(element).hide();
        }
    });
}
$(function() {
    $(".input-link").click(function() {
        $("#input-pane").html($(this).attr("data-input"));
        $("#output-pane").html($(this).attr("data-output"));
        $(".input-link").css("background-color", "#00000000");
        $(this).css("background-color", "#FFFF00FF"); 
        let http_result = $(this).html();
        let hit_miss_unspecified = http_result.substring(0, 2);
        let http_status = http_result.substring(2);
        let http_method = $(this).closest('div')[0].firstChild.nodeValue;
        let endpoint = $(this).closest('.endpoint_path')[0].firstChild.nodeValue;
        $("#title-header").html(endpoint);
        $("#title-pane").html([hit_miss_unspecified, http_method, http_status].join(" "));
    });
    $("input").click(update_hidden);
    $("label").click(update_hidden);
    $("input").prop("checked", true);
});

"##;

const COVERAGE_EXPORT_CSS: &str = r##"
body {
    font-family: Segoe UI Emoji;
    margin: 0;
}
h1 {
    position: fixed;
    height: 70pt;
    padding: 5pt;
}
.contents {
    height: calc(100% - 70pt);
    margin-top: 70pt;
    position: fixed;
    width: calc(100% - 5pt);
    margin-left: 5pt;
}
nav {
    float: left;
    width: 250pt;
    height: 100%;
    overflow-y: scroll;
    overflow-x: hidden;
}
article {
    float: left;
    overflow-y: auto;
    width: calc(100% - 260pt);
    height: 100%;
    padding-left: 10pt;
}
#input-pane, #output-pane {
    max-width: 100%;
    font-family: monospace;
    white-space: pre-wrap;
    word-break: break-all;
    background: #eee;
    padding: 5pt;
    border-radius: 4pt;
    margin-right: 10pt;
}
#filters {
    position: fixed;
    top: 5pt;
    right: 5pt;
}
"##;
