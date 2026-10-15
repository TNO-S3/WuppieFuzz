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

use std::{
    fs::{File, create_dir_all},
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
};

use build_html::{
    Container, ContainerType, Html, HtmlContainer, HtmlPage, Table, TableCell, TableCellType,
    TableRow, escape_html,
};
use indexmap::{IndexMap, map::Entry};
use libafl::inputs::Input;
use strum::IntoDiscriminant;

use super::{CoverageClient, MAP_SIZE};
use crate::{
    initial_corpus::QUEUE_DIR,
    input::{Method, OpenApiInput},
    openapi::{
        spec::Spec,
        validate_response::{ValidationError, ValidationErrorDiscriminants},
    },
    reporting::wfc_report::fault_category_name,
    state::CRASHES_DIR,
};

const HIT_SYMBOL: &str = "&#x2714;&#xfe0f;";
const MISS_SYMBOL: &str = "&#x274c;";
const SUPERFLUOUS_SYMBOL: &str = "&#x26a0;&#xfe0f";

/// Builds an `EndpointCoverageClient` from `api` and wraps it as a shared, lockable
/// `CoverageClient` so it can be used interchangeably with other coverage backends.
pub fn setup_endpoint_coverage(
    api: &Spec,
) -> core::result::Result<Arc<Mutex<EndpointCoverageClient>>, anyhow::Error> {
    let mut endpoint_coverage_client = Arc::new(Mutex::new(EndpointCoverageClient::new(api)));
    endpoint_coverage_client.fetch_coverage(true); // no-op for this particular CoverageClient
    Ok(endpoint_coverage_client)
}

/// Endpoint coverage client.
pub struct EndpointCoverageClient {
    // Keys: (method, path, status) - status is a String, not `StatusCode`, because
    // oas3 keys a spec operation's `responses` map by string status codes.
    endpoint_cov_map: IndexMap<(Method, String, String), Coverage>,
    cov_map: [u8; MAP_SIZE],
    cov_map_total: [u8; MAP_SIZE],
    len: usize,
    max_ratio: (u64, u64),
    /// Distinct faults (validation errors) observed per (method, path), used for
    /// building Web Fuzzing Commons (WFC) reports.
    faults: Vec<EndpointFault>,
}

/// A distinct fault (validation error) observed on a given endpoint during the
/// fuzzing campaign. Used to populate WFC reports (see `crate::reporting::wfc_report`).
#[derive(Debug, Clone)]
pub struct EndpointFault {
    /// The HTTP method of the endpoint on which the fault was observed.
    pub method: Method,
    /// The path of the endpoint on which the fault was observed.
    pub path: String,
    /// The HTTP status code of the response that triggered the fault.
    pub status: u16,
    /// Which kind of validation error was observed.
    pub discriminant: ValidationErrorDiscriminants,
    /// A human-readable description of an example occurrence of this fault.
    pub message: String,
    /// The number of times this exact fault (same method, path, status and kind) was observed.
    pub occurrences: u32,
    /// LibAFL's deterministic content-hash name (`Input::generate_name`) for the full
    /// request sequence that first triggered this fault; a copy of that sequence is
    /// saved to `CRASHES_DIR` under this name as soon as the fault is recorded (see
    /// `ensure_crash_file`), so it is expected to always be locatable on disk (see
    /// `locate_test_case`, used by `reporting::wfc_report`).
    pub test_case_name: String,
    /// A curl-equivalent representation of the request that first triggered this
    /// fault. Used by the HTML endpoint coverage report to let users inspect this
    /// specific fault variant, separately from the (possibly different) example
    /// stored for a plain "hit" on the same method/path/status.
    pub request: String,
    /// The response body text first observed for this fault.
    pub response: String,
}

/// Arguments for `EndpointCoverageClient::cover`, bundled into a struct to avoid
/// a long parameter list (clippy::too_many_arguments).
pub struct CoverArgs<'a> {
    /// HTTP method of the request that produced this response.
    pub method: Method,
    /// Path of the request that produced this response.
    pub path: String,
    /// HTTP status of the response.
    pub status: reqwest::StatusCode,
    /// A curl-equivalent representation of the request that produced this response.
    pub input: String,
    /// The response body text.
    pub output: String,
    /// The validation error found for this response, if any.
    pub validation_error: Option<ValidationError>,
    /// The full request sequence currently being executed, saved to `CRASHES_DIR`
    /// the first time a new fault is observed.
    pub sequence: &'a OpenApiInput,
}

/// Arguments for `EndpointCoverageClient::record_fault`, bundled for the same
/// reason as `CoverArgs`.
struct FaultArgs<'a> {
    method: Method,
    path: &'a str,
    status: reqwest::StatusCode,
    err: &'a ValidationError,
    sequence: &'a OpenApiInput,
    request: &'a str,
    response: &'a str,
}

/// Locates the on-disk file named `file_name` holding the request sequence for a
/// given fault, without writing a new copy of it.
///
/// Faults recorded via `record_fault` are proactively written to `CRASHES_DIR` the
/// moment they are first observed (see `ensure_crash_file`), so this is checked
/// first and should almost always succeed. As a fallback (e.g. a read-only
/// filesystem prevented the proactive write, or the file was otherwise removed
/// from under us), LibAFL's own `QUEUE_DIR` is also checked under the same name,
/// since LibAFL persists crashing inputs there too as part of its normal solutions
/// handling. Only if neither location has the file does this return `None`.
pub fn locate_test_case(file_name: &str) -> Option<String> {
    for dir in [CRASHES_DIR, QUEUE_DIR] {
        let path = Path::new(dir).join(file_name);
        if path.exists() {
            return Some(path.to_string_lossy().to_string());
        }
    }
    None
}

/// Ensures `sequence` is saved to `CRASHES_DIR` under its deterministic content-hash
/// name (`Input::generate_name`), the same name and directory LibAFL's own
/// `solutions` corpus would use for it, and returns that name.
///
/// Every fault tracked by `record_fault` corresponds to an execution that set
/// `ExitKind::Crash`, so LibAFL's `CrashFeedback` would normally persist it to
/// `CRASHES_DIR` anyway. However, faults first observed while LibAFL re-executes
/// seeds during corpus minimization bypass that objective/solutions machinery
/// entirely (see `MapCorpusMinimizer::minimize`), and the corresponding seed can
/// later be deleted from the queue if minimization finds it redundant for coverage
/// purposes (coverage that is tracked per status code, not per fault reason, so a
/// seed can be "redundant" there while being the only reproducer for its specific
/// fault). Writing it here ourselves, right away, closes that gap; if the file
/// already exists (e.g. LibAFL got there first), this is a cheap, harmless no-op.
fn ensure_crash_file(sequence: &OpenApiInput) -> String {
    let file_name = sequence.generate_name(None);
    let path = Path::new(CRASHES_DIR).join(&file_name);
    if !path.exists() {
        if let Err(err) = create_dir_all(CRASHES_DIR) {
            log::warn!("Could not create directory {CRASHES_DIR} for crash files: {err}");
        } else if let Err(err) = sequence.to_file(&path) {
            log::warn!("Could not write crash file to {path:?}: {err}");
        }
    }
    file_name
}

/// Like `ensure_crash_file`, but returns the full path to the reproducer file
/// rather than just its name. Used to link every crashing request (not just the
/// first occurrence of each distinct fault) to its reproducer in the SQLite
/// report, via `Reporting::report_crash`.
pub fn ensure_crash_file_path(sequence: &OpenApiInput) -> String {
    let file_name = ensure_crash_file(sequence);
    Path::new(CRASHES_DIR)
        .join(file_name)
        .to_string_lossy()
        .to_string()
}

/// HTML presentation data for a single fault, used in the flat "All faults" table
/// of the HTML coverage report.
struct FaultBadge {
    /// The WFC fault category id (e.g. `SCHEMA_INVALID_RESPONSE`), shared with
    /// `reporting::wfc_report` so both reports use the exact same vocabulary.
    category: &'static str,
    /// The on-disk reproducer path, if one could be located (see `locate_test_case`).
    reproduce: Option<String>,
    /// A CSS class (`cat-<CATEGORY>`) identifying this fault's WFC category, used
    /// as a styling hook for the category badge.
    class: String,
}

/// Builds the badge category, reproducer path and CSS class used to render `fault`
/// in the HTML coverage report, using the same WFC category vocabulary as
/// `reporting::wfc_report`.
fn fault_badge(fault: &EndpointFault) -> FaultBadge {
    let (category, _code) = fault_category_name(fault.discriminant, fault.status);
    FaultBadge {
        category,
        reproduce: locate_test_case(&fault.test_case_name),
        class: format!("cat-{category}"),
    }
}

/// Truncates `s` to at most `max_chars` characters, appending an ellipsis if it was
/// shortened. Used to keep long validation-error messages (which can embed entire
/// schema dumps) from blowing up the "All faults" table layout.
fn truncate(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        Some((byte_idx, _)) => format!("{}…", &s[..byte_idx]),
        None => s.to_string(),
    }
}

/// Renders a fault message as a truncated `<span>` with the full text in its
/// `title` tooltip. Shared by the "All faults" table and fault-variant blocks.
fn message_html(message: &str) -> String {
    format!(
        r#"<span title="{full}">{short}</span>"#,
        full = escape_html(message),
        short = escape_html(&truncate(message, 160)),
    )
}

/// Renders the "Reproduce" markup for a fault's reproducer path (with a copy
/// button), or an explanatory message if none could be located (see
/// `locate_test_case`). `inline` lays the path and button out on one line
/// (compact, for the "All faults" table); otherwise they are stacked, which
/// suits the more spacious fault-variant blocks.
fn reproduce_html(reproduce: Option<&str>, inline: bool) -> String {
    match reproduce {
        Some(path) => {
            let escaped_path = escape_html(path);
            let separator = if inline { " " } else { "<br>" };
            format!(
                r#"<code title="{escaped_path}">{escaped_path}</code>{separator}<button class="copy-btn" data-copy="wuppiefuzz reproduce {escaped_path}">Copy reproduce command</button>"#
            )
        }
        None => "<em>not found in crashes or queue directories</em>".to_string(),
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::enum_variant_names)]
enum Coverage {
    /// This status code occurs in the specification, but was not seen
    ExpectedNotFound,
    /// This status code occurs in the specification, and was seen
    /// (request, response, whether this example also triggered a validation error).
    /// Status codes defined in the spec still count as "found" even when the one
    /// response seen for them failed validation (e.g. a schema mismatch), but such
    /// a tainted example is replaced by a clean one as soon as one is observed, so
    /// the displayed example doesn't misleadingly double as a fault's own example
    /// (see `cover`).
    ExpectedFound(String, String, bool),
    /// This status code was seen but does not occur in the specification
    /// (request, response, validation error)
    UnexpectedFound(String, String, String),
}

/// Renders a single `.fault-variant` block (category badge, message, request,
/// response, reproduce) for one `EndpointFault`, as used in the hidden
/// `.fault-variants` templates in the endpoint tree (see `export_filesystem`).
fn render_fault_variant(fault: &EndpointFault) -> String {
    let FaultBadge {
        category,
        reproduce,
        class,
    } = fault_badge(fault);
    format!(
        r#"<div class="fault-variant">
            <div class="fv-header"><span class="badge {class}">{category}</span> &times;{occurrences} &mdash; {message}</div>
            <h4>Request</h4><div class="fv-pane">{request}</div>
            <h4>Response</h4><div class="fv-pane">{response}</div>
            <h4>Reproduce</h4><div class="fv-pane">{reproduce}</div>
        </div>"#,
        occurrences = fault.occurrences,
        message = message_html(&fault.message),
        request = escape_html(&fault.request),
        response = escape_html(&fault.response),
        reproduce = reproduce_html(reproduce.as_deref(), false),
    )
}

impl EndpointCoverageClient {
    /// Creates a new endpoint coverage client given an API specification.
    pub fn new(api: &Spec) -> Self {
        let coverage_index_map: IndexMap<_, _> = api
            .operations()
            // Collect all method-path-status tuples from the API spec
            .flat_map(|(path, method, operation)| {
                operation
                    .responses
                    .as_ref()
                    .unwrap()
                    .keys()
                    .map(move |status| (Method::from(&method), path.to_owned(), status.clone()))
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
            faults: Vec::new(),
        }
    }

    /// Update the endpoint coverage maps (`self.cov_map` and `self.cov_map_total`)
    /// based on the response code `status` after sending the request with
    /// method `method` to `path`. `sequence` is the full request sequence being
    /// executed; the first time a new fault is observed, it is saved to disk (see
    /// `record_fault`).
    pub fn cover(&mut self, args: CoverArgs<'_>) {
        let CoverArgs {
            method,
            path,
            status,
            input,
            output,
            validation_error,
            sequence,
        } = args;
        if let Some(err) = &validation_error {
            self.record_fault(FaultArgs {
                method,
                path: &path,
                status,
                err,
                sequence,
                request: &input,
                response: &output,
            });
        }

        // Get the coverage entry for the method-path-status combination.
        // The entry may be Vacant or Occupied, see below for what this means.
        let entry = self
            .endpoint_cov_map
            // Use as_str to ensure "200" instead of "200 OK"
            .entry((method, path, status.as_str().to_string()));
        // Must get the index before entry.insert below, which needs ownership of the entry
        let index = entry.index();

        // Only add this testcase to the endpoint coverage map if nothing was there before
        match entry {
            // No pre-existing entry for the method-path-status combination, we found an unspecified response!
            Entry::Vacant(entry) => {
                // `validation_error` is always `Some` here: an unspecified status always
                // fails `validate_response` with `OtherStatusNotSpecified`/`Status5xxNotSpecified`,
                // which is exactly why this entry is Vacant. The fallback is defensive only.
                entry.insert(Coverage::UnexpectedFound(
                    input,
                    output,
                    validation_error.map_or_else(
                        || "Validation error required!".to_string(),
                        |val| val.to_string(),
                    ),
                ));
            }
            // Occupied entry, either already found (expected or unexpected) or expected but not yet found
            Entry::Occupied(mut entry) => {
                match entry.get() {
                    Coverage::ExpectedNotFound => {
                        // Status codes in the spec count as covered even if the one
                        // response observed for them failed validation; such a
                        // "tainted" example is upgraded below as soon as a clean one
                        // is seen, so it isn't stuck permanently doubling as a fault's
                        // own example.
                        entry.insert(Coverage::ExpectedFound(
                            input,
                            output,
                            validation_error.is_some(),
                        ));
                    }
                    Coverage::ExpectedFound(_, _, true) if validation_error.is_none() => {
                        entry.insert(Coverage::ExpectedFound(input, output, false));
                    }
                    _ => {}
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
        self.len = std::cmp::max(self.len, index + 1);
        // Map the method-path-status triplets via their index to *bits*, not bytes.
        // Hence the bitwise operations, the first 8 indices get mapped into the first byte
        // and since we always *add* coverage, we can OR the corresponding bit into that byte.
        self.cov_map[index / 8] |= 0b10000000 >> (index % 8);
        self.cov_map_total[index / 8] |= 0b10000000 >> (index % 8);
    }

    /// Records a validation error observed for a given (method, path, status),
    /// deduplicating repeated occurrences of the same fault type by incrementing
    /// a counter instead of storing a new entry.
    ///
    /// Faults are deduplicated by (method, path, status, discriminant) rather than
    /// just (method, path, discriminant): the same kind of validation error can
    /// occur at different HTTP statuses on the same endpoint (e.g. an unspecified
    /// status observed as both 404 and 409), and these represent distinct faults
    /// that should be reported separately. Since the WFC fault category for a
    /// given discriminant is a deterministic function of the status (see
    /// `reporting::wfc_report::fault_category`), including status in the key also
    /// guarantees that every entry in `faults` maps to exactly one fault category.
    ///
    /// The first time a given fault is observed, `sequence` (the full request
    /// sequence that triggered it) is saved to `CRASHES_DIR` (see
    /// `ensure_crash_file`), so WFC reports can point faults at a real, replayable
    /// test case instead of a synthetic id.
    fn record_fault(&mut self, args: FaultArgs<'_>) {
        let FaultArgs {
            method,
            path,
            status,
            err,
            sequence,
            request,
            response,
        } = args;
        let discriminant = err.discriminant();
        let status = status.as_u16();
        if let Some(existing) = self.faults.iter_mut().find(|fault| {
            fault.method == method
                && fault.path == path
                && fault.status == status
                && fault.discriminant == discriminant
        }) {
            existing.occurrences += 1;
        } else {
            self.faults.push(EndpointFault {
                method,
                path: path.to_owned(),
                status,
                discriminant,
                message: err.to_string(),
                occurrences: 1,
                test_case_name: ensure_crash_file(sequence),
                request: request.to_owned(),
                response: response.to_owned(),
            });
        }
    }

    /// Returns all distinct faults (validation errors) observed so far. Faults are
    /// deduplicated by (method, path, status, discriminant) (see `record_fault`),
    /// but otherwise returned as a flat list; callers that need faults grouped by
    /// endpoint or fault category (e.g. `reporting::wfc_report`) do so themselves.
    pub fn faults(&self) -> &[EndpointFault] {
        &self.faults
    }

    /// Returns the unique operation ids (`METHOD:path`) known from the API specification.
    pub fn endpoint_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .endpoint_cov_map
            .keys()
            .map(|(method, path, _)| format!("{method}:{path}"))
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// Returns, for every endpoint for which at least one status code was observed,
    /// the operation id (`METHOD:path`) along with the list of observed HTTP status codes.
    pub fn covered_http_status(&self) -> Vec<(String, Vec<Option<u16>>)> {
        let mut map: IndexMap<String, Vec<Option<u16>>> = IndexMap::new();
        for ((method, path, status), coverage) in &self.endpoint_cov_map {
            if matches!(
                coverage,
                Coverage::ExpectedFound(..) | Coverage::UnexpectedFound(..)
            ) {
                map.entry(format!("{method}:{path}"))
                    .or_default()
                    .push(status.parse::<u16>().ok());
            }
        }
        map.into_iter().collect()
    }

    fn export_filesystem(&self, base_path: &Path) -> Result<(), libafl::Error> {
        // Make a tree in the same structure as the html page will contain:
        // path -> method -> status codes
        let mut operation_tree =
            IndexMap::<&String, IndexMap<Method, IndexMap<String, &Coverage>>>::new();
        for ((method, path, status), cov_entry) in &self.endpoint_cov_map {
            operation_tree
                .entry(path)
                .or_default()
                .entry(*method)
                .or_default()
                .insert(status.as_str().to_string(), cov_entry);
        }
        operation_tree.sort_keys();

        // Groups faults by (method, path, status). Rather than listing fault variants
        // as extra nav entries, each status item in the tree gets a hidden sibling
        // <li> (holding a <div class="fault-variants">) with one static block per
        // distinct fault recorded for that exact method/path/status; this is never
        // shown in the nav itself, only used as a data source so the article pane
        // can display these variants (each with its own request/response/reproduce)
        // when their base status item is selected (see COVERAGE_EXPORT_JAVASCRIPT).
        let mut fault_lookup = IndexMap::<(Method, &str, u16), Vec<&EndpointFault>>::new();
        for fault in &self.faults {
            fault_lookup
                .entry((fault.method, fault.path.as_str(), fault.status))
                .or_default()
                .push(fault);
        }

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
                            |list, item| {
                                let list = match item.1 {
                                    Coverage::ExpectedFound(request, response, tainted) => {
                                        // A tainted example never had a clean (fault-free)
                                        // occurrence to upgrade to (see `cover`): its request
                                        // and response are identical to one of this status's
                                        // own fault variants, so the article pane shows a
                                        // remark instead of duplicating that content.
                                        let class = if *tainted {
                                            "input-link c-hit c-fault-only"
                                        } else {
                                            "input-link c-hit"
                                        };
                                        list.with_link_attr(
                                            "#",
                                            format!("{} {}", HIT_SYMBOL, item.0),
                                            [
                                                ("data-input", escape_html(request).as_str()),
                                                ("data-output", escape_html(response).as_str()),
                                                ("class", class),
                                            ],
                                        )
                                    }
                                    Coverage::UnexpectedFound(
                                        request,
                                        response,
                                        validation_error,
                                    ) => list.with_link_attr(
                                        "#",
                                        format!("{} {}", SUPERFLUOUS_SYMBOL, item.0),
                                        [
                                            ("data-input", escape_html(request).as_str()),
                                            ("data-output", escape_html(response).as_str()),
                                            (
                                                "validation-error",
                                                escape_html(validation_error).as_str(),
                                            ),
                                            // Status codes not in the spec are themselves a
                                            // fault (`OtherStatusNotSpecified`), always
                                            // recorded from this exact same occurrence, so
                                            // there's no separate "clean" example for these
                                            // - the article pane shows a remark instead of
                                            // duplicating the content from the fault variant.
                                            ("class", "input-link c-extra c-fault-only"),
                                        ],
                                    ),
                                    Coverage::ExpectedNotFound => list.with_raw(format!(
                                        "<a class=\"c-miss\">{} {}</a>",
                                        MISS_SYMBOL, item.0
                                    )),
                                };
                                // Add the hidden fault-variants template right after the
                                // item it belongs to (see comment on `fault_lookup` above).
                                // Status keys are always numeric (sourced from
                                // `StatusCode::as_str()`), so a parse failure can't occur.
                                let status: u16 = item.0.parse().unwrap_or_default();
                                match fault_lookup.get(&(method, path.as_str(), status)) {
                                    Some(faults) => {
                                        let blocks: String =
                                            faults.iter().copied().map(render_fault_variant).collect();
                                        // `with_raw` on a list container still wraps this
                                        // in its own (unmarked) <li>; identify it via the
                                        // inner div's class instead, which `next("li")
                                        // .children(".fault-variants")` in the JS below
                                        // can select without depending on the <li> itself.
                                        list.with_raw(format!(
                                            r#"<div class="fault-variants" style="display:none">{blocks}</div>"#
                                        ))
                                    }
                                    None => list,
                                }
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

        // A flat table of every distinct fault found, for users who want an overview
        // without clicking through the endpoint tree. Mirrors the WFC report's
        // `foundFaults`, but interactive and with a ready-to-copy reproduce command.
        let mut faults_table = Table::new().with_header_row([
            "Method & path",
            "Status",
            "Category",
            "Occurrences",
            "Message",
            "Reproducer",
        ]);
        for fault in &self.faults {
            let FaultBadge {
                category,
                reproduce,
                class,
            } = fault_badge(fault);
            let reproduce_cell = reproduce_html(reproduce.as_deref(), false);
            faults_table.add_custom_body_row(
                TableRow::new()
                    .with_cell(TableCell::new(TableCellType::Data).with_raw(format!(
                        "{} {}",
                        fault.method,
                        escape_html(&fault.path)
                    )))
                    .with_cell(
                        TableCell::new(TableCellType::Data).with_raw(fault.status.to_string()),
                    )
                    .with_cell(
                        TableCell::new(TableCellType::Data)
                            .with_raw(format!(r#"<span class="badge {class}">{category}</span>"#)),
                    )
                    .with_cell(
                        TableCell::new(TableCellType::Data).with_raw(fault.occurrences.to_string()),
                    )
                    .with_cell(
                        TableCell::new(TableCellType::Data).with_raw(message_html(&fault.message)),
                    )
                    .with_cell(TableCell::new(TableCellType::Data).with_raw(reproduce_cell)),
            );
        }

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
                    .with_attributes([("id", "tabs")])
                    .with_raw(format!(
                        r##"
                        <button id="tab-endpoints" class="tab active">Endpoints</button>
                        <button id="tab-faults" class="tab">All faults ({})</button>
                        <a id="wfc-link" href="../report.json" target="_blank" title="Only present if the campaign was run with --wfc-report">View WFC report.json &#x2197;&#xfe0f;</a>
                        "##,
                        self.faults.len()
                    )),
            )
            .with_container(
                Container::new(ContainerType::Div)
                    .with_attributes([("id", "view-endpoints"), ("class", "contents")])
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
                            .with_container(
                                Container::new(ContainerType::Div)
                                    .with_attributes([("id", "request-response-section")])
                                    .with_header(2, "Request")
                                    .with_paragraph_attr(
                                        "None selected yet",
                                        [("id", "input-pane")],
                                    )
                                    .with_header(2, "Response")
                                    .with_paragraph_attr(
                                        "None selected yet",
                                        [("id", "output-pane")],
                                    ),
                            )
                            .with_paragraph_attr(
                                "",
                                [("id", "fault-only-remark"), ("style", "display:none")],
                            )
                            .with_header(2, "Fault variants")
                            .with_paragraph_attr(
                                "None selected yet",
                                [("id", "fault-variants-pane")],
                            )
                    ),
            )
            .with_container(
                Container::new(ContainerType::Div)
                    .with_attributes([("id", "view-faults"), ("class", "contents"), ("style", "display:none")])
                    .with_container(
                        Container::new(ContainerType::Article)
                            .with_attributes([("style", "width: 100%")])
                            .with_header(2, "All faults")
                            .with_raw(faults_table.to_html_string()),
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
            // is(":visible") (rather than checking the child's own "display" style)
            // correctly treats the hidden fault-variants <li> (which has no inline
            // display:none of its own, only a hidden child div, see
            // `export_filesystem`) as invisible too, since it renders with zero size.
            return $(child).is(":visible");
        }).length > 0) { // has visible children?
            $(element).show();
        } else {
            $(element).hide();
        }
    });
    $("ul.path").children().each(function(index, element) {
        if ($(element).children().children().children().filter(function(index, child) {
            return $(child).is(":visible");
        }).length > 0) { // has visible children?
            $(element).show();
        } else {
            $(element).hide();
        }
    });
}
$(function() {
    // Delegated handler so dynamically added markup (e.g. fault variants, which
    // are static blocks not links) doesn't need its own listener; only the base
    // tree items carry the "input-link" class that this targets.
    $(document).on("click", ".input-link", function() {
        $(".input-link").css("background-color", "#00000000");
        $(this).css("background-color", "#FFFF00FF"); 
        let maybe_validation_error = $(this).attr("validation-error");
        if (maybe_validation_error === undefined) {
            maybe_validation_error = "";
        } else {
            maybe_validation_error = " - " + maybe_validation_error;
        }
        let endpoint = $(this).closest('.endpoint_path')[0].firstChild.nodeValue;
        $("#title-header").html(endpoint);
        let http_method = $(this).closest('div')[0].firstChild.nodeValue;
        let http_result = $(this).html();
        let hit_miss_unspecified = http_result.substring(0, 2);
        let http_status = http_result.substring(2);
        $("#title-pane").html([hit_miss_unspecified, http_method, http_status].join(" ") + maybe_validation_error);
        // c-fault-only status codes (unspecified ones, or specified ones that were
        // only ever observed together with a validation fault - see `cover`) have a
        // request/response that is identical to one of their own fault variants, so
        // show a remark instead of duplicating that content in #input-pane/#output-pane.
        if ($(this).hasClass("c-fault-only")) {
            $("#request-response-section").hide();
            let remark = $(this).hasClass("c-extra")
                ? "This status code is not specified in the API; every occurrence of it was recorded as a fault. See the fault variant(s) below for details."
                : "This status code is specified in the API, but it was only ever observed together with a validation fault. See the fault variant(s) below for details.";
            $("#fault-only-remark").text(remark).show();
        } else {
            $("#input-pane").html($(this).attr("data-input"));
            $("#output-pane").html($(this).attr("data-output"));
            $("#request-response-section").show();
            $("#fault-only-remark").hide();
        }
        // Fault variants for this exact status, if any, live inside a hidden
        // <div class="fault-variants"> in the very next <li> sibling (see
        // `export_filesystem`); copy its contents (static request/response/
        // reproduce blocks, nothing left to wire up) into the visible pane.
        let variants = $(this).closest("li").next("li").children(".fault-variants");
        if (variants.length) {
            $("#fault-variants-pane").html(variants.html());
        } else {
            $("#fault-variants-pane").html("No faults recorded for this status.");
        }
    });
    $("input").click(update_hidden);
    $("label").click(update_hidden);
    $("input").prop("checked", true);

    $("#tab-endpoints").click(function () {
        $("#view-faults").hide();
        $("#view-endpoints").show();
        $("#filters").show();
        $(this).addClass("active");
        $("#tab-faults").removeClass("active");
    });
    $("#tab-faults").click(function () {
        $("#view-endpoints").hide();
        $("#view-faults").show();
        $("#filters").hide();
        $(this).addClass("active");
        $("#tab-endpoints").removeClass("active");
    });

    // Delegated handler: the faults table's copy buttons are generated dynamically,
    // so attach the listener to a static ancestor rather than the buttons themselves.
    $(document).on("click", ".copy-btn", function () {
        let text = $(this).attr("data-copy");
        navigator.clipboard.writeText(text).then(function () {
            let button = this;
            let original = $(button).text();
            $(button).text("Copied!");
            setTimeout(function () {
                $(button).text(original);
            }, 1500);
        }.bind(this));
    });
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
/* Each status item in the nav tree is followed by a hidden sibling <li>, auto-
   generated by build_html, that only holds a `.fault-variants` data template
   (see `export_filesystem`). The template div itself is `display:none`, but
   list markers belong to the <li>, not its content, so without this rule that
   <li> still renders an empty bullet point in the nav. */
nav li:has(> .fault-variants) {
    display: none;
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
#fault-variants-pane {
    max-width: 100%;
    margin-right: 10pt;
}
.fault-variant {
    border-top: 1px solid #ccc;
    padding-top: 8pt;
    margin-top: 8pt;
}
.fault-variant .fv-header {
    margin-bottom: 4pt;
}
.fault-variant h4 {
    margin: 4pt 0 2pt 0;
}
.fv-pane {
    max-width: 100%;
    font-family: monospace;
    white-space: pre-wrap;
    word-break: break-all;
    background: #eee;
    padding: 5pt;
    border-radius: 4pt;
}
#filters {
    position: fixed;
    top: 5pt;
    right: 5pt;
}
#tabs {
    position: fixed;
    top: 5pt;
    left: 260pt;
}
.tab {
    font: inherit;
    padding: 4pt 10pt;
    border: 1px solid #ccc;
    border-bottom: none;
    background: #eee;
    cursor: pointer;
}
.tab.active {
    background: #fff;
    font-weight: bold;
}
#wfc-link {
    margin-left: 15pt;
}
.badge {
    display: inline-block;
    padding: 1pt 5pt;
    border-radius: 3pt;
    background: #ffe0b2;
    font-size: 0.85em;
    white-space: nowrap;
}
#view-faults table {
    border-collapse: collapse;
    /* Fixed layout + explicit column widths below keep every column (especially
       Reproducer, the last one) in its own place regardless of how long an
       individual Message cell's content is; without this, a long unbroken message
       can otherwise make the table widen unpredictably and push later columns
       onto their own line. */
    table-layout: fixed;
    width: 100%;
}
#view-faults th, #view-faults td {
    border: 1px solid #ccc;
    padding: 4pt 6pt;
    text-align: left;
    vertical-align: top;
    overflow-wrap: break-word;
}
#view-faults th {
    background: #eee;
}
#view-faults th:nth-child(1), #view-faults td:nth-child(1) { width: 18%; }
#view-faults th:nth-child(2), #view-faults td:nth-child(2) { width: 7%; }
#view-faults th:nth-child(3), #view-faults td:nth-child(3) { width: 16%; }
#view-faults th:nth-child(4), #view-faults td:nth-child(4) { width: 9%; }
#view-faults th:nth-child(5), #view-faults td:nth-child(5) { width: 35%; }
#view-faults th:nth-child(6), #view-faults td:nth-child(6) { width: 15%; }
.copy-btn {
    font-size: 0.85em;
    cursor: pointer;
}
"##;
