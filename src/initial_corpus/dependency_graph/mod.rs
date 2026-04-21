//! Dependency-graph–based generation of an initial fuzzing corpus.
//!
//! # Overview
//!
//! A REST API is most effectively fuzzed when requests are issued in an order
//! that makes semantic sense: you would typically `POST /artists` to create a
//! resource before you `GET /artists/{id}` to read it.  This module infers
//! those orderings automatically from the OpenAPI specification, without any
//! manual configuration, by building a *dependency graph* over the set of
//! operations (endpoints × HTTP methods) and using it to produce a set of
//! seed [`OpenApiInput`]s that the fuzzer can then mutate.
//!
//! # Algorithm
//!
//! The entry point is [`initial_corpus_from_api`].  It performs the following
//! steps:
//!
//! 1. **Build the dependency graph** ([`DependencyGraph::new`]).  Every
//!    operation becomes a *node*.  Two nodes are connected by a directed *edge*
//!    `A → B` whenever a parameter produced by `A` matches a parameter
//!    consumed by `B` (matched by [normalized name](normalize)).  There are
//!    two kinds of edge, distinguished by [`ParameterMatching`]:
//!    - **Response edge** (`ParameterMatching::Response`): `A`'s *response*
//!      body contains a field whose normalized name matches an input parameter
//!      of `B`.  The fuzzer will substitute a back-reference at runtime, once
//!      `A` has actually been executed and has returned a value.
//!    - **Request edge** (`ParameterMatching::Request`): `A`'s *request*
//!      contains or accepts a parameter with the same normalized name as an
//!      input of `B`.  This links two requests that share a client-chosen
//!      value (e.g. a user-supplied ID), so the fuzzer keeps them in sync.
//!
//! 2. **Find connected components** ([`DependencyGraph::connected_components`]).
//!    Operations that share no parameters at all have no ordering constraints
//!    between them.  Splitting them into independent components and processing
//!    each separately keeps the combinatorics manageable.
//!
//! 3. **Topological sort** ([`ops_from_subgraph`]).  Within each component the
//!    edges define a partial order (producers before consumers).  A topological
//!    sort ([`toposort`](mod@self::toposort)) linearises this into a request
//!    sequence, with ties broken by CRUD method order (POST < GET < PUT < PATCH
//!    < DELETE).
//!
//! 4. **Generate concrete examples** ([`openapi_inputs_from_ops`] /
//!    [`openapi_example_input_from_ops`]).  For each topologically-sorted
//!    sequence of operations, generate one or more [`OpenApiInput`]s populated
//!    with concrete parameter values taken from the spec (examples, defaults,
//!    or synthesised values).
//!
//! 5. **Wire up references** ([`add_references_to_openapi_input`]).  Replace
//!    concrete parameter values with [`IReference`] / [`OReference`] pointers
//!    wherever an edge says the value should come from an earlier request in
//!    the same sequence.  Multiple wiring choices (when a parameter could be
//!    satisfied by more than one earlier operation) are each emitted as a
//!    separate [`OpenApiInput`].
//!
//! # Sub-modules
//!
//! - [`normalize`](self::normalize) — Derives a *normalized name* for each
//!   parameter so that semantically equivalent names such as `artistId`,
//!   `artist_id`, and the path parameter `id` under `/artists/` all map to the
//!   same key `artist|id`.  See that module for the full normalization rules.
//! - [`toposort`](mod@self::toposort) — A custom depth-first topological sort
//!   that breaks ties between nodes at the same graph depth using CRUD method
//!   order.
mod normalize;
mod toposort;
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet, hash_map::DefaultHasher},
    fmt::Display,
    fs::{File, create_dir_all},
    hash::{Hash, Hasher},
    io::Write,
    path::Path,
};

use petgraph::{
    prelude::{DiGraph, NodeIndex},
    stable_graph::DefaultIx,
    unionfind::UnionFind,
    visit::{EdgeRef, IntoNodeReferences, NodeIndexable},
};

use self::{
    normalize::{
        ParameterNormalization, normalize_parameters, normalize_request_body, normalize_response,
    },
    toposort::{Cycle, toposort},
};
use crate::{
    input::{
        Method, OpenApiInput, ParameterContents,
        parameter::{IReference, OReference},
    },
    openapi::{
        QualifiedOperation,
        examples::{example_from_qualified_operation, openapi_inputs_from_ops},
        spec::Spec,
    },
    parameter_access::{ParameterAccess, ParameterAddressing, ParameterMatching},
};

/// Generates seed [`OpenApiInput`]s for the fuzzer from the given API specification.
///
/// This is the top-level entry point for dependency-graph–based corpus generation.
/// See the [module documentation](self) for a description of the full algorithm.
///
/// When the number of interesting parameter combinations for a subgraph is too
/// large, the function falls back to generating a single representative example
/// per operation sequence rather than enumerating all combinations.
pub fn initial_corpus_from_api(api: &Spec) -> Vec<OpenApiInput> {
    let dependency_graph = DependencyGraph::new(api);

    // Turn all subgraphs into sorted lists of node indices
    dependency_graph
        .connected_components()
        .iter()
        .map(|nodes| dependency_graph.subgraph(nodes))
        .map(|subgraph| {
            ops_from_subgraph(&subgraph).map(|(ops, idxs)| {
                // TODO: pass subgraph into openapi_inputs_from_ops to prevent generation of parameter values
                // that will be replaced by references below anyway. The current implementation often
                // massively overgenerates all the different combinations, most of which then get
                // mapped back to the same OpenApiInput since all concrete parameter values get
                // overwritten with references to the same parameter in an earlier response.
                let inputs =
                    openapi_inputs_from_ops(api, ops.clone().into_iter(), &subgraph, &idxs)
                        .inspect_err(|err| {
                            log::warn!("{err} - falling back to single example generation.");
                        })
                        .unwrap_or(vec![openapi_example_input_from_ops(api, ops.into_iter())]);

                inputs.into_iter().flat_map(move |input| {
                    add_references_to_openapi_input(&subgraph, &idxs, &input)
                })
            })
        })
        .filter_map(|result| result.ok())
        .flatten()
        .collect()
}

/// Returns the operations in the subgraph sorted in topological (dependency) order.
///
/// The returned tuple contains:
/// - A `Vec<QualifiedOperation>` in execution order (producers before consumers).
/// - A parallel `Vec<NodeIndex>` mapping each position back to the node in the
///   subgraph, which callers need to resolve graph edges later.
///
/// Returns `Err(Cycle)` if the subgraph contains a cyclic dependency; such a
/// subgraph is skipped during corpus generation.
fn ops_from_subgraph<'a>(
    subgraph: &DiGraph<QualifiedOperation<'a>, ParameterMatching, DefaultIx>,
) -> Result<(Vec<QualifiedOperation<'a>>, Vec<NodeIndex>), Cycle<NodeIndex>> {
    let sorted_nodes = match toposort(subgraph, None) {
        Ok(nodes) => nodes,
        Err(cycle) => {
            let operation = &subgraph[cycle.node_id()];
            log::error!(
                "While building initial corpus from the API specification, found operation with a (self-)cycle {} {}",
                operation.method,
                operation.path
            );
            return Err(cycle);
        }
    };
    Ok((
        sorted_nodes
            .iter()
            .map(|index| subgraph[*index].clone())
            .collect(),
        sorted_nodes,
    ))
}

/// Creates a single-example [`OpenApiInput`] from a sequence of operations.
///
/// Each operation is populated with one representative parameter value (from
/// the spec's `example`/`default`, or a synthesised value).  This is the
/// fallback path used when full combination generation would produce too many
/// seeds.
fn openapi_example_input_from_ops<'a>(
    api: &Spec,
    ops_iter: impl Iterator<Item = QualifiedOperation<'a>>,
) -> OpenApiInput {
    OpenApiInput(
        ops_iter
            .map(|op| example_from_qualified_operation(api, op))
            .collect(),
    )
}

/// Rewires concrete parameter values inside `openapi_input` to back-references
/// wherever the subgraph has an edge saying the value can come from an earlier
/// request.
///
/// `sorted_nodes[i]` is the graph node corresponding to `openapi_input.0[i]`.
///
/// # Multiple wiring choices
///
/// A single input parameter may be satisfiable by more than one earlier
/// operation (multiple incoming edges).  Rather than returning the cartesian
/// product of all possible wirings (which would be exponential), this function
/// zips the alternatives column-by-column and returns one [`OpenApiInput`] per
/// column.  For example, if parameter A can be wired from A1 or A2, and
/// parameter B from B1, B2, or B3, the function produces:
///
/// | Output | A wired from | B wired from |
/// |--------|-------------|-------------|
/// | 1 (unwired baseline) | — | — |
/// | 2      | A1           | B1           |
/// | 3      | A2           | B2           |
/// | 4      | —            | B3           |
///
/// # Request vs. Response edges
///
/// - **Response edge** (`ParameterMatching::Response`): the value must be read
///   from the runtime response of an earlier request, so an [`OReference`] is
///   inserted.  All incoming response edges for a parameter are collected as
///   alternatives (see above).
/// - **Request edge** (`ParameterMatching::Request`): the value should mirror
///   a parameter in an earlier request, so an [`IReference`] is inserted.
///   Because request edges are typically transitive (the referenced parameter
///   may itself be referenced from an even earlier request), only the
///   *earliest* matching source is recorded per input parameter.
fn add_references_to_openapi_input(
    subgraph: &DiGraph<QualifiedOperation, ParameterMatching, DefaultIx>,
    sorted_nodes: &[NodeIndex],
    openapi_input: &OpenApiInput,
) -> Vec<OpenApiInput> {
    assert_eq!(sorted_nodes.len(), openapi_input.0.len());
    // Naming: we use source and target here as the edges are defined in the graph, i.e.
    // we are replacing Values that are targets with References to sources.
    let mut target_to_sources: HashMap<ParameterAddressing, Vec<ParameterAddressing>> =
        HashMap::new();
    for (target_index, _request) in openapi_input.0.iter().enumerate() {
        let target_node_index = sorted_nodes[target_index];
        // Track which input parameters have already been assigned a Request-type source.
        // Using a set keyed by input_access so that each distinct input parameter gets
        // its earliest matching source, rather than only the very first parameter found.
        let mut request_references_added: HashSet<ParameterAccess> = HashSet::new();
        // Consider the requests that come before the target to possibly add a reference to
        for (source_index, source_node_index) in sorted_nodes.iter().enumerate().take(target_index)
        {
            for edge in subgraph.edges_directed(target_node_index, petgraph::Direction::Incoming) {
                if *source_node_index == edge.source() && target_node_index == edge.target() {
                    match edge.weight() {
                        ParameterMatching::Request {
                            output_access,
                            input_access,
                            ..
                        } => {
                            // Only add a reference to the earliest matching source per
                            // input parameter (the edges are likely transitive).
                            if !request_references_added.contains(input_access) {
                                request_references_added.insert(input_access.clone());
                                target_to_sources
                                    .entry((target_index, input_access.clone()).into())
                                    .or_default()
                                    .push((source_index, output_access.clone()).into());
                            }
                        }
                        ParameterMatching::Response {
                            output_access,
                            input_access,
                            ..
                        } => {
                            target_to_sources
                                .entry((target_index, input_access.clone()).into())
                                .or_default()
                                .push((source_index, output_access.clone()).into());
                        }
                    }
                }
            }
        }
    }
    // Determine how many combinations we will create, this is the length of the longest list of
    // sources (we will add each target-source combination in only one request)
    let max_len = target_to_sources
        .values()
        .map(|v| v.len())
        .max()
        .unwrap_or(0);
    let mut backref_combinations: Vec<Vec<(ParameterAddressing, ParameterAddressing)>> =
        vec![Vec::new()];
    for i in 0..max_len {
        let mut new_combination = Vec::new();
        for (key, values) in &target_to_sources {
            if let Some(value) = values.get(i) {
                new_combination.push(((*key).clone(), value.clone()));
            }
        }
        if !new_combination.is_empty() {
            backref_combinations.push(new_combination);
        }
    }

    // For each combination, construct an OpenApiInput
    let mut inputs_with_references = vec![];
    for backref_combination in backref_combinations.iter() {
        let mut requests_with_references = openapi_input.0.clone();
        for target_and_source in backref_combination {
            let target = &target_and_source.0;
            let source = &target_and_source.1;
            if let Some(x) = requests_with_references[target.request_index]
                .get_mut_parameter(target.access.unwrap_request_variant())
            {
                match source.access {
                    crate::parameter_access::ParameterAccess::Request(_) => {
                        *x = ParameterContents::IReference(IReference {
                            request_index: source.request_index,
                            parameter_access: source.access.clone(),
                        });
                    }
                    crate::parameter_access::ParameterAccess::Response(_) => {
                        *x = ParameterContents::OReference(OReference {
                            request_index: source.request_index,
                            parameter_access: source.access.clone(),
                        });
                    }
                }
            }
        }
        inputs_with_references.push(OpenApiInput(requests_with_references));
    }
    inputs_with_references
}

/// The directed graph type used throughout this module.
///
/// - **Nodes** are [`QualifiedOperation`]s (an API path + HTTP method + the
///   `oas3` operation struct).
/// - **Edges** carry a [`ParameterMatching`] value that records *which*
///   parameters were matched and *how* (response output → request input, or
///   two requests sharing the same client-supplied value).
type DepGraph<'a> = DiGraph<QualifiedOperation<'a>, ParameterMatching, DefaultIx>;

/// A dependency graph over all operations in an OpenAPI specification.
///
/// **Nodes** represent individual API operations (a path + HTTP method pair).
/// **Directed edges** `A → B` mean that operation `A` produces a parameter
/// that operation `B` needs as input.  See [`DepGraph`] for the concrete graph
/// type and [`ParameterMatching`] for the two kinds of edge.
///
/// Use [`DependencyGraph::new`] to build the graph from a spec, then
/// [`DependencyGraph::connected_components`] to partition it, and
/// [`DependencyGraph::subgraph`] to extract each component for further
/// processing.
pub struct DependencyGraph<'a> {
    graph: DepGraph<'a>,
}

impl<'a> DependencyGraph<'a> {
    /// Builds a dependency graph from the given API specification.
    ///
    /// The construction proceeds in three passes:
    ///
    /// 1. **Add nodes**: one node per `(path, method)` pair.
    /// 2. **Collect I/O parameters**: for every node, derive the normalized
    ///    names of its inputs, its response-output fields, and its
    ///    request-output fields (see [`inout_params`]).
    /// 3. **Add edges**: for every ordered pair of distinct nodes `(A, B)`,
    ///    call [`find_links`] to find parameters that `A` produces and `B`
    ///    consumes.  A CRUD-order guard (`A.method ≤ B.method`) prevents
    ///    trivially circular edges between same-resource operations (e.g.
    ///    it avoids adding a GET→POST edge when the POST already implies a
    ///    later GET).
    pub fn new(api: &'a Spec) -> Self {
        let mut graph = DiGraph::new();

        // Add all operations to the graph as nodes
        for (path, method, operation) in api.operations() {
            graph.add_node(QualifiedOperation::new(path, method, operation));
        }

        // Find all input, response_output and request_output parameters for all operations,
        // cache them to efficiently find edges
        // (We save them by node index, node indices are a compact interval)
        let inout_params: Vec<_> = (0..graph.node_count())
            .map(NodeIndex::new)
            .map(|n| inout_params(api, &graph[n]))
            .collect();
        // Find edges (parameters in common) between all nodes (operations)
        for op_left in graph.node_indices() {
            for op_right in graph.node_indices() {
                // Prevent self-cycles
                if op_left == op_right {
                    continue;
                }
                // Enforce CRUD order
                if (graph[op_left].method.cmp(&graph[op_right].method)) == Ordering::Greater {
                    continue;
                }
                for link in find_links(
                    &inout_params[op_right.index()].0,
                    &inout_params[op_left.index()].1,
                    &inout_params[op_left.index()].2,
                ) {
                    graph.add_edge(op_left, op_right, link);
                }
            }
        }
        Self { graph }
    }

    /// Partitions the graph into connected components.
    ///
    /// Returns one `Vec<NodeIndex>` per component, with node indices sorted
    /// in ascending order within each component.  The order of components in
    /// the outer `Vec` is unspecified.
    ///
    /// Operations that share no parameter links end up in separate components
    /// and can be processed independently.  This avoids cross-contamination of
    /// unrelated request sequences and keeps the combinatorics bounded.
    ///
    /// **Note**: `NodeIndex` values are only stable as long as the graph is not
    /// modified.  Retain this constraint when using the returned indices.
    pub fn connected_components(&self) -> Vec<Vec<NodeIndex>> {
        let mut vertex_sets = self.union_find();

        // The UnionFind will point you to a representative for each vertex.
        // The representative is a usize (from to_index), so we use that to
        // keep track of our subgraphs.
        let mut subgraphs = HashMap::new();
        for operation in self.graph.node_indices() {
            let representative = vertex_sets.find_mut(operation);
            subgraphs
                .entry(representative)
                .or_insert_with(Vec::new)
                .push(operation)
        }

        subgraphs
            .into_values()
            .map(|mut subgraph| {
                subgraph.sort_unstable();
                subgraph
            })
            .collect()
    }

    /// Writes a human-readable Mermaid diagram of the dependency graph.
    ///
    /// Creates `<report_path>/corpus/mermaid_graph.md`, which contains a
    /// Mermaid `graph LR` block showing every operation as a node and every
    /// parameter dependency as a labelled edge.  Connected components are
    /// wrapped in Mermaid `subgraph` blocks.
    ///
    /// The file can be viewed with any Mermaid-capable Markdown renderer (e.g.
    /// the VS Code Mermaid extension, GitHub's Markdown preview, or
    /// <https://mermaid.live>).
    pub fn write_report(&self, report_path: &Path) -> std::io::Result<()> {
        let corpus_path = report_path.join("corpus");
        create_dir_all(&corpus_path)?;
        let corpus_file = corpus_path.join("mermaid_graph.md");
        let mut file = File::create(corpus_file)?;

        writeln!(file, "# Dependency graph based on OpenAPI spec\n")?;
        writeln!(
            file,
            "This markdown document can be rendered using a Mermaid plugin. It demonstrates the discovered dependencies between API requests.\n"
        )?;
        writeln!(file, "```mermaid")?;
        writeln!(file, "graph LR;")?;

        writeln!(file, "  %% Nodes")?;
        for node in self.graph.node_references() {
            let mut hasher = DefaultHasher::new();
            node.0.hash(&mut hasher);
            writeln!(
                &mut file,
                "  {}(\"{} {}\");",
                hasher.finish(),
                self.graph[node.0].method,
                self.graph[node.0].path
            )?;
        }

        writeln!(file, "  %% Edges")?;
        for edge in self.graph.edge_references() {
            let mut hasher_source = DefaultHasher::new();
            let mut hasher_target = DefaultHasher::new();
            edge.source().hash(&mut hasher_source);
            edge.target().hash(&mut hasher_target);
            let arrow = match edge.weight() {
                ParameterMatching::Request { .. } => "< I >",
                ParameterMatching::Response { .. } => "< O >",
            };
            writeln!(
                &mut file,
                "  {} -->|\"{} {} {} ({})\"| {};",
                hasher_source.finish(),
                edge.weight().output_access(),
                arrow,
                edge.weight().input_access(),
                edge.weight().input_name_normalized(),
                hasher_target.finish(),
            )?;
        }
        writeln!(file, "  %% Connected components")?;
        let mut components = self.connected_components();
        components.sort_by_key(|vec| vec.len());
        for (index, component) in components.iter().enumerate() {
            writeln!(file, "  subgraph connected_component_{index};")?;
            writeln!(file, "    direction LR;")?;
            for node in component {
                let mut hasher = DefaultHasher::new();
                node.hash(&mut hasher);
                writeln!(file, "    {};", hasher.finish())?;
            }
            writeln!(file, "  end;")?;
        }

        writeln!(file, "```")?;

        Ok(())
    }

    /// Extracts a subgraph containing only the given nodes (and their mutual edges).
    ///
    /// `nodes` must be sorted in ascending order (as returned by
    /// [`connected_components`](Self::connected_components)) because the
    /// implementation uses binary search to filter nodes.
    pub fn subgraph(
        &self,
        nodes: &[NodeIndex],
    ) -> DiGraph<QualifiedOperation<'a>, ParameterMatching, DefaultIx> {
        let mut subgraph = self.graph.clone();
        subgraph.retain_nodes(|_, node| nodes.binary_search(&node).is_ok());
        subgraph
    }

    /// Builds a [`UnionFind`] structure that groups nodes into connected components.
    ///
    /// Each edge `A → B` in the graph causes `A` and `B` to be placed in the
    /// same set.  After processing all edges, nodes in the same set belong to
    /// the same connected component.  [`connected_components`](Self::connected_components)
    /// uses this to efficiently enumerate those sets.
    fn union_find(&self) -> UnionFind<NodeIndex> {
        let mut vertex_sets = UnionFind::new(self.graph.node_bound());
        for edge in self.graph.edge_references() {
            // Unify the two sets containing these vertices, i.e. they are in
            // the same set
            vertex_sets.union(edge.source(), edge.target());
        }
        vertex_sets
    }
}

impl Display for DependencyGraph<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Here comes the graph:\nnode -- edge (param-out normalized param-in) -- node"
        )?;
        for edge in self.graph.edge_references() {
            writeln!(
                f,
                "{} {} -- ({} {} {}) -> {} {}",
                self.graph[edge.source()].method,
                self.graph[edge.source()].path,
                edge.weight().output_access(),
                edge.weight().input_name_normalized(),
                edge.weight().input_access(),
                self.graph[edge.target()].method,
                self.graph[edge.target()].path,
            )?;
        }
        writeln!(f, "End of the graph")?;
        Ok(())
    }
}

/// Finds all dependency edges from operation 1 to operation 2.
///
/// An edge exists whenever an output parameter of op 1 has the same
/// [normalized name](normalize) as an input parameter of op 2.  There are two
/// independent output sets to check against (see [`inout_params`]):
///
/// - **Response outputs** (fields returned in the HTTP response body of op 1):
///   produce a [`ParameterMatching::Response`] edge.  The actual value is only
///   available at runtime after op 1 has been executed.
/// - **Request outputs** (parameters sent *in* the request for op 1, or its
///   POST body): produce a [`ParameterMatching::Request`] edge.  This links
///   two requests that should carry the same client-chosen value.
///
/// A single input parameter may generate one edge of each kind if both output
/// sets happen to contain a matching name.
fn find_links<'a>(
    inputs_to_2: &'a [ParameterNormalization],
    response_outputs_from_1: &'a [ParameterNormalization],
    request_outputs_from_1: &'a [ParameterNormalization],
) -> Vec<ParameterMatching> {
    // Finds links with responses
    inputs_to_2
        .iter()
        .filter_map(|input| {
            Some(ParameterMatching::Response {
                output_access: response_outputs_from_1
                    .iter()
                    .find(|output| {
                        output.normalized == input.normalized // || output.name == input.name
                    })?
                    .parameter_access
                    .clone(),
                input_access: input.parameter_access.clone(),
                input_name_normalized: input.normalized.clone(),
            })
        })
        // Adds links with requests
        .chain(inputs_to_2.iter().filter_map(|input| {
            Some(ParameterMatching::Request {
                output_access: request_outputs_from_1
                    .iter()
                    .find(|output| output.normalized == input.normalized)?
                    .parameter_access
                    .clone(),
                input_access: input.parameter_access.clone(),
                input_name_normalized: input.normalized.clone(),
            })
        }))
        .collect()
}

/// Collects all ParameterNormalizations used as inputs and outputs for the QualifiedOperation.
/// "Inputs" are variables to be passed into a request.
/// "Outputs" come in two flavors:
///   1. "Response Outputs": variables to be returned by the server at runtime,
///      which can be reused as inputs.
///   2. "Request Outputs": variables in POST requests, which should possibly be reused in
///      other requests (e.g. two requests that should use the same user ID).
///
/// The order of the return value is: (inputs, response_outputs, request_outputs).
fn inout_params<'a>(
    api: &'a Spec,
    op: &QualifiedOperation<'a>,
) -> (
    Vec<ParameterNormalization>,
    Vec<ParameterNormalization>,
    Vec<ParameterNormalization>,
) {
    // All field names from the response body are outputs to potentially refer back to. Collect them.
    let response_output_fields: Vec<_> = op
        .operation
        .responses
        .iter()
        .flatten()
        .filter_map(|(_, ref_or_response)| ref_or_response.resolve(api).ok())
        .filter_map(|response| {
            normalize_response(
                api,
                &response,
                op.path.split('/').map(String::from).collect(),
            )
        })
        // Flatten normalizations into one big collection (not grouped per Response)
        .flatten()
        .collect();

    // All parameters are inputs for the request. Collect those.
    let mut input_fields = normalize_parameters(api, &op.path, op.operation);
    // If two operations have the same parameters, they can be input-linked, so also consider these "request outputs".
    let mut request_output_fields = input_fields.clone();

    // For POST requests, also consider body fields as "request output" parameters.
    // (Choose your own name or ID and still be able to use it in later GET requests etc)
    let request_body_fields = op
        .operation
        .request_body
        .iter()
        .filter_map(|ref_or_body| ref_or_body.resolve(api).ok())
        .find_map(|body| {
            normalize_request_body(api, &body, op.path.split('/').map(String::from).collect())
        })
        .unwrap_or_default();
    if op.method == Method::Post {
        request_output_fields.extend_from_slice(&request_body_fields);
    }
    input_fields.extend(request_body_fields);

    (input_fields, response_output_fields, request_output_fields)
}
