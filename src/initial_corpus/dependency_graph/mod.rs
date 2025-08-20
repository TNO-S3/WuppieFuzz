mod normalize;
pub mod parameter_access;
mod toposort;

/// The fuzzer wants to use outputs of previous requests (POST artist -> artistid)
/// as input to other requests (GET artist?id=1). To know which outputs to use for which inputs,
/// you need a graph that connects possible requests/operations (nodes) by parameters that carry
/// the same meaning (edges). The dependency graph module attempts to build such a graph.
use std::{
    cmp::Ordering,
    collections::{HashMap, hash_map::DefaultHasher},
    fmt::Display,
    fs::{File, create_dir_all},
    hash::{Hash, Hasher},
    io::Write,
    path::Path,
};

use openapiv3::{OpenAPI, StatusCode};
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
    initial_corpus::dependency_graph::parameter_access::ParameterMatching,
    input::{Method, OpenApiInput, ParameterContents, parameter::ParameterKind},
    openapi::{
        QualifiedOperation,
        examples::{example_from_qualified_operation, openapi_inputs_from_ops},
    },
};

/// Returns OpenApiInputs generated from a dependency graph derived from the OpenAPI
/// specification. If rigorously generating parameter combinations would result in
/// too many inputs, it just generates a single example.
pub fn initial_corpus_from_api(api: &OpenAPI) -> Vec<OpenApiInput> {
    let dependency_graph = DependencyGraph::new(api);

    // Turn all subgraphs into sorted lists of node indices
    dependency_graph
        .connected_components()
        .iter()
        .map(|nodes| dependency_graph.subgraph(nodes))
        .map(|subgraph| match ops_from_subgraph(&subgraph) {
            Ok((ops, idxs)) => {
                // TODO: pass subgraph into openapi_inputs_from_ops to prevent generation of parameter values
                // that will be replaced by references below anyway. The current implementation often
                // massively overgenerates all the different combinations, most of which then get
                // mapped back to the same OpenApiInput since all concrete parameter values get
                // overwritten with references to the same parameter in an earlier response.
                let mut inputs =
                    openapi_inputs_from_ops(api, ops.clone().into_iter(), &subgraph, &idxs)
                        .inspect_err(|err| {
                            log::warn!("{err} - falling back to single example generation.");
                        })
                        .unwrap_or(vec![openapi_example_input_from_ops(api, ops.into_iter())]);
                inputs.iter_mut().for_each(|input| {
                    add_references_to_openapi_input(&subgraph, &idxs, input);
                });
                Ok(inputs)
            }
            Err(e) => Err(e),
        })
        .filter_map(|result| result.ok())
        .flatten()
        .collect()
}

/// Creates a vector of topologically sorted QualifiedOperations (path, method, etc.)
/// from the subgraph. To let the caller keep track of the sorting, this function also
/// returns a Vec of the NodeIndex items corresponding to the QualifiedOperations.
fn ops_from_subgraph<'a>(
    subgraph: &DiGraph<QualifiedOperation<'a>, ParameterMatching, DefaultIx>,
) -> Result<(Vec<QualifiedOperation<'a>>, Vec<NodeIndex>), Cycle<NodeIndex>> {
    let sorted_nodes = match toposort(subgraph, None) {
        Ok(nodes) => nodes,
        Err(cycle) => {
            let operation = &subgraph[cycle.node_id()];
            // TODO: early-exit with this error, or support cycles
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

/// Creates an example OpenApiInput from the sequence of QualifiedOperations given by ops_iter for the given api.
fn openapi_example_input_from_ops<'a>(
    api: &OpenAPI,
    ops_iter: impl Iterator<Item = QualifiedOperation<'a>>,
) -> OpenApiInput {
    OpenApiInput(
        ops_iter
            .map(|op| example_from_qualified_operation(api, op))
            .collect(),
    )
}

/// Replace parameter Values of requests in the openapi_input with References.
/// The parameter Values for which this is done are defined by the edges in the subgraph,
/// where the source and target of each edge index into sorted_nodes to get the position
/// of the request in the openapi_input.
fn add_references_to_openapi_input(
    subgraph: &DiGraph<QualifiedOperation, ParameterMatching, DefaultIx>,
    sorted_nodes: &[NodeIndex],
    openapi_input: &mut OpenApiInput,
) {
    for edge in subgraph.edge_references() {
        assert_eq!(sorted_nodes.len(), openapi_input.0.len());
        let source_index = sorted_nodes
            .iter()
            .position(|n| *n == edge.source())
            .expect("source node of an edge not found in the graph");
        let target_index = sorted_nodes
            .iter()
            .position(|n| *n == edge.target())
            .expect("target node of an edge not found in the graph");

        // It is possible (if the API graph contains cycles) for a request
        // to refer to a future request (usually two ways to GET the same
        // kind of resource). We can of course only use backwards edges.
        if source_index >= target_index {
            continue;
        }

        // Turn the parameter of the edge's target (which at this point got a concrete
        // placeholder Value based on e.g. an example or its type) into a Reference to
        // the parameter of the same name and kind in the source.
        log::debug!("{:#?}", openapi_input.0[target_index]);
        if let Some(x) =
            openapi_input.0[target_index].get_mut_parameter(&edge.weight().name_input.clone())
        {
            *x = ParameterContents::Reference {
                request_index: source_index,
                parameter_access: edge.weight().name_output.clone(),
            };
        }
    }
}

type DepGraph<'a> = DiGraph<QualifiedOperation<'a>, ParameterMatching, DefaultIx>;

/// A dependency graph defined on the operations of an API. The edges of the graph
/// denote parameter dependencies: `O1 -> O2` means O1 returns a parameter that is
/// needed to perform O2. The edges have associated strings that contain the stem
/// (normalized form) of the parameter name.
pub struct DependencyGraph<'a> {
    /// The API that the dependency graph is about.
    graph: DepGraph<'a>,
}

impl<'a> DependencyGraph<'a> {
    pub fn new(api: &'a OpenAPI) -> Self {
        let mut graph = DiGraph::new();

        // Add all operations to the graph as nodes
        for (path, method, operation, path_item) in api.operations() {
            match QualifiedOperation::new(path, method, operation, path_item) {
                Ok(qualified_operation) => {
                    graph.add_node(qualified_operation);
                }
                Err(invalid_method) => {
                    log::error!("Invalid method for operation {method} {path}: {invalid_method}");
                }
            }
        }

        // Find all input and output parameters for all operations, cache them
        // to efficiently find edges
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
                    &inout_params[op_left.index()].1,
                    &inout_params[op_right.index()].0,
                ) {
                    graph.add_edge(op_left, op_right, link);
                }
            }
        }
        Self { graph }
    }

    /// Returns a Vec of all connected components of the graph. The nodes are
    /// referred to by NodeIndex, which is unstable under updates of the graph.
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
            writeln!(
                &mut file,
                "  {} -->|{} <-> {}| {};",
                hasher_source.finish(),
                edge.weight().name_output,
                edge.weight().name_input,
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

    /// Given the graph and a subset of nodes, returns a new graph containing only nodes and
    /// edges that exist in the given subset of nodes.
    pub fn subgraph(
        &self,
        nodes: &[NodeIndex],
    ) -> DiGraph<QualifiedOperation<'a>, ParameterMatching, DefaultIx> {
        let mut subgraph = self.graph.clone();
        subgraph.retain_nodes(|_, node| nodes.binary_search(&node).is_ok());
        subgraph
    }

    /// Return the subgraphs as a UnionFind (an efficient subset finding data
    /// structure).
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
                edge.weight().name_output,
                edge.weight().normalized,
                edge.weight().name_input,
                self.graph[edge.target()].method,
                self.graph[edge.target()].path,
            )?;
        }
        writeln!(f, "End of the graph")?;
        Ok(())
    }
}

/// Checks if two operations are linked: an output parameter of operation 1 occurs
/// as an input parameter of operation 2. If they are linked, returns the parameter
/// name in normalized form.
fn find_links<'a>(
    outputs_from_1: &'a [ParameterNormalization],
    inputs_to_2: &'a [(ParameterNormalization, ParameterKind)],
) -> Vec<ParameterMatching> {
    // Return the first input to 2 that is returned from 1
    inputs_to_2
        .iter()
        .filter_map(|input| {
            Some(ParameterMatching {
                name_output: outputs_from_1
                    .iter()
                    .find(|output| {
                        output.normalized == input.0.normalized || output.name == input.0.name
                    })?
                    .nested_context
                    .clone(),
                name_input: input.0.nested_context.clone(),
                normalized: input.0.normalized.clone(),
                kind_input: input.1,
            })
        })
        .collect()
}

/// Collects all names of parameters and fields used as input and output to this
/// operation.
fn inout_params<'a>(
    api: &'a OpenAPI,
    op: &QualifiedOperation<'a>,
) -> (
    Vec<(ParameterNormalization, ParameterKind)>,
    Vec<ParameterNormalization>,
) {
    // Outputs from a request are all field names from the response body. Collect them.
    let mut output_fields: Vec<_> = op
        .operation
        .responses
        .responses
        .iter()
        .filter(|(status_code, _)| status_is_2xx(status_code))
        .filter_map(|(_, ref_or_response)| ref_or_response.resolve(api).ok())
        .filter_map(|response| {
            normalize_response(api, op.path, response, ParameterAccess::new(vec![]))
        })
        .flatten() // Combine all 2XX responses, if multiple
        .collect();

    // Inputs to a request are all parameters. Collect those.
    let mut input_fields = normalize_parameters(api, op.path, op.operation);

    // For POST requests, also consider input parameters as output parameters!
    // (Choose your own name or ID and still be able to use it in later GET requests etc)
    // In addition, for *non*-POST requests, body return parameters count as inputs.
    // (We only count non-body parameters for POST requests as input, on the assumption
    // that a proper REST api will have 'parent' type parameters, such as 'artist' for
    // an album, in the path and not in the request body.)
    let body_fields = op
        .operation
        .request_body
        .iter()
        .filter_map(|ref_or_body| ref_or_body.resolve(api).ok())
        .find_map(|body| normalize_request_body(api, op.path, body, ParameterAccess::new(vec![])))
        .unwrap_or_default();
    if op.method == Method::Post {
        output_fields.extend(body_fields.clone());
    }
    input_fields.extend(
        body_fields
            .into_iter()
            .map(|param| (param, ParameterKind::Body)),
    );

    (input_fields, output_fields)
}

/// Checks if a StatusCode is 2XX
fn status_is_2xx(status_code: &StatusCode) -> bool {
    // The implementation is currently (1.0.1) that the Code variant is just the
    // status code, and a Range variant is nXX. This is not documented, but I
    // derived this from the Display implementation...
    // https://docs.rs/openapiv3/latest/src/openapiv3/status_code.rs.html#10
    match status_code {
        StatusCode::Code(n) => *n >= 200 && *n < 300,
        StatusCode::Range(n) => *n == 2,
    }
}
