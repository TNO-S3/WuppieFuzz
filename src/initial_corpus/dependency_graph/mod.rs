mod normalize;
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
    parameter_access::{ParameterAddressing, ParameterMatching},
};

/// Returns OpenApiInputs generated from a dependency graph derived from the OpenAPI
/// specification. If rigorously generating parameter combinations would result in
/// too many inputs, it just generates a single example.
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
    api: &Spec,
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
///
/// Note that each Value may reference one of multiple Values in previous responses.
/// For this reason we create multiple OpenApiInputs; one for each choice of reference.
/// To avoid a combinatorial explosion, we do not take the cartesian product of these
/// reference choices but combine them more simply: say we have these target parameters
/// with their source parameters:
///
/// A -> A1, A2
/// B -> B1, B2, B3
///
/// In that case we will only create these combinations of references:
///
/// 1. A -> A1, B -> B1
/// 2. A -> A2, B -> B2
/// 3. B -> B3
///
/// For ParameterMatching::Request variants the edges are (likely) transitive (they refer to
/// earlier Values that may *also* be replaced with References based on names or
/// normalized names being equal). Therefore we only add a single Reference, to the
/// earliest matching request in the chain.
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
        // let edges = subgraph.edges_directed(target_node_index, petgraph::Direction::Incoming);
        let mut request_reference_added = false;
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
                            if !request_reference_added {
                                request_reference_added = true;
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

/// Checks if two operations are linked: an output parameter of operation 1 occurs
/// as an input parameter of operation 2. If they are linked, return the link in the
/// form of a ParameterMatching. Note that a parameter can be linked to another operation
/// twice: once to a parameter in the request and once to a parameter in the response.
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
