mod normalize;
mod toposort;

/// The fuzzer wants to use outputs of previous requests (POST artist -> artistid)
/// as input to other requests (GET artist?id=1). To know which outputs to use for which inputs,
/// you need a graph that connects possible requests/operations (nodes) by parameters that carry
/// the same meaning (edges). The dependency graph module attempts to build such a graph.
use std::{
    cmp::Ordering,
    collections::{HashMap, VecDeque, hash_map::DefaultHasher},
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
    configuration::CorpusSequenceMode,
    input::{
        Method, OpenApiInput, ParameterContents,
        parameter::{IReference, OReference},
    },
    openapi::{
        QualifiedOperation,
        examples::{all_interesting_inputs_for_operations, example_request_for_operation},
        spec::Spec,
    },
    parameter_access::{ParameterAddressing, ParameterMatching},
};

/// Returns OpenApiInputs generated from a dependency graph derived from the OpenAPI
/// specification. If rigorously generating parameter combinations would result in
/// too many inputs, it just generates a single example.
pub fn initial_corpus_from_api(
    api: &Spec,
    corpus_sequence_mode: CorpusSequenceMode,
    full_path_config: PathGenerationConfig,
) -> Vec<OpenApiInput> {
    let enforce_crud = match corpus_sequence_mode {
        CorpusSequenceMode::Crud => true,
        CorpusSequenceMode::Full => full_path_config.enforce_crud_order,
    };
    let dependency_graph = DependencyGraph::new(api, enforce_crud);

    match corpus_sequence_mode {
        CorpusSequenceMode::Crud => {
            // Turn all subgraphs into sorted lists of node indices
            dependency_graph
                .connected_components()
                .iter()
                .map(|nodes| dependency_graph.subgraph(nodes))
                .map(|subgraph| {
                    ops_from_subgraph(&subgraph).map(|(ops, idxs)| {
                        let inputs = all_interesting_inputs_for_operations(
                            api,
                            ops.clone().into_iter(),
                            &subgraph,
                            &idxs,
                        )
                        .inspect_err(|err| {
                            log::warn!("{err} - falling back to single example generation.");
                        })
                        .unwrap_or_else(|_| {
                            vec![openapi_example_input_from_ops(api, ops.into_iter())]
                        });

                        inputs.into_iter().flat_map(move |input| {
                            add_references_to_openapi_input(&subgraph, &idxs, &input)
                        })
                    })
                })
                .filter_map(|result| result.ok())
                .flatten()
                .collect()
        }
        CorpusSequenceMode::Full => dependency_graph
            .connected_components()
            .iter()
            .map(|nodes| dependency_graph.subgraph(nodes))
            .flat_map(|subgraph| {
                openapi_inputs_for_first_n_subgraph_paths(
                    api,
                    &subgraph,
                    full_path_config.max_paths,
                    full_path_config,
                )
            })
            .collect(),
    }
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
            .map(|op| example_request_for_operation(api, op))
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

/// Configuration for path enumeration in dependency subgraphs.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub struct PathGenerationConfig {
    /// Minimum number of operations (nodes) a path should contain.
    pub min_path_length: usize,
    /// Maximum number of revisits per node. For example, `0` means each node can occur at most once.
    pub max_revisits: usize,
    /// Hard cap on the number of paths to generate to avoid path-space explosion.
    pub max_paths: usize,
    /// Whether to enforce CRUD method ordering (POST before GET before DELETE, etc.).
    /// When true, edges only go from lower to higher CRUD-ordered methods, producing a DAG.
    /// When false, edges can go in any direction, allowing cycles.
    pub enforce_crud_order: bool,
    /// Minimum cycle size allowed in the dependency graph.
    /// 1 = self-loops allowed, 2 = no self-loops (default).
    pub min_cycle_size: usize,
}

impl Default for PathGenerationConfig {
    fn default() -> Self {
        Self {
            min_path_length: 1,
            max_revisits: 0,
            max_paths: 1000,
            enforce_crud_order: false,
            min_cycle_size: 2,
        }
    }
}

/// Returns the first `n` paths from a connected subgraph in breadth-first order.
///
/// Assumes `subgraph` is connected. If this is not the case, the function logs an error and returns
/// an empty vector.
#[allow(dead_code)]
pub fn first_n_path_indices_from_subgraph(
    subgraph: &DepGraph<'_>,
    n: usize,
    mut config: PathGenerationConfig,
) -> Vec<Vec<NodeIndex>> {
    if n == 0 {
        return Vec::new();
    }
    config.max_paths = config.max_paths.min(n);
    enumerate_paths_breadth_first(subgraph, config)
}

/// Returns the path identified by `index` in breadth-first order.
///
/// Assumes `subgraph` is connected. If this is not the case, the function logs an error and returns
/// `None`.
#[allow(dead_code)]
pub fn nth_path_indices_from_subgraph(
    subgraph: &DepGraph<'_>,
    index: u64,
    config: PathGenerationConfig,
) -> Option<Vec<NodeIndex>> {
    let Ok(n) = usize::try_from(index.saturating_add(1)) else {
        log::error!("Path index {index} does not fit in usize on this platform.");
        return None;
    };
    first_n_path_indices_from_subgraph(subgraph, n, config)
        .into_iter()
        .nth(index as usize)
}

/// Returns all OpenApiInputs for the first `n` enumerated paths in `subgraph`.
///
/// Each path is converted to an example input and then references are added based on edges in the
/// same subgraph.
#[allow(dead_code)]
pub fn openapi_inputs_for_first_n_subgraph_paths(
    api: &Spec,
    subgraph: &DepGraph<'_>,
    n: usize,
    config: PathGenerationConfig,
) -> Vec<OpenApiInput> {
    first_n_path_indices_from_subgraph(subgraph, n, config)
        .into_iter()
        .flat_map(|path| {
            let ops = path.iter().map(|idx| subgraph[*idx].clone());
            let input = openapi_example_input_from_ops(api, ops);
            add_references_to_openapi_input(subgraph, &path, &input)
        })
        .collect()
}

/// Returns all OpenApiInputs corresponding to the enumerated path identified by `index`.
#[allow(dead_code)]
pub fn openapi_inputs_for_subgraph_path_index(
    api: &Spec,
    subgraph: &DepGraph<'_>,
    index: u64,
    config: PathGenerationConfig,
) -> Option<Vec<OpenApiInput>> {
    let path = nth_path_indices_from_subgraph(subgraph, index, config)?;
    let ops = path.iter().map(|idx| subgraph[*idx].clone());
    let input = openapi_example_input_from_ops(api, ops);
    Some(add_references_to_openapi_input(subgraph, &path, &input))
}

fn connected_component_count<N, E>(graph: &DiGraph<N, E, DefaultIx>) -> usize {
    if graph.node_count() == 0 {
        return 0;
    }
    let mut vertex_sets = UnionFind::new(graph.node_bound());
    for edge in graph.edge_references() {
        vertex_sets.union(edge.source(), edge.target());
    }
    let mut representatives = std::collections::HashSet::new();
    for node in graph.node_indices() {
        representatives.insert(vertex_sets.find_mut(node));
    }
    representatives.len()
}

fn enumerate_paths_breadth_first<N, E>(
    graph: &DiGraph<N, E, DefaultIx>,
    config: PathGenerationConfig,
) -> Vec<Vec<NodeIndex>> {
    if graph.node_count() == 0 || config.max_paths == 0 {
        return Vec::new();
    }

    let components = connected_component_count(graph);
    if components != 1 {
        log::error!(
            "Path generation requires a connected subgraph; received {components} connected components."
        );
        return Vec::new();
    }

    let max_possible_path_length = graph
        .node_count()
        .saturating_mul(1usize.saturating_add(config.max_revisits));
    if config.min_path_length > max_possible_path_length {
        log::error!(
            "No paths generated: min_path_length={} is too large for subgraph size={} with max_revisits={}",
            config.min_path_length,
            graph.node_count(),
            config.max_revisits
        );
        return Vec::new();
    }

    let mut queue: VecDeque<Vec<NodeIndex>> = graph.node_indices().map(|n| vec![n]).collect();
    let mut result = Vec::new();
    while let Some(path) = queue.pop_front() {
        if path.len() >= config.min_path_length {
            result.push(path.clone());
            if result.len() >= config.max_paths {
                log::error!(
                    "Path generation reached max_paths={} limit; truncating enumeration.",
                    config.max_paths
                );
                break;
            }
        }

        let Some(last) = path.last().copied() else {
            continue;
        };
        for neighbor in graph.neighbors(last) {
            let occurrences = path.iter().filter(|&&node| node == neighbor).count();
            if occurrences < 1 + config.max_revisits {
                // Enforce min_cycle_size: skip if the neighbor was visited too recently
                if path
                    .iter()
                    .rposition(|&n| n == neighbor)
                    .is_some_and(|last_pos| path.len() - last_pos < config.min_cycle_size)
                {
                    continue;
                }
                let mut extended = path.clone();
                extended.push(neighbor);
                queue.push_back(extended);
            }
        }
    }

    if result.is_empty() {
        log::error!(
            "No paths generated: min_path_length={} is too large for subgraph size={} with max_revisits={}",
            config.min_path_length,
            graph.node_count(),
            config.max_revisits
        );
    }

    result
}

/// A dependency graph defined on the operations of an API. The edges of the graph
/// denote parameter dependencies: `O1 -> O2` means O1 returns a parameter that is
/// needed to perform O2. The edges have associated strings that contain the stem
/// (normalized form) of the parameter name.
pub struct DependencyGraph<'a> {
    /// The API that the dependency graph is about.
    graph: DepGraph<'a>,
}

impl<'a> DependencyGraph<'a> {
    pub fn new(api: &'a Spec, enforce_crud_order: bool) -> Self {
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
                // Enforce CRUD order (if configured)
                if enforce_crud_order
                    && (graph[op_left].method.cmp(&graph[op_right].method)) == Ordering::Greater
                {
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

#[cfg(test)]
mod tests {
    use super::{PathGenerationConfig, enumerate_paths_breadth_first};
    use petgraph::prelude::DiGraph;

    #[test]
    fn enumerate_paths_orders_by_breadth_first_length() {
        let mut graph = DiGraph::<(), (), _>::new();
        let n0 = graph.add_node(());
        let n1 = graph.add_node(());

        // Check that without edges, no paths are returned.
        let paths = enumerate_paths_breadth_first(
            &graph,
            PathGenerationConfig {
                min_path_length: 1,
                max_revisits: 0,
                max_paths: 10,
                enforce_crud_order: false,
                min_cycle_size: 2,
            },
        );
        assert!(paths.is_empty());

        graph.add_edge(n0, n1, ());
        graph.add_edge(n1, n0, ());

        let paths = enumerate_paths_breadth_first(
            &graph,
            PathGenerationConfig {
                min_path_length: 1,
                max_revisits: 2,
                max_paths: 10,
                enforce_crud_order: false,
                min_cycle_size: 2,
            },
        );

        // With BFS, path lengths should never decrease.
        let lengths: Vec<usize> = paths.iter().map(Vec::len).collect();
        assert!(lengths.windows(2).all(|w| w[0] <= w[1]));

        // The first layer should contain all single-node paths.
        assert_eq!(lengths[0], 1);
        assert_eq!(lengths[1], 1);
        // With the graph of two nodes, the remaining paths should be longer.
        assert!(lengths.len() > 2);
        for length in lengths.iter().skip(2) {
            assert_ne!(*length, 1);
        }
    }

    #[test]
    fn enumerate_paths_returns_empty_when_min_path_length_is_infeasible() {
        let mut graph = DiGraph::<(), (), _>::new();
        let n0 = graph.add_node(());
        let n1 = graph.add_node(());
        graph.add_edge(n0, n1, ());
        graph.add_edge(n1, n0, ());
        let paths = enumerate_paths_breadth_first(
            &graph,
            PathGenerationConfig {
                min_path_length: 3,
                max_revisits: 3,
                max_paths: 10,
                enforce_crud_order: false,
                min_cycle_size: 3,
            },
        );

        assert!(paths.is_empty());
    }

    #[test]
    fn enumerate_paths_respects_max_paths_limit() {
        let mut graph = DiGraph::<(), (), _>::new();
        let n0 = graph.add_node(());
        let n1 = graph.add_node(());
        let n2 = graph.add_node(());
        graph.add_edge(n0, n1, ());
        graph.add_edge(n1, n2, ());
        // max_paths makes the n0->n1->n2 path be omitted
        let paths = enumerate_paths_breadth_first(
            &graph,
            PathGenerationConfig {
                min_path_length: 1,
                max_revisits: 3,
                max_paths: 4,
                enforce_crud_order: false,
                min_cycle_size: 2,
            },
        );

        assert_eq!(paths.len(), 4);
    }

    #[test]
    fn dependency_graph_crud_ordering_and_cycles() {
        use super::{DependencyGraph, first_n_path_indices_from_subgraph};
        use crate::openapi::spec::Spec;
        use oas3::spec::{
            Info, MediaType, ObjectOrReference, ObjectSchema, Operation, Parameter, PathItem,
            RequestBody, Response, SchemaType, SchemaTypeSet,
        };
        use petgraph::visit::EdgeRef;
        use std::cmp::Ordering;
        use std::collections::BTreeMap;

        // Helper: create an object schema with given field names (all string type)
        fn object_schema_with_fields(fields: &[&str]) -> ObjectSchema {
            let mut properties = BTreeMap::new();
            for &field in fields {
                properties.insert(
                    field.to_string(),
                    ObjectOrReference::Object(ObjectSchema {
                        schema_type: Some(SchemaTypeSet::Single(SchemaType::String)),
                        ..Default::default()
                    }),
                );
            }
            ObjectSchema {
                schema_type: Some(SchemaTypeSet::Single(SchemaType::Object)),
                properties,
                ..Default::default()
            }
        }

        // Helper: create a JSON response with given body fields
        fn json_response(fields: &[&str]) -> BTreeMap<String, ObjectOrReference<Response>> {
            let mut content = BTreeMap::new();
            content.insert(
                "application/json".to_string(),
                MediaType {
                    schema: Some(ObjectOrReference::Object(object_schema_with_fields(fields))),
                    ..Default::default()
                },
            );
            let mut responses = BTreeMap::new();
            responses.insert(
                "200".to_string(),
                ObjectOrReference::Object(Response {
                    description: Default::default(),
                    headers: Default::default(),
                    content,
                    links: Default::default(),
                    extensions: Default::default(),
                }),
            );
            responses
        }

        // Helper: create a JSON request body with given fields
        fn json_request_body(fields: &[&str]) -> Option<ObjectOrReference<RequestBody>> {
            let mut content = BTreeMap::new();
            content.insert(
                "application/json".to_string(),
                MediaType {
                    schema: Some(ObjectOrReference::Object(object_schema_with_fields(fields))),
                    ..Default::default()
                },
            );
            Some(ObjectOrReference::Object(RequestBody {
                description: Default::default(),
                content,
                required: Default::default(),
            }))
        }

        // Build a 4-operation spec:
        // POST /item    body: {value}  response: {id}
        // GET /item     query: value   response: {id}
        // GET /item/{id}  path: id
        // DELETE /item/{id}  path: id
        let mut paths = BTreeMap::new();

        // /item path: POST and GET
        paths.insert(
            "/item".to_string(),
            PathItem {
                post: Some(Operation {
                    request_body: json_request_body(&["value"]),
                    responses: Some(json_response(&["id"])),
                    ..Default::default()
                }),
                get: Some(Operation {
                    parameters: vec![ObjectOrReference::Object(Parameter {
                        name: "value".to_string(),
                        location: oas3::spec::ParameterIn::Query,
                        description: Default::default(),
                        required: Default::default(),
                        deprecated: Default::default(),
                        allow_empty_value: Default::default(),
                        style: Default::default(),
                        explode: Default::default(),
                        allow_reserved: Default::default(),
                        schema: Default::default(),
                        example: Default::default(),
                        examples: Default::default(),
                        content: Default::default(),
                        extensions: Default::default(),
                    })],
                    responses: Some(json_response(&["id"])),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );

        // /item/{id} path: GET and DELETE
        paths.insert(
            "/item/{id}".to_string(),
            PathItem {
                get: Some(Operation {
                    parameters: vec![ObjectOrReference::Object(Parameter {
                        name: "id".to_string(),
                        location: oas3::spec::ParameterIn::Path,
                        description: Default::default(),
                        required: Default::default(),
                        deprecated: Default::default(),
                        allow_empty_value: Default::default(),
                        style: Default::default(),
                        explode: Default::default(),
                        allow_reserved: Default::default(),
                        schema: Default::default(),
                        example: Default::default(),
                        examples: Default::default(),
                        content: Default::default(),
                        extensions: Default::default(),
                    })],
                    ..Default::default()
                }),
                delete: Some(Operation {
                    parameters: vec![ObjectOrReference::Object(Parameter {
                        name: "id".to_string(),
                        location: oas3::spec::ParameterIn::Path,
                        description: Default::default(),
                        required: Default::default(),
                        deprecated: Default::default(),
                        allow_empty_value: Default::default(),
                        style: Default::default(),
                        explode: Default::default(),
                        allow_reserved: Default::default(),
                        schema: Default::default(),
                        example: Default::default(),
                        examples: Default::default(),
                        content: Default::default(),
                        extensions: Default::default(),
                    })],
                    ..Default::default()
                }),
                ..Default::default()
            },
        );

        let spec: Spec = oas3::Spec {
            openapi: "3.1.0".to_string(),
            info: Info {
                title: Default::default(),
                summary: Default::default(),
                description: Default::default(),
                terms_of_service: Default::default(),
                version: Default::default(),
                contact: Default::default(),
                license: Default::default(),
                extensions: Default::default(),
            },
            servers: Default::default(),
            paths: Some(paths),
            components: Default::default(),
            security: Default::default(),
            tags: Default::default(),
            webhooks: Default::default(),
            external_docs: Default::default(),
            extensions: Default::default(),
        }
        .into();

        // Test 1: With enforce_crud_order=true, all edges go from lower to higher CRUD method order
        let graph_crud = DependencyGraph::new(&spec, true);
        let _components_crud = graph_crud.connected_components();
        for edge in graph_crud.graph.edge_references() {
            let source_method = &graph_crud.graph[edge.source()].method;
            let target_method = &graph_crud.graph[edge.target()].method;
            assert!(
                source_method.cmp(target_method) != Ordering::Greater,
                "CRUD graph has edge from {:?} to {:?}, violating CRUD ordering",
                source_method,
                target_method,
            );
        }

        // Test 2: Without enforce_crud_order and with min_cycle_size=1 (self-loops allowed),
        // exactly 2 backward edges and 4 self-loops exist
        let graph_no_crud = DependencyGraph::new(&spec, false);
        let backward_edge_count = graph_no_crud
            .graph
            .edge_references()
            .filter(|edge| {
                let source_method = &graph_no_crud.graph[edge.source()].method;
                let target_method = &graph_no_crud.graph[edge.target()].method;
                source_method.cmp(target_method) == Ordering::Greater
            })
            .count();
        assert_eq!(
            backward_edge_count, 2,
            "Expected exactly 2 backward edges (GET→POST, DELETE→GET), got {}",
            backward_edge_count
        );
        let self_loop_count = graph_no_crud
            .graph
            .edge_references()
            .filter(|edge| edge.source() == edge.target())
            .count();
        assert_eq!(
            self_loop_count, 4,
            "Expected exactly 4 self-loops (one per operation), got {}",
            self_loop_count
        );

        // Test 3: With revisits, the non-CRUD graph produces more paths due to backward edges.
        let config_with_revisits = PathGenerationConfig {
            min_path_length: 1,
            max_revisits: 1,
            max_paths: 1000,
            enforce_crud_order: false,
            min_cycle_size: 2,
        };
        let config_crud_with_revisits = PathGenerationConfig {
            min_path_length: 1,
            max_revisits: 1,
            max_paths: 1000,
            enforce_crud_order: false, // doesn't matter here, graph already built
            min_cycle_size: 2,
        };

        // Build subgraphs and enumerate paths
        let paths_crud =
            first_n_path_indices_from_subgraph(&graph_crud.graph, 1000, config_crud_with_revisits);
        let paths_no_crud =
            first_n_path_indices_from_subgraph(&graph_no_crud.graph, 1000, config_with_revisits);

        // The CRUD graph is a DAG (edges only go from lower to higher CRUD methods),
        // producing exactly 15 paths. The non-CRUD graph has backward edges between
        // different methods, producing (found by just running it) exactly 80 paths.
        assert_eq!(
            paths_crud.len(),
            15,
            "CRUD graph should produce exactly 15 paths"
        );
        assert_eq!(
            paths_no_crud.len(),
            80,
            "Non-CRUD graph should produce exactly 80 paths"
        );

        // Test 4: max_paths truncation works
        let config_limited = PathGenerationConfig {
            min_path_length: 1,
            max_revisits: 1,
            max_paths: 2,
            enforce_crud_order: false,
            min_cycle_size: 1,
        };
        let paths_limited =
            first_n_path_indices_from_subgraph(&graph_no_crud.graph, 2, config_limited);
        assert!(
            paths_limited.len() <= 2,
            "max_paths should limit output to at most 2 paths"
        );
    }

    #[test]
    fn ops_from_subgraph_returns_error_on_self_loop() {
        use super::{DependencyGraph, ops_from_subgraph};
        use crate::openapi::spec::Spec;
        use oas3::spec::{
            Info, MediaType, ObjectOrReference, ObjectSchema, Operation, Parameter, PathItem,
            Response, SchemaType, SchemaTypeSet,
        };
        use petgraph::visit::EdgeRef;
        use std::collections::BTreeMap;

        // Create a spec with a single GET operation whose response output "id"
        // matches its own input query parameter "id", producing a self-loop.
        let mut properties = BTreeMap::new();
        properties.insert(
            "id".to_string(),
            ObjectOrReference::Object(ObjectSchema {
                schema_type: Some(SchemaTypeSet::Single(SchemaType::String)),
                ..Default::default()
            }),
        );
        let response_schema = ObjectSchema {
            schema_type: Some(SchemaTypeSet::Single(SchemaType::Object)),
            properties,
            ..Default::default()
        };

        let mut content = BTreeMap::new();
        content.insert(
            "application/json".to_string(),
            MediaType {
                schema: Some(ObjectOrReference::Object(response_schema)),
                ..Default::default()
            },
        );
        let mut responses = BTreeMap::new();
        responses.insert(
            "200".to_string(),
            ObjectOrReference::Object(Response {
                description: Default::default(),
                headers: Default::default(),
                content,
                links: Default::default(),
                extensions: Default::default(),
            }),
        );

        let mut paths = BTreeMap::new();
        paths.insert(
            "/item".to_string(),
            PathItem {
                get: Some(Operation {
                    parameters: vec![ObjectOrReference::Object(Parameter {
                        name: "id".to_string(),
                        location: oas3::spec::ParameterIn::Query,
                        description: Default::default(),
                        required: Default::default(),
                        deprecated: Default::default(),
                        allow_empty_value: Default::default(),
                        style: Default::default(),
                        explode: Default::default(),
                        allow_reserved: Default::default(),
                        schema: Default::default(),
                        example: Default::default(),
                        examples: Default::default(),
                        content: Default::default(),
                        extensions: Default::default(),
                    })],
                    responses: Some(responses),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );

        let spec: Spec = oas3::Spec {
            openapi: "3.1.0".to_string(),
            info: Info {
                title: Default::default(),
                summary: Default::default(),
                description: Default::default(),
                terms_of_service: Default::default(),
                version: Default::default(),
                contact: Default::default(),
                license: Default::default(),
                extensions: Default::default(),
            },
            servers: Default::default(),
            paths: Some(paths),
            components: Default::default(),
            security: Default::default(),
            tags: Default::default(),
            webhooks: Default::default(),
            external_docs: Default::default(),
            extensions: Default::default(),
        }
        .into();

        // Build the dependency graph with CRUD ordering enabled.
        // Since we removed min_cycle_size from graph construction, self-loops are present.
        let graph = DependencyGraph::new(&spec, true);

        let self_loop_count = graph
            .graph
            .edge_references()
            .filter(|edge| edge.source() == edge.target())
            .count();
        assert!(
            self_loop_count > 0,
            "Expected self-loops in the CRUD graph, but found none"
        );

        // ops_from_subgraph calls toposort, which should fail on self-loops.
        for nodes in graph.connected_components() {
            let subgraph = graph.subgraph(&nodes);
            let result = ops_from_subgraph(&subgraph);
            assert!(
                result.is_err(),
                "Expected toposort to fail due to self-loop in CRUD graph"
            );
        }
    }

    #[test]
    fn ops_from_subgraph_returns_error_on_longer_cycle() {
        use super::{DependencyGraph, ops_from_subgraph};
        use crate::openapi::spec::Spec;
        use oas3::spec::{
            Info, MediaType, ObjectOrReference, ObjectSchema, Operation, Parameter, PathItem,
            Response, SchemaType, SchemaTypeSet,
        };
        use petgraph::visit::EdgeRef;
        use std::collections::BTreeMap;

        fn object_schema_with_fields(fields: &[&str]) -> ObjectSchema {
            let mut properties = BTreeMap::new();
            for &field in fields {
                properties.insert(
                    field.to_string(),
                    ObjectOrReference::Object(ObjectSchema {
                        schema_type: Some(SchemaTypeSet::Single(SchemaType::String)),
                        ..Default::default()
                    }),
                );
            }
            ObjectSchema {
                schema_type: Some(SchemaTypeSet::Single(SchemaType::Object)),
                properties,
                ..Default::default()
            }
        }

        fn json_response(fields: &[&str]) -> BTreeMap<String, ObjectOrReference<Response>> {
            let mut content = BTreeMap::new();
            content.insert(
                "application/json".to_string(),
                MediaType {
                    schema: Some(ObjectOrReference::Object(object_schema_with_fields(fields))),
                    ..Default::default()
                },
            );
            let mut responses = BTreeMap::new();
            responses.insert(
                "200".to_string(),
                ObjectOrReference::Object(Response {
                    description: Default::default(),
                    headers: Default::default(),
                    content,
                    links: Default::default(),
                    extensions: Default::default(),
                }),
            );
            responses
        }

        // Create a spec with two GET operations that form a cycle via response-based
        // parameter matching. Normalization includes the last path segment as context,
        // so both operations must share the same last segment for their normalizations
        // to match:
        //   GET /a/item  takes query param "x", responds with "y"
        //     -> input normalized: "item|x", response output normalized: "item|y"
        //   GET /b/item  takes query param "y", responds with "x"
        //     -> input normalized: "item|y", response output normalized: "item|x"
        // This creates response-based edges in both directions, forming a 2-node cycle.
        // Since both are GET, CRUD ordering does not prevent either direction.
        let mut paths = BTreeMap::new();
        paths.insert(
            "/a/item".to_string(),
            PathItem {
                get: Some(Operation {
                    parameters: vec![ObjectOrReference::Object(Parameter {
                        name: "x".to_string(),
                        location: oas3::spec::ParameterIn::Query,
                        description: Default::default(),
                        required: Default::default(),
                        deprecated: Default::default(),
                        allow_empty_value: Default::default(),
                        style: Default::default(),
                        explode: Default::default(),
                        allow_reserved: Default::default(),
                        schema: Default::default(),
                        example: Default::default(),
                        examples: Default::default(),
                        content: Default::default(),
                        extensions: Default::default(),
                    })],
                    responses: Some(json_response(&["y"])),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        paths.insert(
            "/b/item".to_string(),
            PathItem {
                get: Some(Operation {
                    parameters: vec![ObjectOrReference::Object(Parameter {
                        name: "y".to_string(),
                        location: oas3::spec::ParameterIn::Query,
                        description: Default::default(),
                        required: Default::default(),
                        deprecated: Default::default(),
                        allow_empty_value: Default::default(),
                        style: Default::default(),
                        explode: Default::default(),
                        allow_reserved: Default::default(),
                        schema: Default::default(),
                        example: Default::default(),
                        examples: Default::default(),
                        content: Default::default(),
                        extensions: Default::default(),
                    })],
                    responses: Some(json_response(&["x"])),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );

        let spec: Spec = oas3::Spec {
            openapi: "3.1.0".to_string(),
            info: Info {
                title: Default::default(),
                summary: Default::default(),
                description: Default::default(),
                terms_of_service: Default::default(),
                version: Default::default(),
                contact: Default::default(),
                license: Default::default(),
                extensions: Default::default(),
            },
            servers: Default::default(),
            paths: Some(paths),
            components: Default::default(),
            security: Default::default(),
            tags: Default::default(),
            webhooks: Default::default(),
            external_docs: Default::default(),
            extensions: Default::default(),
        }
        .into();

        // Build graph with CRUD ordering. Both operations are GET, so edges go
        // in both directions forming a cycle longer than a self-loop.
        let graph = DependencyGraph::new(&spec, true);

        // Verify there is a multi-node cycle: edges between distinct nodes in both
        // directions (GET /a -> GET /b and GET /b -> GET /a).
        let cross_edge_count = graph
            .graph
            .edge_references()
            .filter(|edge| edge.source() != edge.target())
            .count();
        assert!(
            cross_edge_count >= 2,
            "Expected at least 2 cross-edges forming a cycle, got {}",
            cross_edge_count
        );

        // ops_from_subgraph calls toposort, which should fail on the cycle.
        for nodes in graph.connected_components() {
            let subgraph = graph.subgraph(&nodes);
            let result = ops_from_subgraph(&subgraph);
            assert!(
                result.is_err(),
                "Expected toposort to fail due to cycle between same-method operations"
            );
        }
    }
}
