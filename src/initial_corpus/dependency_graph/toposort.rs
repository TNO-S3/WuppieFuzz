//! Topological sort with CRUD-order tie-breaking.
//!
//! `petgraph` provides a generic topological sort, but it does not give any
//! guarantee about the relative order of nodes that have no ordering constraint
//! between them (i.e. nodes at the same "depth" in the DAG).
//!
//! For the dependency graph we want a deterministic, semantically meaningful
//! tiebreaker: among operations that are not mutually constrained, a `POST`
//! (create) should come before a `GET` (read), which should come before a
//! `PUT`/`PATCH` (update), which should come before a `DELETE`.  This matches
//! the natural lifecycle of a REST resource and produces more realistic request
//! sequences for the fuzzer to start from.
//!
//! The implementation is a depth-first post-order traversal (the standard
//! approach for topological sorting) with one modification: when a node is
//! first visited its neighbors are sorted by CRUD method order before being
//! pushed onto the DFS stack.

use petgraph::{
    prelude::*,
    visit::{GraphBase, GraphRef, IntoNodeIdentifiers, VisitMap, Visitable},
};

use super::DepGraph;

/// \[Generic\] Perform a topological sort of a directed graph.
///
/// If the graph was acyclic, return a vector of nodes in topological order:
/// each node is ordered before its successors.
/// Otherwise, it will return a `Cycle` error. Self loops are also cycles.
///
/// To handle graphs with cycles, use the scc algorithms or `DfsPostOrder`
/// instead of this function.
///
/// If `space` is not `None`, it is used instead of creating a new workspace for
/// graph traversal. The implementation is iterative.
pub fn toposort<'a>(
    graph: &DepGraph<'a>,
    space: Option<
        &mut DfsSpace<<DepGraph<'a> as GraphBase>::NodeId, <DepGraph<'a> as Visitable>::Map>,
    >,
) -> Result<Vec<<DepGraph<'a> as GraphBase>::NodeId>, Cycle<<DepGraph<'a> as GraphBase>::NodeId>> {
    // based on kosaraju scc
    with_dfs(graph, space, |dfs| {
        dfs.reset(graph);
        let mut finished = graph.visit_map();

        let mut finish_stack = Vec::new();
        for i in graph.node_identifiers() {
            if dfs.discovered.is_visited(&i) {
                continue;
            }
            dfs.stack.push(i);
            while let Some(&nx) = dfs.stack.last() {
                if dfs.discovered.visit(nx) {
                    // First time visiting `nx`: Push neighbors, don't pop `nx`
                    // WuppieFuzz addition: sort neighbors in CRUD order
                    let mut neighbors = graph.neighbors(nx).collect::<Vec<_>>();
                    neighbors.sort_by(|a, b| graph[*a].method.cmp(&graph[*b].method));
                    for succ in neighbors.iter() {
                        if succ == &nx {
                            // self cycle
                            return Err(Cycle(nx));
                        }
                        if !dfs.discovered.is_visited(succ) {
                            dfs.stack.push(*succ);
                        } else if !finished.is_visited(succ) {
                            // Back edge: *succ is discovered but not yet finished,
                            // meaning it is still on the DFS stack. This is a cycle.
                            return Err(Cycle(*succ));
                        }
                    }
                } else {
                    dfs.stack.pop();
                    if finished.visit(nx) {
                        // Second time: All reachable nodes must have been finished
                        finish_stack.push(nx);
                    }
                }
            }
        }
        finish_stack.reverse();

        Ok(finish_stack)
    })
}

/// An algorithm error: a cycle was found in the graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cycle<N>(N);

impl<N> Cycle<N> {
    /// Return a node id that participates in the cycle
    pub fn node_id(&self) -> N
    where
        N: Copy,
    {
        self.0
    }
}

type DfsSpaceType<G> = DfsSpace<<G as GraphBase>::NodeId, <G as Visitable>::Map>;

/// Borrows or creates a [`Dfs`] traversal object, then calls `f` with it.
///
/// If `space` is `Some`, the existing `Dfs` inside the [`DfsSpace`] is reused
/// (avoiding an allocation).  Otherwise a fresh empty `Dfs` is created on the
/// stack.  This mirrors the pattern used by `petgraph`'s own toposort helper.
fn with_dfs<G, F, R>(g: G, space: Option<&mut DfsSpaceType<G>>, f: F) -> R
where
    G: GraphRef + Visitable,
    F: FnOnce(&mut Dfs<G::NodeId, G::Map>) -> R,
{
    let mut local_visitor;
    let dfs = if let Some(v) = space {
        &mut v.dfs
    } else {
        local_visitor = Dfs::empty(g);
        &mut local_visitor
    };
    f(dfs)
}

/// Workspace for a graph traversal.
#[derive(Clone, Debug)]
pub struct DfsSpace<N, VM> {
    dfs: Dfs<N, VM>,
}

impl<N, VM> Default for DfsSpace<N, VM>
where
    VM: VisitMap<N> + Default,
{
    fn default() -> Self {
        DfsSpace {
            dfs: Dfs {
                stack: <_>::default(),
                discovered: <_>::default(),
            },
        }
    }
}
