use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::{BufReader, BufWriter, Write},
    path::Path,
};

use anyhow::{Context, bail};
use quick_xml::{
    Reader, Writer,
    events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event},
};

use crate::{input::Method, parameter_access::ParameterAccess};

pub(crate) const GRAPHML_SCHEMA_VERSION: &str = "1";

const KEY_NODE_METHOD: &str = "node_method";
const KEY_NODE_PATH: &str = "node_path";
const KEY_EDGE_KIND: &str = "edge_kind";
const KEY_EDGE_OUTPUT_ACCESS: &str = "edge_output_access";
const KEY_EDGE_INPUT_ACCESS: &str = "edge_input_access";
const KEY_EDGE_INPUT_NAME_NORMALIZED: &str = "edge_input_name_normalized";
const KEY_GRAPH_SCHEMA_VERSION: &str = "graph_schema_version";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EdgeKind {
    Request,
    Response,
}

impl EdgeKind {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Request => "REQUEST",
            Self::Response => "RESPONSE",
        }
    }

    pub(crate) fn parse(value: &str) -> anyhow::Result<Self> {
        if value.eq_ignore_ascii_case("REQUEST") {
            Ok(Self::Request)
        } else if value.eq_ignore_ascii_case("RESPONSE") {
            Ok(Self::Response)
        } else {
            bail!("Invalid edge kind '{value}', expected REQUEST or RESPONSE")
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct GraphMlNode {
    pub(crate) id: String,
    pub(crate) method: Method,
    pub(crate) path: String,
}

#[derive(Debug, Clone)]
pub(crate) struct GraphMlEdge {
    pub(crate) source: String,
    pub(crate) target: String,
    pub(crate) kind: EdgeKind,
    pub(crate) output_access: ParameterAccess,
    pub(crate) input_access: ParameterAccess,
    pub(crate) input_name_normalized: String,
}

#[derive(Debug, Clone)]
pub(crate) struct GraphMlGraph {
    pub(crate) nodes: Vec<GraphMlNode>,
    pub(crate) edges: Vec<GraphMlEdge>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GraphMlImportPolicy {
    FailFast,
    SkipInvalid,
}

fn write_text_element(
    writer: &mut Writer<BufWriter<File>>,
    tag_name: &str,
    attributes: &[(&str, &str)],
    value: &str,
) -> anyhow::Result<()> {
    let mut tag = BytesStart::new(tag_name);
    for (name, attr_value) in attributes {
        tag.push_attribute((*name, *attr_value));
    }
    writer
        .write_event(Event::Start(tag.borrow()))
        .context("Could not write XML start tag")?;
    writer
        .write_event(Event::Text(BytesText::new(value)))
        .context("Could not write XML text")?;
    writer
        .write_event(Event::End(BytesEnd::new(tag_name)))
        .context("Could not write XML end tag")?;
    Ok(())
}

pub(crate) fn write_graphml(path: &Path, graph: &GraphMlGraph) -> anyhow::Result<()> {
    let file = File::create(path)
        .with_context(|| format!("Could not create GraphML file at {path:?}"))?;
    let mut writer = Writer::new_with_indent(BufWriter::new(file), b' ', 2);

    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .context("Could not write XML declaration")?;

    let mut graphml_tag = BytesStart::new("graphml");
    graphml_tag.push_attribute(("xmlns", "http://graphml.graphdrawing.org/xmlns"));
    writer
        .write_event(Event::Start(graphml_tag.borrow()))
        .context("Could not write graphml start tag")?;

    let keys = [
        (KEY_NODE_METHOD, "node", "method"),
        (KEY_NODE_PATH, "node", "path"),
        (KEY_EDGE_KIND, "edge", "kind"),
        (KEY_EDGE_OUTPUT_ACCESS, "edge", "output_access"),
        (KEY_EDGE_INPUT_ACCESS, "edge", "input_access"),
        (
            KEY_EDGE_INPUT_NAME_NORMALIZED,
            "edge",
            "input_name_normalized",
        ),
        (KEY_GRAPH_SCHEMA_VERSION, "graph", "schema_version"),
    ];

    for (id, attr_for, attr_name) in keys {
        let mut key_tag = BytesStart::new("key");
        key_tag.push_attribute(("id", id));
        key_tag.push_attribute(("for", attr_for));
        key_tag.push_attribute(("attr.name", attr_name));
        key_tag.push_attribute(("attr.type", "string"));
        writer
            .write_event(Event::Empty(key_tag.borrow()))
            .context("Could not write GraphML key")?;
    }

    let mut graph_tag = BytesStart::new("graph");
    graph_tag.push_attribute(("id", "dependency_graph"));
    graph_tag.push_attribute(("edgedefault", "directed"));
    writer
        .write_event(Event::Start(graph_tag.borrow()))
        .context("Could not write graph start tag")?;

    write_text_element(
        &mut writer,
        "data",
        &[("key", KEY_GRAPH_SCHEMA_VERSION)],
        GRAPHML_SCHEMA_VERSION,
    )?;

    for node in &graph.nodes {
        let mut node_tag = BytesStart::new("node");
        node_tag.push_attribute(("id", node.id.as_str()));
        let label = format!("{} {}", node.method.as_str(), node.path);
        node_tag.push_attribute(("method", node.method.as_str()));
        node_tag.push_attribute(("path", node.path.as_str()));
        node_tag.push_attribute(("label", label.as_str()));
        writer
            .write_event(Event::Start(node_tag.borrow()))
            .context("Could not write node start tag")?;

        write_text_element(
            &mut writer,
            "data",
            &[("key", KEY_NODE_METHOD)],
            node.method.as_str(),
        )?;
        write_text_element(
            &mut writer,
            "data",
            &[("key", KEY_NODE_PATH)],
            node.path.as_str(),
        )?;

        writer
            .write_event(Event::End(BytesEnd::new("node")))
            .context("Could not write node end tag")?;
    }

    for (index, edge) in graph.edges.iter().enumerate() {
        let mut edge_tag = BytesStart::new("edge");
        let edge_id = format!("e{index}");
        edge_tag.push_attribute(("id", edge_id.as_str()));
        edge_tag.push_attribute(("source", edge.source.as_str()));
        edge_tag.push_attribute(("target", edge.target.as_str()));
        let output_access_str = edge.output_access.to_graphml_string();
        let input_access_str = edge.input_access.to_graphml_string();
        edge_tag.push_attribute(("kind", edge.kind.as_str()));
        edge_tag.push_attribute(("output_access", output_access_str.as_str()));
        edge_tag.push_attribute(("input_access", input_access_str.as_str()));
        edge_tag.push_attribute(("input_name_normalized", edge.input_name_normalized.as_str()));
        let label = format!(
            "{} {} -> {}",
            edge.kind.as_str(),
            output_access_str,
            input_access_str
        );
        edge_tag.push_attribute(("label", label.as_str()));
        writer
            .write_event(Event::Start(edge_tag.borrow()))
            .context("Could not write edge start tag")?;

        write_text_element(
            &mut writer,
            "data",
            &[("key", KEY_EDGE_KIND)],
            edge.kind.as_str(),
        )?;
        write_text_element(
            &mut writer,
            "data",
            &[("key", KEY_EDGE_OUTPUT_ACCESS)],
            &edge.output_access.to_graphml_string(),
        )?;
        write_text_element(
            &mut writer,
            "data",
            &[("key", KEY_EDGE_INPUT_ACCESS)],
            &edge.input_access.to_graphml_string(),
        )?;
        write_text_element(
            &mut writer,
            "data",
            &[("key", KEY_EDGE_INPUT_NAME_NORMALIZED)],
            edge.input_name_normalized.as_str(),
        )?;

        writer
            .write_event(Event::End(BytesEnd::new("edge")))
            .context("Could not write edge end tag")?;
    }

    writer
        .write_event(Event::End(BytesEnd::new("graph")))
        .context("Could not write graph end tag")?;
    writer
        .write_event(Event::End(BytesEnd::new("graphml")))
        .context("Could not write graphml end tag")?;

    writer
        .into_inner()
        .flush()
        .context("Could not flush GraphML writer")?;

    Ok(())
}

fn attr_value<'a>(tag: &'a BytesStart<'a>, name: &[u8]) -> anyhow::Result<Option<String>> {
    let maybe_attr = tag
        .attributes()
        .find_map(|attr_res| {
            let attr = attr_res.ok()?;
            (attr.key.as_ref() == name).then_some(attr)
        })
        .map(|attr| String::from_utf8(attr.value.to_vec()))
        .transpose()
        .context("Could not parse XML attribute bytes")?;
    Ok(maybe_attr)
}

fn require_data_field(
    values: &BTreeMap<String, String>,
    name: &str,
    context_name: &str,
) -> anyhow::Result<String> {
    values
        .get(name)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Missing required {context_name} data field '{name}'"))
}

pub(crate) fn read_graphml(path: &Path, policy: GraphMlImportPolicy) -> anyhow::Result<GraphMlGraph> {
    let file = File::open(path).with_context(|| format!("Could not open GraphML file at {path:?}"))?;
    let mut reader = Reader::from_reader(BufReader::new(file));
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();

    let mut key_id_to_name = HashMap::<String, String>::new();
    let mut graph_schema_version: Option<String> = None;

    let mut nodes: Vec<GraphMlNode> = Vec::new();
    let mut edges: Vec<GraphMlEdge> = Vec::new();

    let mut current_node_id: Option<String> = None;
    let mut current_edge_source_target: Option<(String, String)> = None;
    let mut current_data_key_name: Option<String> = None;
    let mut current_data_text = String::new();

    let mut current_node_data: BTreeMap<String, String> = BTreeMap::new();
    let mut current_edge_data: BTreeMap<String, String> = BTreeMap::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(tag)) => {
                let name = tag.name().as_ref().to_vec();
                if name.as_slice() == b"key" {
                    let id = attr_value(&tag, b"id")?
                        .ok_or_else(|| anyhow::anyhow!("GraphML key is missing 'id'"))?;
                    let attr_name = attr_value(&tag, b"attr.name")?
                        .ok_or_else(|| anyhow::anyhow!("GraphML key '{id}' missing 'attr.name'"))?;
                    key_id_to_name.insert(id, attr_name);
                } else if name.as_slice() == b"node" {
                    current_node_id = Some(
                        attr_value(&tag, b"id")?
                            .ok_or_else(|| anyhow::anyhow!("GraphML node missing 'id'"))?,
                    );
                    current_node_data.clear();
                    // Pre-populate from XML attributes as fallback
                    if let Some(v) = attr_value(&tag, b"method")? {
                        current_node_data.entry("method".to_string()).or_insert(v);
                    }
                    if let Some(v) = attr_value(&tag, b"path")? {
                        current_node_data.entry("path".to_string()).or_insert(v);
                    }
                } else if name.as_slice() == b"edge" {
                    let source = attr_value(&tag, b"source")?
                        .ok_or_else(|| anyhow::anyhow!("GraphML edge missing 'source'"))?;
                    let target = attr_value(&tag, b"target")?
                        .ok_or_else(|| anyhow::anyhow!("GraphML edge missing 'target'"))?;
                    current_edge_source_target = Some((source, target));
                    current_edge_data.clear();
                    // Pre-populate from XML attributes as fallback
                    if let Some(v) = attr_value(&tag, b"kind")? {
                        current_edge_data.entry("kind".to_string()).or_insert(v);
                    }
                    if let Some(v) = attr_value(&tag, b"output_access")? {
                        current_edge_data.entry("output_access".to_string()).or_insert(v);
                    }
                    if let Some(v) = attr_value(&tag, b"input_access")? {
                        current_edge_data.entry("input_access".to_string()).or_insert(v);
                    }
                    if let Some(v) = attr_value(&tag, b"input_name_normalized")? {
                        current_edge_data.entry("input_name_normalized".to_string()).or_insert(v);
                    }
                } else if name.as_slice() == b"data" {
                    let key_id = attr_value(&tag, b"key")?
                        .ok_or_else(|| anyhow::anyhow!("GraphML data tag missing 'key'"))?;
                    let key_name = key_id_to_name.get(&key_id).cloned().ok_or_else(|| {
                        anyhow::anyhow!("GraphML data key '{key_id}' has no matching <key> declaration")
                    })?;
                    current_data_key_name = Some(key_name);
                    current_data_text.clear();
                }
            }
            Ok(Event::Empty(tag)) => {
                let name = tag.name().as_ref().to_vec();
                if name.as_slice() == b"key" {
                    let id = attr_value(&tag, b"id")?
                        .ok_or_else(|| anyhow::anyhow!("GraphML key is missing 'id'"))?;
                    let attr_name = attr_value(&tag, b"attr.name")?
                        .ok_or_else(|| anyhow::anyhow!("GraphML key '{id}' missing 'attr.name'"))?;
                    key_id_to_name.insert(id, attr_name);
                }
            }
            Ok(Event::Text(text)) => {
                if current_data_key_name.is_some() {
                    current_data_text.push_str(&String::from_utf8_lossy(text.as_ref()));
                }
            }
            Ok(Event::End(tag)) => {
                let name = tag.name().as_ref().to_vec();
                if name.as_slice() == b"data" {
                    let key_name = current_data_key_name.take().ok_or_else(|| {
                        anyhow::anyhow!("Unexpected GraphML </data> without matching <data>")
                    })?;

                    if current_node_id.is_some() {
                        current_node_data.insert(key_name, current_data_text.clone());
                    } else if current_edge_source_target.is_some() {
                        current_edge_data.insert(key_name, current_data_text.clone());
                    } else if key_name == "schema_version" {
                        graph_schema_version = Some(current_data_text.clone());
                    } else if policy == GraphMlImportPolicy::FailFast {
                        bail!("Unexpected graph-level data field '{key_name}'");
                    } else {
                        log::warn!("Ignoring unexpected graph-level data field '{key_name}'");
                    }
                    current_data_text.clear();
                } else if name.as_slice() == b"node" {
                    let node_id = current_node_id.take().ok_or_else(|| {
                        anyhow::anyhow!("Unexpected GraphML </node> without matching <node>")
                    })?;
                    let method = require_data_field(&current_node_data, "method", "node")?;
                    let path = require_data_field(&current_node_data, "path", "node")?;
                    let method = Method::try_from(method.as_str())
                        .map_err(|err| anyhow::anyhow!("Invalid node method '{method}': {err}"))?;
                    nodes.push(GraphMlNode {
                        id: node_id,
                        method,
                        path,
                    });
                } else if name.as_slice() == b"edge" {
                    let (source, target) = current_edge_source_target.take().ok_or_else(|| {
                        anyhow::anyhow!("Unexpected GraphML </edge> without matching <edge>")
                    })?;
                    let source_for_log = source.clone();
                    let target_for_log = target.clone();

                    let edge_result = (|| -> anyhow::Result<GraphMlEdge> {
                        let kind = require_data_field(&current_edge_data, "kind", "edge")?;
                        let output_access =
                            require_data_field(&current_edge_data, "output_access", "edge")?;
                        let input_access =
                            require_data_field(&current_edge_data, "input_access", "edge")?;
                        let input_name_normalized = require_data_field(
                            &current_edge_data,
                            "input_name_normalized",
                            "edge",
                        )?;

                        Ok(GraphMlEdge {
                            source,
                            target,
                            kind: EdgeKind::parse(&kind)?,
                            output_access: ParameterAccess::from_graphml_string(&output_access)
                                .map_err(|err| anyhow::anyhow!(err))?,
                            input_access: ParameterAccess::from_graphml_string(&input_access)
                                .map_err(|err| anyhow::anyhow!(err))?,
                            input_name_normalized,
                        })
                    })();

                    match edge_result {
                        Ok(edge) => edges.push(edge),
                        Err(error) => {
                            if policy == GraphMlImportPolicy::FailFast {
                                return Err(error);
                            }
                            log::warn!(
                                "Skipping invalid GraphML edge {source_for_log:?} -> {target_for_log:?}: {error}"
                            );
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Ok(Event::Comment(_))
            | Ok(Event::Decl(_))
            | Ok(Event::DocType(_))
            | Ok(Event::CData(_))
            | Ok(Event::PI(_))
            | Ok(Event::GeneralRef(_)) => {}
            Err(error) => return Err(error).context("Failed to parse GraphML XML"),
        }
        buf.clear();
    }

    let schema_version = graph_schema_version.unwrap_or_else(|| {
        log::info!(
            "No schema_version found in GraphML input, assuming version '{}'",
            GRAPHML_SCHEMA_VERSION
        );
        GRAPHML_SCHEMA_VERSION.to_string()
    });
    if schema_version != GRAPHML_SCHEMA_VERSION {
        bail!(
            "Unsupported GraphML schema version '{schema_version}', expected '{}'.",
            GRAPHML_SCHEMA_VERSION
        );
    }

    Ok(GraphMlGraph { nodes, edges })
}
