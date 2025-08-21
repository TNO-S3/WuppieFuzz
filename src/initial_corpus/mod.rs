//! Helper functions for loading a corpus from disk. See module documentation of
//! the `input` submodule for information on serialization.
pub mod dependency_graph;

use std::{
    collections::hash_map::DefaultHasher,
    convert::TryInto,
    fs::{self, File, create_dir_all},
    hash::{Hash, Hasher},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use libafl::{
    HasMetadata,
    corpus::{Corpus, InMemoryOnDiskCorpus, SchedulerTestcaseMetadata, Testcase},
};
use openapiv3::OpenAPI;

use self::dependency_graph::DependencyGraph;
use crate::{
    initial_corpus::dependency_graph::initial_corpus_from_api,
    input::{OpenApiInput, OpenApiRequest},
};

/// Loads an `OpenApiInput` from a yaml file.
pub fn load_starting_corpus(
    corpus_dir: &Path,
) -> Result<Vec<OpenApiInput>, Box<dyn std::error::Error>> {
    let mut corpus_vec = vec![];
    for file in fs::read_dir(corpus_dir)? {
        let file = file?.path();
        match serde_yaml::from_reader(std::fs::File::open(file)?) {
            Ok(input) => corpus_vec.push(input),
            Err(err) => return Err(err.into()),
        }
    }
    Ok(corpus_vec)
}

/// Generates a corpus and writes it to the path specified at `corpus_dir`.
/// Additionally, if `report_path` is specified, the dependency graph (i.e.
/// the dependencies between parameters of the requests in each series generated
/// as the initial corpus) used to generate the initial corpus is then written
/// to the `report_path`.
pub fn generate_corpus_to_files(api: &OpenAPI, corpus_dir: &Path, report_path: Option<&Path>) {
    let inputs = initial_corpus_from_api(api);
    log::debug!("Writing corpus to file...");
    if let Err(e) = write_corpus_to_files(&inputs, corpus_dir) {
        log::warn!("Error writing corpus to file: {e}");
    } else {
        log::info!("Wrote generated corpus to {corpus_dir:?}");
    }
    if let Some(report_path) = report_path {
        // The dependency graph was already generated while creating it from the API
        // but it is cheap to build, so we can afford to do it again for reporting.
        let dependency_graph = DependencyGraph::new(api);
        let _ = dependency_graph.write_report(report_path);
        let _ = write_corpus_report(&inputs, report_path);
    }
}

pub fn write_corpus_to_files(
    corpus: &[OpenApiInput],
    corpus_dir: &Path,
) -> Result<(), anyhow::Error> {
    fs::create_dir_all(corpus_dir)?;
    for (input_name, input) in corpus.iter().enumerate() {
        let file_path = corpus_dir.join(input_name.to_string());
        let file = std::fs::OpenOptions::new()
            .truncate(true)
            .write(true)
            .create(true)
            .open(file_path)?;
        serde_yaml::to_writer(file, input)?;
    }
    Ok(())
}

/// Loads an `OpenApiInput` from a yaml file and prints its contents.
pub fn print_starting_corpus(filename: &Path) {
    match load_starting_corpus(filename) {
        Ok(res) => log::debug!("{res:?}"),
        Err(err) => log::error!("Error: {err}"),
    }
}

pub fn initialize_corpus(
    api: &OpenAPI,
    initial_corpus_path: Option<&Path>,
    report_path: &Option<&Path>,
) -> InMemoryOnDiskCorpus<OpenApiInput> {
    let mut corpus = InMemoryOnDiskCorpus::new(PathBuf::from("./queue")).unwrap();
    match initial_corpus_path {
        Some(initial_corpus_path) => {
            log::info!("Filling corpus from file: {initial_corpus_path:?}");
            fill_corpus_from_file(&mut corpus, initial_corpus_path)
        }
        None => {
            log::info!("No corpus supplied, generating one based on the API");
            fill_corpus_from_api(&mut corpus, api, report_path)
        }
    }
    corpus
}

fn write_corpus_report(input_vector: &[OpenApiInput], report_path: &Path) -> std::io::Result<()> {
    let corpus_path = report_path.join("corpus");
    create_dir_all(&corpus_path)?;
    let corpus_file = corpus_path.join("corpus_graphs.md");
    let mut file = File::create(corpus_file)?;
    writeln!(
        file,
        "# Corpus graph based on OpenAPI spec generated inputs\n"
    )?;
    writeln!(
        file,
        "This markdown document can be rendered using a Mermaid plugin. It demonstrates the generated sequences of API requests.\n"
    )?;
    writeln!(file, "```mermaid")?;
    writeln!(file, "graph LR;")?;

    writeln!(file, "  %% Inputs")?;
    let mut input_vector_indices = (0..input_vector.len()).collect::<Vec<_>>();
    input_vector_indices.sort_by_key(|k| input_vector[*k].0.len());
    for index in input_vector_indices {
        let input = &input_vector[index];
        writeln!(file, "  subgraph input_{index};")?;
        writeln!(file, "    direction LR;")?;
        for request in &input.0 {
            let mut hasher = DefaultHasher::new();
            request.to_string().hash(&mut hasher);
            writeln!(
                file,
                "    {}(\"{} {}\");",
                hasher.finish(),
                request.method,
                request.path,
            )?;
        }
        for edge in input.0.windows(2) {
            let [request_in, request_out]: &[OpenApiRequest; 2] = edge.try_into().unwrap();
            let mut hasher_in = DefaultHasher::new();
            request_in.to_string().hash(&mut hasher_in);
            let mut hasher_out = DefaultHasher::new();
            request_out.to_string().hash(&mut hasher_out);
            writeln!(
                file,
                "    {} --> {};",
                hasher_in.finish(),
                hasher_out.finish(),
            )?;
        }
        writeln!(file, "  end;")?;
    }

    writeln!(file, "```")?;

    Ok(())
}

fn fill_corpus_from_file(
    corpus: &mut InMemoryOnDiskCorpus<OpenApiInput>,
    initial_corpus_path: &Path,
) {
    match load_starting_corpus(initial_corpus_path) {
        Ok(inputs) => {
            print_starting_corpus(initial_corpus_path);
            for input in inputs {
                let mut testcase = Testcase::new(input);
                testcase.set_exec_time(Duration::from_secs(1));
                testcase.add_metadata(SchedulerTestcaseMetadata::new(0));
                match corpus.add(testcase) {
                    Ok(_) => (),
                    Err(e) => log::warn!("Could not add testcase to corpus, omitting. {e:?}"),
                }
            }
        }
        Err(err) => {
            log::warn!("Error loading initial corpus, will generate random inputs instead: {err}")
        }
    };
}

fn fill_corpus_from_api(
    corpus: &mut InMemoryOnDiskCorpus<OpenApiInput>,
    api: &OpenAPI,
    report_path: &Option<&Path>,
) {
    let inputs = initial_corpus_from_api(api);
    if let Some(report_path) = report_path {
        // The dependency graph was already generated while creating it from the API
        // but it is cheap to build, so we can afford to do it again for reporting.
        let dependency_graph = DependencyGraph::new(api);
        let _ = dependency_graph.write_report(report_path);
        let _ = write_corpus_report(&inputs, report_path);
    }
    for input in inputs {
        let mut testcase = Testcase::new(input);
        testcase.add_metadata(SchedulerTestcaseMetadata::new(0));
        testcase.set_disabled(false);
        testcase.set_exec_time(Duration::from_secs(1));
        let _ = testcase.load_input(corpus);
        let _ = corpus.add(testcase);
    }
}
