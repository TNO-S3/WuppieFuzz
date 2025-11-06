use std::{
    convert::TryFrom,
    io,
    io::ErrorKind,
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand, ValueEnum, value_parser};
use libafl::schedulers::powersched::BaseSchedule;
use serde::Deserialize;
use strum::VariantArray;
use url::Url;

use crate::openapi::validate_response::ValidationErrorDiscriminants;

const DEFAULT_REQUEST_TIMEOUT: u64 = 30000;
const DEFAULT_METHOD_MUTATION_STRATEGY: MethodMutationStrategy = MethodMutationStrategy::FollowSpec;
const DEFAULT_LOG_LEVEL: log::LevelFilter = log::LevelFilter::Info;

lazy_static! {
    static ref CONFIGURATION: Result<Configuration, anyhow::Error> =
        Configuration::try_from(PartialConfiguration::get()?);
}

/// Grey-box REST API Fuzzer written in Rust with LibAFL.
#[derive(Parser)]
#[command(about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// The list of supported subcommands.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
pub enum Commands {
    /// Print the version and exit
    Version,
    /// Print the licences
    License,
    /// Print the software bill of materials
    Sbom,
    /// Verify the current authentication settings by attempting to connect to the PuT
    VerifyAuth {
        /// The path to a configuration file. If present, the configuration file is used
        /// to configure the fuzzer. Arguments given on the command line take precedence
        /// over the configuration file.
        #[arg(long, value_parser, value_name = "CONFIG_FILE.YAML")]
        config: Option<PathBuf>,
        /// OpenAPI specification
        #[arg(long, value_parser, value_name = "OPENAPI_SPEC.YAML")]
        openapi_spec: Option<PathBuf>,
        /// The URL of the server to fuzz. This is usually specified in the OpenAPI specification,
        /// but you can use this option to override it.
        #[arg(value_parser=verify_url, long)]
        target: Option<Url>,
        /// How to log in to the API server. The value should be the name of a YAML file
        /// that contains the login configuration. See login.md for information on how
        /// to build one.
        #[arg(long, value_parser, value_name = "AUTH.YAML")]
        authentication: Option<PathBuf>,
        /// Custom (static) headers that should be added to each request. These header
        /// parameters will not be mutated, contrary to the usual header parameters
        /// passed through an API specification.
        #[arg(long, value_parser, value_name = "STATIC_HEADERS.YAML")]
        header: Option<PathBuf>,
        // Manually added possible values below, since automatically showing possible values of an external (remote) enum
        // such as log::LevelFilter is not well supported.
        // See https://github.com/serde-rs/serde/issues/1301, https://github.com/serde-rs/serde/issues/723
        /// Log level to output. This flag takes precedence over the environment variable. [possible values: off, error, warn, debug, info, trace]
        #[arg(value_parser = clap::value_parser!(log::LevelFilter), long, value_enum, env = "LOG_LEVEL", ignore_case = true)]
        log_level: Option<log::LevelFilter>,
    },
    /// Generate a starting corpus and write it to a directory, then exit
    OutputCorpus {
        /// A directory to output the corpus to
        #[arg(value_name = "CORPUS_DIRECTORY")]
        corpus_directory: PathBuf,
        /// OpenAPI specification to generate corpus entries from
        #[arg(long, value_parser, value_name = "OPENAPI_SPEC.YAML")]
        openapi_spec: PathBuf,
        /// If given, the fuzzer saves mermaid graphs to this directory that represent
        /// inferred relationships between the endpoints and their parameters
        #[arg(long, value_parser, value_name = "REPORTS/")]
        report_path: Option<PathBuf>,
        // Manually added possible values below, since automatically showing possible values of an external (remote) enum
        // such as log::LevelFilter is not well supported.
        // See https://github.com/serde-rs/serde/issues/1301, https://github.com/serde-rs/serde/issues/723
        /// Log level to output. This flag takes precedence over the environment variable. [possible values: off, error, warn, debug, info, trace]
        #[arg(value_parser = clap::value_parser!(log::LevelFilter), long, value_enum, env = "LOG_LEVEL", ignore_case = true)]
        log_level: Option<log::LevelFilter>,
    },
    /// Reproduce a crash file generated during an earlier fuzzing run
    Reproduce {
        /// The path to a configuration file. If present, the configuration file is used
        /// to configure the fuzzer. Arguments given on the command line take precedence
        /// over the configuration file.
        #[arg(long, value_parser, value_name = "CONFIG_FILE.YAML")]
        config: Option<PathBuf>,
        /// The crash file to reproduce
        #[arg(value_name = "CRASH_FILE")]
        crash_file: PathBuf,
        /// The OpenAPI specification of the program under test
        #[arg(long, value_name = "OPENAPI_SPEC.YAML")]
        openapi_spec: Option<PathBuf>,
        /// The URL of the server to fuzz. This is usually specified in the OpenAPI specification,
        /// but you can use this option to override it.
        #[arg(value_parser=verify_url, long)]
        target: Option<Url>,
        /// How to log in to the API server. The value should be the name of a YAML file
        /// that contains the login configuration. See login.md for information on how
        /// to build one.
        #[arg(long, value_parser, value_name = "AUTH.YAML")]
        authentication: Option<PathBuf>,
        /// Custom (static) headers that should be added to each request. These header
        /// parameters will not be mutated, contrary to the usual header parameters
        /// passed through an API specification.
        #[arg(long, value_parser, value_name = "STATIC_HEADERS.YAML")]
        header: Option<PathBuf>,
        // Manually added possible values below, since automatically showing possible values of an external (remote) enum
        // such as log::LevelFilter is not well supported.
        // See https://github.com/serde-rs/serde/issues/1301, https://github.com/serde-rs/serde/issues/723
        /// Log level to output. This flag takes precedence over the environment variable. [possible values: off, error, warn, debug, info, trace]
        #[arg(value_parser = clap::value_parser!(log::LevelFilter), long, value_enum, env = "LOG_LEVEL", ignore_case = true)]
        log_level: Option<log::LevelFilter>,
    },
    /// Fuzz test an OpenAPI backend
    Fuzz {
        /// The path to a configuration file. If present, the configuration file is used
        /// to configure the fuzzer. Arguments given on the command line take precedence
        /// over the configuration file.
        #[arg(long, value_parser, value_name = "CONFIG_FILE.YAML")]
        config: Option<PathBuf>,

        /// The path to the open api specification of the target. The specification must
        /// also contain the "server"-field at which the target is hosted.
        #[arg(value_parser, value_name = "OPENAPI_SPEC.YAML")]
        openapi_spec: Option<PathBuf>,

        /// The path to an initial corpus given as a directory with yaml files.
        #[arg(short, long, id = "initial_corpus", value_name = "CORPUS_DIRECTORY")]
        initial_corpus: Option<PathBuf>,

        /// The URL of the server to fuzz. This is usually specified in the OpenAPI specification,
        /// but you can use this option to override it.
        #[arg(value_parser=verify_url, long)]
        target: Option<Url>,

        /// The host address of the coverage agent from which the coverage map can be obtained.
        /// Can be either a hostname or an IP address, and must include a port.
        #[arg(value_parser=parse_socket_addr, long)]
        coverage_host: Option<SocketAddr>,

        /// The format in which your instrumentation provides coverage information.
        /// Must be one of {'jacoco', 'lcov', 'coverband'}. If omitted, the fuzzer will use
        /// endpoint coverage only.
        #[arg(value_parser, long, value_enum, ignore_case = true)]
        coverage_format: Option<CoverageFormat>,

        /// Total fuzzing time-out in seconds. If present, the fuzzer exits after the
        /// timeout has passed.
        #[arg(value_parser, long, required_if_eq_all([("report", "true")]))]
        timeout: Option<core::num::NonZeroU64>,

        /// Per-request time-out in milliseconds. Defaults to DEFAULT_REQUEST_TIMEOUT milliseconds.
        #[arg(value_parser, long)]
        request_timeout: Option<u64>,

        /// Set the power schedule to use. Defaults to FAST.
        #[arg(value_parser, long, value_enum, required = false, ignore_case = true)]
        power_schedule: Option<BaseSchedule>,

        /// Which errors the fuzzer considers a bug. By default, all behaviour that does not match the specification is considered a bug.
        ///
        /// The possible errors are:
        /// - "OperationNotInSpec": The operation does not exist in the spec, which incidentally means it should not have been executed by the fuzzer to begin with.
        /// - "StatusNotSpecified": The HTTP status code returned from the API is not one of the status codes mentioned for this path in the specification.
        /// - "ResponseReferenceBroken":  The specification calls for an object to be returned, and refers to the correct structure of this object using a reference (`#/example/reference`). However, the reference path is not present in the specification or contains circular references.
        /// - "ResponseObjectIncorrect": The response body returned by the API does not match the structure specified in the API specification.
        /// - "ResponseEnumIncorrect": A field in the response body object is specified as an enumeration, but the returned value is not one of the possible variants.
        /// - "ResponseMalformedJSON": The response body returned by the API can not be parsed as JSON.
        /// - "UnexpectedContent": The API returned a response body, but no response is specified.
        /// - "MediaTypeContainsNoSchema": The API contains a media type "application/json" with no schema for the data inside the json object. We can't validate the response if no model is given.
        /// - "SchemaIsAny": The schema can be anything (occurs e.g. when it does not specify a type) we cannot validate schemas that are this flexible.
        ///
        /// By default, the value for this option is a list of all of the above. By specifying a subset of the above errors, you can configure what behaviour is considered a bug by the fuzzer.
        #[arg(
            value_parser,
            long,
            value_enum,
            required = false,
            ignore_case = true,
            verbatim_doc_comment
        )]
        crash_criteria: Option<Vec<ValidationErrorDiscriminants>>,

        /// If present, ask the coverage monitor to generate a report after the
        /// time-out passes
        #[arg(long, value_parser(value_parser!(bool)), num_args(0..=1), require_equals = true, default_missing_value("true"), ignore_case = true)]
        report: Option<bool>,

        /// If present, determine with which HTTP methods to mutate.
        /// Must be one of {'follow-spec', 'common5', 'common7'},
        /// follow-spec: only mutate with methods from api specification
        /// common5: mutate with one of [get, post, put, patch, delete]
        /// common7: mutate with one of [get, post, put, patch, delete, head, trace]
        /// If omitted, only mutate with methods from api specification.
        #[arg(value_parser, long, value_enum, required = false, ignore_case = true)]
        method_mutation_strategy: Option<MethodMutationStrategy>,

        /// When generating a Jacoco coverage report, look for class files in this
        /// directory
        #[arg(value_parser, long, required_if_eq_all([("report", "true"), ("coverage_format", "jacoco")]))]
        jacoco_class_dir: Option<PathBuf>,

        /// When generating a coverage report, look for source files in this
        /// directory
        #[arg(value_parser, long, required_if_eq_all([("report", "true"), ("coverage_format", "jacoco")]))]
        source_dir: Option<PathBuf>,

        /// Output to stdout can be formatted in human readable format or json.
        #[arg(value_parser, long, value_enum, required = false, ignore_case = true)]
        output_format: Option<OutputFormat>,

        /// How to log in to the API server, if applicable. The value should be the
        /// name of a YAML file that contains the login configuration. See login.md
        /// for information on how to build one.
        #[arg(long, value_parser, value_name = "AUTH.YAML")]
        authentication: Option<PathBuf>,

        /// Custom (static) headers that should be added to each request. These header
        /// parameters will not be mutated, contrary to the usual header parameters
        /// passed through an API specification.
        #[clap(long, value_parser, value_name = "STATIC_HEADERS.YAML")]
        header: Option<PathBuf>,

        // Manually added possible values below, since automatically showing possible values of an external (remote) enum
        // such as log::LevelFilter is not well supported.
        // See https://github.com/serde-rs/serde/issues/1301, https://github.com/serde-rs/serde/issues/723
        /// Log level to output. This flag takes precedence over the environment variable. [possible values: off, error, warn, debug, info, trace]
        #[arg(value_parser = clap::value_parser!(log::LevelFilter), long, value_enum, env = "LOG_LEVEL", ignore_case = true)]
        log_level: Option<log::LevelFilter>,

        /// Prefix used to filter the classes returned from the jacoco coverage. The class name can be found in the source code of the software under test.
        /// The class name returned from jacoco is in the form of "org/example/software/class".
        /// If no coverage is obtained anymore please check if the prefix is correct. If you use the trace debug level all skipped segment names are logged.
        #[arg(value_parser, long)]
        jacoco_class_prefix: Option<String>,
    },
}

impl Commands {
    fn config_filename(&self) -> Option<&PathBuf> {
        match self {
            Commands::VerifyAuth { config, .. }
            | Commands::Reproduce { config, .. }
            | Commands::Fuzz { config, .. } => config.as_ref(),
            _ => None,
        }
    }

    fn fuzzer_config(self) -> Result<PartialConfiguration, anyhow::Error> {
        match self {
            Commands::VerifyAuth {
                openapi_spec,
                target,
                authentication,
                header,
                log_level,
                ..
            } => Ok(PartialConfiguration {
                openapi_spec,
                target,
                authentication,
                header,
                log_level,
                ..Default::default()
            }),
            Commands::Reproduce {
                openapi_spec,
                target,
                authentication,
                header,
                log_level,
                ..
            } => Ok(PartialConfiguration {
                openapi_spec,
                target,
                authentication,
                header,
                log_level,
                ..Default::default()
            }),
            Commands::Fuzz {
                openapi_spec,
                initial_corpus,
                target: server,
                coverage_host,
                coverage_format,
                timeout,
                request_timeout,
                power_schedule,
                crash_criteria,
                report,
                method_mutation_strategy,
                jacoco_class_dir,
                source_dir,
                output_format,
                authentication,
                header,
                log_level,
                jacoco_class_prefix,
                ..
            } => Ok(PartialConfiguration {
                openapi_spec,
                initial_corpus,
                target: server,
                coverage_host,
                coverage_format,
                timeout,
                request_timeout,
                power_schedule,
                crash_criteria,
                report,
                method_mutation_strategy,
                jacoco_class_dir,
                source_dir,
                output_format,
                authentication,
                header,
                log_level,
                jacoco_class_prefix,
            }),
            Commands::OutputCorpus {
                corpus_directory: _,
                openapi_spec,
                report_path: _,
                log_level,
            } => Ok(PartialConfiguration {
                openapi_spec: Some(openapi_spec),
                log_level,
                ..Default::default()
            }),
            _ => Err(anyhow!(
                "Tried to generate a configuration for an unsupported command"
            )),
        }
    }
}

/// PartialConfiguration is a representation of a WuppieFuzz configuration, obtained from the
/// CLI or from a configuration file.
///
/// Partial configurations are only one source, e.g. config file or command line.
/// You can't make any field mandatory, since then they all need to be specified in both places,
/// which is counterproductive. The Configuration is combined from the two (many?) Partials
/// and does have mandatory fields. Therefore creating a Configuration from a PartialConfiguration
/// using TryFrom can fail.
///
#[derive(Debug, Default, PartialEq, Eq, Deserialize, Parser)]
struct PartialConfiguration {
    /// The path to the open api specification of the target. The specification must
    /// also contain the "server"-field at which the target is hosted.
    #[clap(value_parser, value_name = "OPENAPI_SPEC.YAML")]
    pub openapi_spec: Option<PathBuf>,

    /// The path to an initial corpus given as a directory with yaml files.
    #[clap(short, long, id = "initial_corpus", value_name = "CORPUS_DIRECTORY")]
    pub initial_corpus: Option<PathBuf>,

    /// The URL of the server to fuzz. This is usually specified in the OpenAPI specification,
    /// but you can use this option to override it.
    #[arg(value_parser, long)]
    pub target: Option<Url>,

    /// The host address of the coverage agent from which the coverage map can be obtained.
    /// Can be either a hostname or an IP address, and must include a port.
    #[clap(value_parser=parse_socket_addr, long)]
    pub coverage_host: Option<SocketAddr>,

    /// The format in which your instrumentation provides coverage information.
    /// Must be one of {'jacoco', 'lcov', 'coverband'}. If omitted, the fuzzer will use
    /// endpoint coverage only.
    #[clap(value_parser, long, value_enum, ignore_case = true)]
    pub coverage_format: Option<CoverageFormat>,

    /// Total fuzzing time-out in seconds. If present, the fuzzer exits after the
    /// timeout has passed.
    #[clap(value_parser, long, required_if_eq_all([("report", "true"), ("output_corpus", "false")]))]
    pub timeout: Option<core::num::NonZeroU64>,

    /// Per-request time-out in milliseconds. Defaults to DEFAULT_REQUEST_TIMEOUT milliseconds.
    #[clap(value_parser, long)]
    pub request_timeout: Option<u64>,

    /// Set the power schedule to use. Defaults to FAST.
    #[arg(value_parser, long, value_enum, required = false, ignore_case = true)]
    pub power_schedule: Option<BaseSchedule>,

    /// Which errors the fuzzer considers a bug. By default, all behaviour that does not match the specification is considered a bug.
    ///
    /// The possible errors are:
    /// - "OperationNotInSpec": The operation does not exist in the spec, which incidentally means it should not have been executed by the fuzzer to begin with.
    /// - "StatusNotSpecified": The HTTP status code returned from the API is not one of the status codes mentioned for this path in the specification.
    /// - "ResponseReferenceBroken":  The specification calls for an object to be returned, and refers to the correct structure of this object using a reference (`#/example/reference`). However, the reference path is not present in the specification or contains circular references.
    /// - "ResponseObjectIncorrect": The response body returned by the API does not match the structure specified in the API specification.
    /// - "ResponseEnumIncorrect": A field in the response body object is specified as an enumeration, but the returned value is not one of the possible variants.
    /// - "ResponseMalformedJSON": The response body returned by the API can not be parsed as JSON.
    /// - "UnexpectedContent": The API returned a response body, but no response is specified.
    /// - "MediaTypeContainsNoSchema": The API contains a media type "application/json" with no schema for the data inside the json object. We can't validate the response if no model is given.
    /// - "SchemaIsAny": The schema can be anything (occurs e.g. when it does not specify a type) we cannot validate schemas that are this flexible.
    ///
    /// By default, the value for this option is a list of all of the above. By specifying a subset of the above errors, you can configure what behaviour is considered a bug by the fuzzer.
    #[clap(value_parser, long, value_enum, required = false, ignore_case = true)]
    pub crash_criteria: Option<Vec<ValidationErrorDiscriminants>>,

    /// If present, ask the coverage monitor to generate a report after the
    /// time-out passes
    #[clap(long, value_parser(value_parser!(bool)), num_args(0..=1), require_equals = true, default_missing_value("true"), ignore_case = true)]
    pub report: Option<bool>,

    /// If present, determine with which HTTP methods to mutate.
    /// Must be one of {'follow-spec', 'common5', 'common7'},
    /// followspec: only mutate with methods from api specification
    /// common5: mutate with one of [get, post, put, patch, delete]
    /// common7: mutatue with one of [get, post, put, patch, delete, head, trace]
    /// If omitted, only mutate with methods from api specification.
    #[clap(value_parser, long, value_enum, required = false, ignore_case = true)]
    pub method_mutation_strategy: Option<MethodMutationStrategy>,

    /// When generating a Jacoco coverage report, look for class files in this
    /// directory
    #[clap(value_parser, long, required_if_eq_all([("report", "true"), ("coverage_format", "jacoco")]))]
    pub jacoco_class_dir: Option<PathBuf>,

    /// When generating a coverage report, look for source files in this
    /// directory
    #[clap(value_parser, long, required_if_eq_all([("report", "true"), ("coverage_format", "jacoco")]))]
    pub source_dir: Option<PathBuf>,

    /// Output to stdout can be formatted in human readable format or json.
    #[clap(value_parser, long, value_enum, required = false, ignore_case = true)]
    pub output_format: Option<OutputFormat>,

    /// How to log in to the API server, if applicable. The value should be the
    /// name of a YAML file that contains the login configuration. See login.md
    /// for information on how to build one.
    #[clap(value_parser, long)]
    pub authentication: Option<PathBuf>,

    /// Custom (static) headers that should be added to each request. These header
    /// parameters will not be mutated, contrary to the usual header parameters
    /// passed through an API specification.
    #[clap(value_parser, long)]
    pub header: Option<PathBuf>,

    // Manually added possible values below, since automatically showing possible values of an external (remote) enum
    // such as log::LevelFilter is not well supported.
    // See https://github.com/serde-rs/serde/issues/1301, https://github.com/serde-rs/serde/issues/723
    /// Log level to output. This flag takes precedence over the environment variable. [possible values: off, error, warn, debug, info, trace]
    #[clap(value_parser = clap::value_parser!(log::LevelFilter), long, value_enum, env = "LOG_LEVEL", ignore_case = true)]
    pub log_level: Option<log::LevelFilter>,

    /// Prefix used to filter the classes returned from the jacoco coverage. The class name can be found in the source code of the software under test.
    /// The class name returned from jacoco is in the form of "org/example/software/class".
    /// If no coverage is obtained anymore please check if the prefix is correct. If you use the trace debug level all skipped segment names are logged.
    #[clap(value_parser, long)]
    pub jacoco_class_prefix: Option<String>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum, Deserialize)]
pub enum CoverageFormat {
    #[serde(alias = "jacoco")]
    Jacoco,
    #[serde(alias = "lcov")]
    Lcov,
    #[serde(alias = "coverband")]
    Coverband,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum, Deserialize)]
pub enum OutputFormat {
    #[serde(alias = "json")]
    Json,
    #[serde(
        alias = "human-readable",
        alias = "human_readable",
        alias = "humanreadable"
    )]
    HumanReadable,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum, Deserialize)]
pub enum MethodMutationStrategy {
    #[serde(alias = "follow-spec", alias = "follow_spec", alias = "followspec")]
    FollowSpec,
    #[serde(alias = "common-5", alias = "common_5", alias = "common5")]
    Common5,
    #[serde(alias = "common-7", alias = "common_7", alias = "common7")]
    Common7,
}

/// The main configuration object.
#[derive(PartialEq, Eq)]
pub struct Configuration {
    /// The path to the open api specification of the target. The specification must
    /// also contain the "server"-field at which the target is hosted.
    pub openapi_spec: Option<PathBuf>,

    /// The path to an initial corpus given as a directory with yaml files.
    pub initial_corpus: Option<PathBuf>,

    /// The URL of the server to fuzz. This is usually specified in the OpenAPI specification,
    /// but you can use this option to override it.
    pub target: Option<Url>,

    /// The host address of the coverage agent from which the coverage map can be obtained.
    /// Can be either a hostname or an IP address, and must include a port.
    pub coverage_host: Option<SocketAddr>,

    /// The format in which your instrumentation provides coverage information.
    /// Must be one of {'jacoco', 'lcov', 'coverband'}. If omitted, the fuzzer will use
    /// endpoint coverage only.
    pub coverage_configuration: CoverageConfiguration,

    /// Total fuzzing time-out in seconds. If present, the fuzzer exits after the
    /// timeout has passed.
    pub timeout: Option<core::num::NonZeroU64>,

    /// Per-request time-out in milliseconds. Defaults to DEFAULT_REQUEST_TIMEOUT miliseconds.
    pub request_timeout: u64,

    /// The power schedule to use for prioritizing seeds.
    pub power_schedule: BaseSchedule,

    /// Which errors the fuzzer considers a bug. By default, all behaviour that does not match the specification is considered a bug.
    ///
    /// The possible errors are:
    /// - "OperationNotInSpec": The operation does not exist in the spec, which incidentally means it should not have been executed by the fuzzer to begin with.
    /// - "StatusNotSpecified": The HTTP status code returned from the API is not one of the status codes mentioned for this path in the specification.
    /// - "ResponseReferenceBroken":  The specification calls for an object to be returned, and refers to the correct structure of this object using a reference (`#/example/reference`). However, the reference path is not present in the specification or contains circular references.
    /// - "ResponseObjectIncorrect": The response body returned by the API does not match the structure specified in the API specification.
    /// - "ResponseEnumIncorrect": A field in the response body object is specified as an enumeration, but the returned value is not one of the possible variants.
    /// - "ResponseMalformedJSON": The response body returned by the API can not be parsed as JSON.
    /// - "UnexpectedContent": The API returned a response body, but no response is specified.
    /// - "MediaTypeContainsNoSchema": The API contains a media type "application/json" with no schema for the data inside the json object. We can't validate the response if no model is given.
    /// - "SchemaIsAny": The schema can be anything (occurs e.g. when it does not specify a type) we cannot validate schemas that are this flexible.
    ///
    /// By default, the value for this option is a list of all of the above. By specifying a subset of the above errors, you can configure what behaviour is considered a bug by the fuzzer.
    pub crash_criteria: Vec<ValidationErrorDiscriminants>,

    /// If present, ask the coverage monitor to generate a report after the
    /// time-out passes.
    pub report: bool,

    /// If present, determine with which HTTP methods to mutate.
    /// If omitted, only mutate with methods from api specification.
    pub method_mutation_strategy: MethodMutationStrategy,

    /// Output to stdout can be formatted in human readable format or json.
    pub output_format: OutputFormat,

    /// How to login to the API server, if applicable. The value should be the
    /// name of a YAML file that contains the login configuration. See login.md
    /// for information on how to build one.
    pub authentication: Option<PathBuf>,

    /// Custom (static) headers that should be added to each request. These header
    /// parameters will not be mutated, contrary to the usual header parameters
    /// passed through an API specification.
    pub header: Option<PathBuf>,

    /// Log level to output. This flag takes precedence over the environment variable.
    pub log_level: log::LevelFilter,
}

/// CoverageConfiguration holds all the coverage-agent-specific configuration.
#[derive(Debug, PartialEq, Eq)]
pub enum CoverageConfiguration {
    /// Endpoint coverage only. No further configuration is needed.
    Endpoint,
    /// LCOV coverage. Requires a source directory if a report needs to be generated.
    Lcov { source_dir: Option<PathBuf> },
    /// Jacoco coverage.
    Jacoco {
        /// Source directory, required if a report needs to be generated.
        source_dir: Option<PathBuf>,
        /// Directory for class files, required if a report is needed.
        jacoco_class_dir: Option<PathBuf>,
        /// Prefix for jacoco classes to filter (any classes without the prefix
        /// are ignored). Example: "org/example/software/class"
        jacoco_class_prefix: Option<String>,
    },
    /// Coverband coverage. Requires a source directory if a report needs to be generated.
    Coverband { source_dir: Option<PathBuf> },
}

impl CoverageConfiguration {
    pub fn type_str(&self) -> &'static str {
        match self {
            Self::Endpoint => "endpoint-only",
            Self::Lcov { .. } => "LCOV",
            Self::Jacoco { .. } => "JaCoCo",
            Self::Coverband { .. } => "Coverband",
        }
    }
}

impl Configuration {
    /// Attempts to gather configuration from all sources. If certain required
    /// parameters are missing, the `Err` variant specifies what is missing.
    pub fn get() -> Result<&'static Self, &'static anyhow::Error> {
        CONFIGURATION.as_ref()
    }

    /// Like `get`, but panics if the configuration is incomplete.
    pub fn must_get() -> &'static Self {
        Self::get().expect("Error loading configuration")
    }
}

impl TryFrom<PartialConfiguration> for Configuration {
    type Error = anyhow::Error;

    fn try_from(value: PartialConfiguration) -> Result<Self, Self::Error> {
        if value.report.unwrap_or(false) {
            if value.coverage_format == Some(CoverageFormat::Jacoco)
                && value.jacoco_class_dir.is_none()
            {
                bail!(
                    "A coverage report is requested for Jacoco coverage, but this requires the jacoco_class_dir parameter to be set",
                );
            }
            if value.coverage_format.is_some() && value.source_dir.is_none() {
                bail!(
                    "A coverage report is requested, but this requires the source_dir parameter to be set",
                );
            }
        }

        if value.openapi_spec.is_none() {
            bail!("No OpenAPI specification file given");
        }

        Ok(Self {
            openapi_spec: value.openapi_spec,
            initial_corpus: value.initial_corpus,
            target: value.target,
            coverage_host: value.coverage_host,
            coverage_configuration: match value.coverage_format {
                Some(CoverageFormat::Jacoco) => CoverageConfiguration::Jacoco {
                    source_dir: value.source_dir,
                    jacoco_class_dir: value.jacoco_class_dir,
                    jacoco_class_prefix: value.jacoco_class_prefix,
                },
                Some(CoverageFormat::Lcov) => CoverageConfiguration::Lcov {
                    source_dir: value.source_dir,
                },
                Some(CoverageFormat::Coverband) => CoverageConfiguration::Coverband {
                    source_dir: value.source_dir,
                },
                None => CoverageConfiguration::Endpoint,
            },
            timeout: value.timeout,
            request_timeout: value.request_timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT),
            power_schedule: value.power_schedule.unwrap_or(BaseSchedule::FAST),
            crash_criteria: value
                .crash_criteria
                .unwrap_or_else(|| ValidationErrorDiscriminants::VARIANTS.to_vec()),
            report: value.report.unwrap_or(false),
            method_mutation_strategy: value
                .method_mutation_strategy
                .unwrap_or(DEFAULT_METHOD_MUTATION_STRATEGY),
            output_format: value.output_format.unwrap_or(OutputFormat::HumanReadable),
            authentication: value.authentication,
            header: value.header,
            log_level: value.log_level.unwrap_or(DEFAULT_LOG_LEVEL),
        })
    }
}

impl PartialConfiguration {
    /// Dynamically loads configuration from the command line arguments
    /// and from any file given as `--config <NAME>`.
    /// The values from the cli are preferred if given.
    pub fn get() -> Result<Self, anyhow::Error> {
        // Parse command line arguments
        let cli_config = Cli::parse();
        // Load any configuration file
        let mut file_config = match cli_config.command.config_filename() {
            Some(filename) => PartialConfiguration::from_yaml_file(filename)?,
            None => return cli_config.command.fuzzer_config(),
        };

        // Prefer cli values if present
        file_config.overwrite_from(cli_config.command.fuzzer_config()?);
        Ok(file_config)
    }

    /// Loads a Configuration from a yaml file
    fn from_yaml_file(filename: &Path) -> Result<Self, anyhow::Error> {
        let file = std::fs::File::open(filename)?;
        Ok(serde_yaml::from_reader(file)?)
    }

    /// Overwrites `self` with the options given in other. If `other` contains
    /// None for a certain field, leaves the value from `self` in place.
    fn overwrite_from(&mut self, other: PartialConfiguration) {
        *self = PartialConfiguration {
            openapi_spec: other.openapi_spec.or(self.openapi_spec.take()),
            initial_corpus: other.initial_corpus.or(self.initial_corpus.take()),
            target: other.target.or(self.target.take()),
            coverage_host: other.coverage_host.or(self.coverage_host.take()),
            coverage_format: other.coverage_format.or(self.coverage_format.take()),
            timeout: other.timeout.or(self.timeout.take()),
            request_timeout: other.request_timeout.or(self.request_timeout.take()),
            power_schedule: other.power_schedule.or(self.power_schedule.take()),
            crash_criteria: other.crash_criteria.or(self.crash_criteria.take()),
            report: other.report.or(self.report.take()),
            method_mutation_strategy: other
                .method_mutation_strategy
                .or(self.method_mutation_strategy.take()),
            jacoco_class_dir: other.jacoco_class_dir.or(self.jacoco_class_dir.take()),
            source_dir: other.source_dir.or(self.source_dir.take()),
            output_format: other.output_format.or(self.output_format.take()),
            authentication: other.authentication.or(self.authentication.take()),
            header: other.header.or(self.header.take()),
            log_level: other.log_level.or_else(|| self.log_level.take()),
            jacoco_class_prefix: other
                .jacoco_class_prefix
                .or_else(|| self.jacoco_class_prefix.take()),
        };
    }
}

/// Function which parses a string to a socket address.
///
/// # Arguments
/// * `socket_string` - A String which can be either a host name or an ip-address with the specified port
///
/// # Returns
/// A socket address corresponding to the string
///
/// # Errors
/// The function error when the function `to_socket_addrs` fails or no valid socket is found.
fn parse_socket_addr(arg: &str) -> Result<SocketAddr, io::Error> {
    let mut sockets = arg.to_socket_addrs()?;
    if let Some(socket) = sockets.next() {
        return Ok(socket);
    }
    Err(io::Error::new(
        ErrorKind::InvalidInput,
        "Could not parse socket address",
    ))
}

fn verify_url(arg: &str) -> anyhow::Result<Url> {
    let url = url::Url::parse(arg)?;
    if !url.scheme().starts_with("http") {
        bail!("The given URL does not start with a scheme (http(s)://)")
    }
    if url.host().is_none() {
        bail!("The given URL does not seem to contain a hostname")
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use std::{convert::TryInto, num::NonZeroU64};

    use super::{
        Configuration, CoverageConfiguration, CoverageFormat, DEFAULT_REQUEST_TIMEOUT,
        OutputFormat, PartialConfiguration, parse_socket_addr,
    };

    #[test]
    fn test_try_from_empty() {
        let stored_config: PartialConfiguration = PartialConfiguration {
            ..Default::default()
        };

        let tried_config: Result<Configuration, _> = stored_config.try_into();

        match tried_config {
            Ok(_) => panic!("Incorrect StoredConfig was accepted as Config!"),
            Err(e) => assert_eq!(e.to_string(), "No OpenAPI specification file given"),
        }
    }

    #[test]
    fn test_try_from_simple() {
        let stored_config: PartialConfiguration = PartialConfiguration {
            openapi_spec: Some("open_api.yaml".into()),
            ..Default::default()
        };

        let tried_config: Configuration = stored_config.try_into().unwrap();

        let coverage_config: CoverageConfiguration = CoverageConfiguration::Endpoint;

        assert_eq!(tried_config.request_timeout, DEFAULT_REQUEST_TIMEOUT);
        assert_eq!(tried_config.log_level, log::LevelFilter::Info);
        assert_eq!(tried_config.coverage_configuration, coverage_config)
    }

    #[test]
    fn test_try_from_jacoco_correct() {
        let stored_config: PartialConfiguration = PartialConfiguration {
            openapi_spec: Some("open_api.yaml".into()),
            coverage_format: Some(CoverageFormat::Jacoco),
            output_format: Some(OutputFormat::HumanReadable),
            report: Some(true),
            jacoco_class_dir: Some("/swagger-petstore/target".into()),
            source_dir: Some("/swagger-petstore/src/main/java".into()),
            timeout: NonZeroU64::new(10000),
            coverage_host: Some(parse_socket_addr("127.0.0.1:6300").unwrap()),
            jacoco_class_prefix: Some("org/example/software/class".into()),
            ..Default::default()
        };

        let tried_config: Configuration = stored_config.try_into().unwrap();

        let coverage_config: CoverageConfiguration = CoverageConfiguration::Jacoco {
            source_dir: Some("/swagger-petstore/src/main/java".into()),
            jacoco_class_dir: Some("/swagger-petstore/target".into()),
            jacoco_class_prefix: Some("org/example/software/class".into()),
        };

        assert_eq!(tried_config.coverage_configuration, coverage_config);
        assert_eq!(tried_config.output_format, OutputFormat::HumanReadable);
        assert!(tried_config.report);
        assert_eq!(tried_config.timeout, NonZeroU64::new(10000));
    }

    #[test]
    fn test_try_from_jacoco_incorrect() {
        let stored_config1: PartialConfiguration = PartialConfiguration {
            openapi_spec: Some("open_api.yaml".into()),
            coverage_format: Some(CoverageFormat::Jacoco),
            report: Some(true),
            ..Default::default()
        };

        let tried_config1: Result<Configuration, _> = stored_config1.try_into();

        match tried_config1 {
            Ok(_) => panic!("Incorrect StoredConfig was accepted as Config!"),
            Err(e) => assert_eq!(
                e.to_string(),
                "A coverage report is requested for Jacoco coverage, but this requires the jacoco_class_dir parameter to be set"
            ),
        }

        let stored_config2: PartialConfiguration = PartialConfiguration {
            openapi_spec: Some("open_api.yaml".into()),
            coverage_format: Some(CoverageFormat::Jacoco),
            jacoco_class_dir: Some("/swagger-petstore/target".into()),
            report: Some(true),
            ..Default::default()
        };

        let tried_config2: Result<Configuration, _> = stored_config2.try_into();

        match tried_config2 {
            Ok(_) => panic!("Incorrect StoredConfig was accepted as Config!"),
            Err(e) => assert_eq!(
                e.to_string(),
                "A coverage report is requested, but this requires the source_dir parameter to be set"
            ),
        }
    }

    #[test]
    fn test_overwrite() {
        let mut file_config: PartialConfiguration = PartialConfiguration {
            openapi_spec: Some("open_api.yaml".into()),
            coverage_host: Some(parse_socket_addr("127.0.0.1:6300").unwrap()),
            timeout: NonZeroU64::new(60000),
            request_timeout: Some(10000),
            output_format: Some(OutputFormat::HumanReadable),
            ..Default::default()
        };

        let cli_config: PartialConfiguration = PartialConfiguration {
            openapi_spec: Some("open_api.yaml".into()),
            timeout: NonZeroU64::new(30000),
            output_format: Some(OutputFormat::Json),
            ..Default::default()
        };

        let result_config: PartialConfiguration = PartialConfiguration {
            openapi_spec: Some("open_api.yaml".into()),
            coverage_host: Some(parse_socket_addr("127.0.0.1:6300").unwrap()),
            timeout: NonZeroU64::new(30000),
            request_timeout: Some(10000),
            output_format: Some(OutputFormat::Json),
            ..Default::default()
        };

        file_config.overwrite_from(cli_config);
        assert_eq!(file_config, result_config);
    }
}
