use std::{
    cell::Cell,
    fs::{create_dir_all, read_to_string},
    path::{Path, PathBuf},
};

use anyhow::Context;
use chrono::SecondsFormat;
use log::info;
use rusqlite::{Connection, named_params};

use crate::{
    configuration::Configuration,
    coverage_clients::effective_coverage_host,
    input::OpenApiRequest,
    openapi::{curl_request::CurlRequest, spec::Spec, validate_response::Response},
    reporting::Reporting,
    types::OpenApiFuzzerStateType,
    wuppie_version::get_wuppie_version,
};

/// Instantiates a MySqLite reporter if desired by the configuration
pub fn get_reporter(config: &Configuration, api: &Spec) -> Result<Option<MySqLite>, anyhow::Error> {
    if !config.report {
        return Ok(None);
    }
    create_dir_all("reports/grafana")?;
    Ok(Some(MySqLite::new(
        Path::new("reports/grafana/report.db"),
        config,
        api,
    )?))
}

/// Number of inserts between transaction commits. Each commit flushes the WAL
/// to disk, so batching amortises that cost across many writes.
const BATCH_SIZE: u32 = 4096;

pub struct MySqLite {
    conn: Connection,
    run_id: i64,
    inserts_since_commit: Cell<u32>,
}

fn extract_config_file_arg(args: &[String]) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == "--config" {
            return args.get(i + 1).cloned();
        }
        if let Some(value) = arg.strip_prefix("--config=") {
            return Some(value.to_string());
        }
    }
    None
}

fn resolve_config_file_path_and_contents(args: &[String]) -> (Option<String>, Option<String>) {
    let Some(config_file_arg) = extract_config_file_arg(args) else {
        return (None, None);
    };
    let config_file_path = PathBuf::from(config_file_arg);
    let absolute_path = if config_file_path.is_absolute() {
        config_file_path
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(config_file_path.clone()))
            .unwrap_or(config_file_path)
    };
    let resolved_path = std::fs::canonicalize(&absolute_path).unwrap_or(absolute_path);
    let contents = read_to_string(&resolved_path).ok();
    (Some(resolved_path.display().to_string()), contents)
}

impl MySqLite {
    pub fn new(path: &Path, config: &Configuration, api: &Spec) -> anyhow::Result<MySqLite> {
        let conn = Connection::open(path).expect("Can not create database file for reporting");

        // Performance pragmas: WAL mode allows concurrent reads/writes and batches
        // disk syncs. SYNCHRONOUS=NORMAL is safe with WAL (protects against process
        // crashes, not power loss mid-write). Increased cache keeps more pages in memory.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA cache_size=-16000;
             PRAGMA busy_timeout=5000;
             PRAGMA temp_store=MEMORY;",
        )
        .context("Could not set performance pragmas")?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY NOT NULL,
                `timestamp` DATETIME NOT NULL
            )",
            [],
        )
        .context("Could not create `runs` table")?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY NOT NULL,
                `timestamp` DATETIME NOT NULL,
                `testcase` varchar(255),
                `path` varchar(255) NOT NULL,
                `type` varchar(10) NOT NULL,
                `data` blob(65535),
                `url` varchar(65535),
                `body` blob(65535),
                `inputid` INT NOT NULL,
                `runid` INTEGER NOT NULL,
                CONSTRAINT run_FK FOREIGN KEY (runid) REFERENCES runs(id)
            )",
            [],
        )
        .context("Could not create `requests` table")?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS responses (
                id INTEGER PRIMARY KEY NOT NULL,
                `timestamp` DATETIME NOT NULL,
                status INT NULL,
                error varchar(255) NULL,
                data blob(65535),
                reqid int NOT NULL,
                CONSTRAINT responses_FK FOREIGN KEY (reqid) REFERENCES requests(id)
            )",
            [],
        )
        .context("Create responses table")?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS coverage (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                `timestamp` DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                `line_coverage` INT NULL,
                `line_coverage_total` INT NULL,
                `endpoint_coverage` INT NULL,
                `endpoint_coverage_total` INT NULL,
                `runid` INTEGER NOT NULL,
                CONSTRAINT run_FK FOREIGN KEY (runid) REFERENCES runs(id)
            )",
            [],
        )
        .context("Could not create `coverage` table")?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS run_configuration (
                runid INTEGER PRIMARY KEY NOT NULL,
                wuppiefuzz_version TEXT NOT NULL,
                target_spec TEXT,
                target_title TEXT NOT NULL,
                target_version TEXT NOT NULL,
                run_command_args TEXT NOT NULL,
                config_file_path TEXT,
                config_file_contents TEXT,
                target TEXT,
                coverage_format TEXT NOT NULL,
                coverage_host TEXT,
                timeout_secs INTEGER,
                request_timeout_ms INTEGER NOT NULL,
                power_schedule TEXT NOT NULL,
                crash_criteria TEXT NOT NULL,
                method_mutation_strategy TEXT NOT NULL,
                output_format TEXT NOT NULL,
                CONSTRAINT run_configuration_FK FOREIGN KEY (runid) REFERENCES runs(id)
            )",
            [],
        )
        .context("Could not create `run_configuration` table")?;

        info!("Created tables for the reporting");

        let mut stmt = conn
            .prepare("INSERT INTO runs (timestamp) VALUES(?)")
            .context("Could not prepare insert statement for runs")?;
        let time = chrono::offset::Utc::now();
        let run_id = stmt
            .insert([time.to_rfc3339_opts(SecondsFormat::Millis, true)])
            .context("Could not create new run")?;
        // end borrow of connection
        drop(stmt);

        let crash_criteria = config
            .crash_criteria
            .iter()
            .map(|c| format!("{c:?}"))
            .collect::<Vec<_>>()
            .join(",");
        let resolved_target_spec = config.openapi_spec.as_ref().map(|path| {
            std::fs::canonicalize(path)
                .unwrap_or_else(|_| path.clone())
                .display()
                .to_string()
        });
        let raw_args = std::env::args_os()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        let run_command_args = serde_json::to_string(&raw_args)
            .context("Could not serialize run command arguments")?;
        let (config_file_path, config_file_contents) =
            resolve_config_file_path_and_contents(&raw_args);
        conn.execute(
            "INSERT INTO run_configuration (
                runid, wuppiefuzz_version, target_spec, target_title, target_version,
                run_command_args, config_file_path, config_file_contents,
                target, coverage_format, coverage_host, timeout_secs, request_timeout_ms,
                power_schedule, crash_criteria, method_mutation_strategy, output_format
            ) VALUES (
                :runid, :wuppiefuzz_version, :target_spec, :target_title, :target_version,
                :run_command_args, :config_file_path, :config_file_contents,
                :target, :coverage_format, :coverage_host, :timeout_secs, :request_timeout_ms,
                :power_schedule, :crash_criteria, :method_mutation_strategy, :output_format
            )",
            named_params! {
                ":runid": run_id,
                ":wuppiefuzz_version": get_wuppie_version(),
                ":target_spec": resolved_target_spec,
                ":target_title": &api.info.title,
                ":target_version": &api.info.version,
                ":run_command_args": run_command_args,
                ":config_file_path": config_file_path,
                ":config_file_contents": config_file_contents,
                ":target": api.servers.first().map(|s| s.url.as_str()),
                ":coverage_format": config.coverage_configuration.type_str(),
                ":coverage_host": config.coverage_host.map(|h| h.to_string()),
                ":timeout_secs": config.timeout.map(|t| t.get() as i64),
                ":request_timeout_ms": config.request_timeout as i64,
                ":power_schedule": format!("{:?}", config.power_schedule),
                ":crash_criteria": crash_criteria,
                ":method_mutation_strategy": format!("{:?}", config.method_mutation_strategy),
                ":output_format": format!("{:?}", config.output_format),
            },
        )
        .context("Could not insert run configuration")?;

        // Begin a long-running transaction. Individual inserts execute immediately
        // (so row IDs are available) but the disk flush is deferred until commit.
        conn.execute_batch("BEGIN")
            .context("Could not begin initial transaction")?;

        Ok(MySqLite {
            conn,
            run_id,
            inserts_since_commit: Cell::new(0),
        })
    }

    /// Commits the current transaction and begins a new one when the batch
    /// threshold is reached. Called after every insert.
    fn maybe_commit_batch(&self) {
        let count = self.inserts_since_commit.get() + 1;
        if count >= BATCH_SIZE {
            self.conn
                .execute_batch("COMMIT; BEGIN")
                .expect("Could not commit batch transaction");
            self.inserts_since_commit.set(0);
        } else {
            self.inserts_since_commit.set(count);
        }
    }
}

impl Drop for MySqLite {
    fn drop(&mut self) {
        // Flush any remaining inserts
        let _ = self.conn.execute_batch("COMMIT");
    }
}

impl Reporting<i64, OpenApiFuzzerStateType> for MySqLite {
    fn report_request(
        &self,
        request: &OpenApiRequest,
        curl: &CurlRequest,
        state: &OpenApiFuzzerStateType,
        input_id: u32,
    ) -> i64 {
        let path = &request.path;
        let method = request.method.to_string();

        let time = chrono::offset::Utc::now();
        let mut insert_stmt = self.conn.prepare_cached("INSERT INTO requests (timestamp, testcase, path, type, url, body, inputid, runid, data) VALUES(:timestamp, :testcase, :path, :type, :url, :body, :inputid, :runid, :data)")
            .expect("Could not prepare insert statement for request");
        let params = named_params! {
            ":timestamp": time.to_rfc3339_opts(SecondsFormat::Millis, true),
            ":testcase": super::get_current_test_case_file_name(state),
            ":path": path,
            ":type": method,
            ":data": curl.to_string(),
            ":url": curl.url(),
            ":body": curl.body().map(String::from_utf8_lossy),
            ":inputid": input_id,
            ":runid": self.run_id,
        };
        let id = insert_stmt
            .insert(params)
            .expect("Could not insert request into database");
        self.maybe_commit_batch();
        id
    }

    fn report_response(&self, response: &Response, request_id: i64) {
        let response_status = response.status();
        let time = chrono::offset::Utc::now();
        let mut insert_stmt = self
            .conn
            .prepare_cached(
                "INSERT INTO responses (timestamp, status, reqid, data) VALUES(?,?,?,?)",
            )
            .expect("Could not prepare insert statement for response with status");
        insert_stmt
            .insert((
                time.to_rfc3339_opts(SecondsFormat::Millis, true),
                response_status.as_str(),
                request_id,
                response.text().unwrap_or_default(),
            ))
            .expect("Could not insert reponse into database");
        self.maybe_commit_batch();
    }

    fn report_response_error(&self, error: &str, request_id: i64) {
        let time = chrono::offset::Utc::now();
        let mut insert_stmt = self
            .conn
            .prepare_cached("INSERT INTO responses (timestamp, error, reqid) VALUES(?,?,?)")
            .expect("Could not prepare insert statement for response with status");
        insert_stmt
            .insert((
                time.to_rfc3339_opts(SecondsFormat::Millis, true),
                error,
                request_id,
            ))
            .expect("Could not insert reponse into database");
        self.maybe_commit_batch();
    }

    fn report_coverage(
        &self,
        line_coverage: u32,
        line_coverage_total: u32,
        endpoint_coverage: u32,
        endpoint_coverage_total: u32,
    ) {
        let mut insert_stmt = self
            .conn
            .prepare_cached("INSERT INTO coverage (line_coverage, line_coverage_total, endpoint_coverage, endpoint_coverage_total, runid) VALUES(?,?,?,?,?)")
            .expect("Could not prepare insert statement for coverage");
        insert_stmt
            .insert((
                line_coverage,
                line_coverage_total,
                endpoint_coverage,
                endpoint_coverage_total,
                self.run_id,
            ))
            .expect("Could not insert coverage into database");
        self.maybe_commit_batch();
    }
}
