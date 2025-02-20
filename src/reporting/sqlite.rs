use std::{fs::create_dir_all, path::Path};

use anyhow::Context;
use chrono::SecondsFormat;
use libafl::corpus::{InMemoryOnDiskCorpus, OnDiskCorpus};
use log::info;
use rusqlite::{named_params, Connection};

use crate::{
    configuration::Configuration,
    input::{OpenApiInput, OpenApiRequest},
    openapi::{curl_request::CurlRequest, validate_response::Response},
    reporting::Reporting,
    state::OpenApiFuzzerState,
};

/// Instantiates a MySqLite reporter if desired by the configuration
pub fn get_reporter(config: &Configuration) -> Result<Option<MySqLite>, anyhow::Error> {
    if !config.report {
        return Ok(None);
    }
    create_dir_all("reports/grafana")?;
    Ok(Some(MySqLite::new(Path::new("reports/grafana/report.db"))?))
}

pub struct MySqLite {
    conn: Connection,
    run_id: i64,
}

impl MySqLite {
    pub fn new(path: &Path) -> anyhow::Result<MySqLite> {
        let conn = Connection::open(path).expect("Can not create database file for reporting");

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
        Ok(MySqLite { conn, run_id })
    }
}

type Oafs = OpenApiFuzzerState<
    OpenApiInput,
    InMemoryOnDiskCorpus<OpenApiInput>,
    libafl_bolts::rands::RomuDuoJrRand,
    OnDiskCorpus<OpenApiInput>,
>;

impl Reporting<i64, Oafs> for MySqLite {
    fn report_request(
        &self,
        request: &OpenApiRequest,
        curl: &CurlRequest,
        state: &Oafs,
        input_id: usize,
    ) -> i64 {
        let path = &request.path;
        let method = request.method.to_string();

        let time = chrono::offset::Utc::now();
        let mut insert_stmt = self.conn.prepare("INSERT INTO requests (timestamp, testcase, path, type, url, body, inputid, runid, data) VALUES(:timestamp, :testcase, :path, :type, :url, :body, :inputid, :runid, :data)")
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
        insert_stmt
            .insert(params)
            .expect("Could not insert request into database")
    }

    fn report_response(&self, response: &Response, request_id: i64) {
        let response_status = response.status();
        let time = chrono::offset::Utc::now();
        let mut insert_stmt = self
            .conn
            .prepare("INSERT INTO responses (timestamp, status, reqid, data) VALUES(?,?,?,?)")
            .expect("Could not prepare insert statement for response with status");
        insert_stmt
            .insert((
                time.to_rfc3339_opts(SecondsFormat::Millis, true),
                response_status.as_str(),
                request_id,
                response.text().unwrap_or_default(),
            ))
            .expect("Could not insert reponse into database");
    }

    fn report_response_error(&self, error: &str, request_id: i64) {
        let time = chrono::offset::Utc::now();
        let mut insert_stmt = self
            .conn
            .prepare("INSERT INTO responses (timestamp, error, reqid) VALUES(?,?,?)")
            .expect("Could not prepare insert statement for response with status");
        insert_stmt
            .insert((
                time.to_rfc3339_opts(SecondsFormat::Millis, true),
                error,
                request_id,
            ))
            .expect("Could not insert reponse into database");
    }

    fn report_coverage(
        &self,
        line_coverage: u64,
        line_coverage_total: u64,
        endpoint_coverage: u64,
        endpoint_coverage_total: u64,
    ) {
        let mut insert_stmt = self
            .conn
            .prepare("INSERT INTO coverage (line_coverage, line_coverage_total, endpoint_coverage, endpoint_coverage_total, runid) VALUES(?,?,?,?,?)")
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
    }
}
