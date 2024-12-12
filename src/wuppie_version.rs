use std::{env, process::Command};

pub fn get_wuppie_version() -> String {
    let git_output = Command::new("git").arg("rev-parse").arg("HEAD").output();
    let git_hash = match git_output {
        Ok(v) => {
            if v.stdout.is_empty() {
                "".to_string()
            } else {
                "-".to_string().clone()
                    + &String::from_utf8(v.stdout)
                        .clone()
                        .unwrap_or("Invalid UTF8 output".to_string())
            }
        }
        Err(_) => "<could not get git hash>".to_string(),
    };

    clap::crate_version!().to_string() + &git_hash
}

pub fn print_version() {
    println!("WuppieFuzz version: {}", get_wuppie_version())
}

pub fn print_license() {
    print_version();
    println!(
        "===============================================================================\
    \n                                LICENSE NOTICE\n\
    ===============================================================================\
    \n{}\n{}\n\
    ===============================================================================",
        include_str!("../LICENSE"),
        include_str!("../LICENSE.THIRDPARTY")
    )
}

pub fn print_sbom() {
    print_version();

    let sbom = include_str!(concat!(env!("OUT_DIR"), "/SBOM.txt"));
    print!(
        "Software Bill of Materials including license notice\n---------------------------------------------------\n{}",
        sbom
    );
}
