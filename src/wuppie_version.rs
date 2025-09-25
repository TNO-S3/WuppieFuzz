use std::env;

pub fn get_wuppie_version() -> String {
    clap::crate_version!().to_string()
        + include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/version.hash"))
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
        "Software Bill of Materials including license notice\n---------------------------------------------------\n{sbom}"
    );
}
