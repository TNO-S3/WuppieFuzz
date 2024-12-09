//! Creates a Software Bill of Materials to be include in every build.

use std::{env, fs::File, io::Write, path::Path};

use cargo_license::{get_dependencies_from_cargo_lock, GetDependenciesOpt};

fn main() {
    let dependencies = get_dependencies_from_cargo_lock(
        Default::default(),
        GetDependenciesOpt {
            avoid_dev_deps: true,
            avoid_build_deps: true,
            direct_deps_only: false,
            root_only: false,
        },
    );

    let allow_list = ["ring 0.17.8"];

    let dep_string = dependencies
        .expect("Failed getting dependencies")
        .iter()
        .map(|dependency| {
            if dependency.license.is_none()
                && !allow_list
                    .contains(&format!("{} {}", dependency.name, dependency.version).as_str())
            {
                panic!(
                    "License information is missing for dependency {} {}",
                    dependency.name, dependency.version
                );
            }
            if dependency.name == "wuppiefuzz" {
                String::new()
            } else {
                format!(
                    "{} {}\n\tlicensed under \"{}\"\n\tby {}\n",
                    dependency.name,
                    dependency.version,
                    dependency.license.as_deref().unwrap_or("custom license"),
                    dependency
                        .authors
                        .as_deref()
                        .unwrap_or("unspecified authors"),
                )
            }
        })
        .collect::<Vec<String>>()
        .join("");

    let sbom_path = Path::new(&env::var("OUT_DIR").unwrap()).join("SBOM.txt");
    let sbom_directory_path = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("SBOM.txt");

    // Create and write to the file
    for file_path in [sbom_path, sbom_directory_path] {
        let mut file = File::create(file_path.clone())
            .unwrap_or_else(|_| panic!("Failed to create {:?}", &file_path.as_path()));
        file.write_all(dep_string.as_bytes())
            .unwrap_or_else(|_| panic!("Failed to write to {:?}", &file_path.as_path()));
    }

    // Tell Cargo to re-run this build script if `build.rs` of `Cargo.lock` is changed
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.lock");
}
