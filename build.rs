//! Creates a Software Bill of Materials to be include in every build.

use std::{env, fs::File, io::Write, path::Path, process::Command};

use cargo_license::{GetDependenciesOpt, get_dependencies_from_cargo_lock};

fn get_hash_version() -> String {
    let git_output = Command::new("git").arg("rev-parse").arg("HEAD").output();
    match git_output {
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
    }
}

fn main() {
    let dependencies = get_dependencies_from_cargo_lock(
        &Default::default(),
        &GetDependenciesOpt {
            avoid_dev_deps: true,
            avoid_build_deps: true,
            avoid_proc_macros: true,
            direct_deps_only: false,
            root_only: false,
        },
    );

    let allow_list = [];

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
    let version_hash_path =
        Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("version.hash");

    // Create and write to the file
    for (file_path, content) in [
        (sbom_path, &dep_string),
        (sbom_directory_path, &dep_string),
        (version_hash_path, &get_hash_version()),
    ] {
        let mut file = File::create(file_path.clone())
            .unwrap_or_else(|_| panic!("Failed to create {:?}", &file_path.as_path()));
        file.write_all(content.as_bytes())
            .unwrap_or_else(|_| panic!("Failed to write to {:?}", &file_path.as_path()));
    }

    // Corpus minimization depends on Z3, which does not compile on all targets.
    // Use a custom flag to enable corpus minimization on supported targets.
    println!("cargo::rustc-check-cfg=cfg(enable_minimizer)");
    let target = std::env::var("TARGET").unwrap();
    if target.contains("apple") || target == "x86_64-unknown-linux-gnu" {
        println!("cargo:rustc-cfg=enable_minimizer");
    }

    // Tell Cargo to re-run this build script if `build.rs` of `Cargo.lock` is changed
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.lock");
}
