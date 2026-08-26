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
            .unwrap_or_else(|_| panic!("Failed to create {:?}", file_path.as_path()));
        file.write_all(content.as_bytes())
            .unwrap_or_else(|_| panic!("Failed to write to {:?}", file_path.as_path()));
    }

    // Tell Cargo to re-run this build script if `build.rs` of `Cargo.lock` is changed
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.lock");

    set_main_thread_stack_size();
    enable_link_diagnostics_if_requested();
}

/// Ensures the main thread gets an ~8 MiB stack (matching Linux/macOS defaults),
/// instead of the OS default (1 MiB on Windows). Deep OpenAPI schema resolution
/// (recursive/circular `$ref`s) and other recursive code paths can otherwise
/// overflow the stack on Windows even though they're fine on Unix targets.
///
/// This is set via `cargo:rustc-link-arg` (rather than relying solely on
/// `.cargo/config.toml`'s `rustflags`) because `rustflags` set there can be
/// silently overridden by a `RUSTFLAGS` environment variable set elsewhere in
/// the build pipeline (e.g. by CI tooling), which fully replaces rather than
/// merges with target-specific `rustflags`. Linker args emitted by a build
/// script are not subject to that override and are always applied.
fn set_main_thread_stack_size() {
    const STACK_SIZE_BYTES: u32 = 8 * 1024 * 1024; // 8 MiB

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_env == "msvc" {
        println!("cargo:rustc-link-arg=/STACK:{STACK_SIZE_BYTES}");
    } else {
        // mingw/gnu toolchain
        println!("cargo:rustc-link-arg=-Wl,--stack,{STACK_SIZE_BYTES}");
    }
}

/// Opt-in diagnostic for tracking down `LNK4098: defaultlib '...' conflicts
/// with use of other libs` warnings on MSVC targets. Set the
/// `WUPPIEFUZZ_LINK_VERBOSE` environment variable (to any value) when
/// building/linking to have the linker print, for every input object/library,
/// which C runtime it was compiled against. This makes it possible to spot
/// exactly which dependency doesn't match the rest (e.g. a vendored native
/// library that ignored the `crt-static` target feature), without guessing.
///
/// Left off by default to avoid spamming normal builds with linker noise.
fn enable_link_diagnostics_if_requested() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "windows" && target_env == "msvc" {
        println!("cargo:rustc-link-arg=/VERBOSE:LIB");
    }
}
