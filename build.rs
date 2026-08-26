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
    diagnose_crt_mismatch();
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

/// Temporary diagnostic for tracking down the `LNK4098: defaultlib 'libcmt'
/// conflicts with use of other libs` warning on MSVC targets.
///
/// Every object compiled for MSVC embeds its requested C runtime as a
/// plain-text `/DEFAULTLIB:"..."` directive, so the dependency responsible
/// for pulling in the "wrong" CRT (dynamic `MSVCRT` instead of the static
/// `LIBCMT` cargo-dist's `msvc-crt-static = true` default expects, or vice
/// versa) can be found by scanning each `.rlib` already produced under
/// `target/` for those markers — no `dumpbin`/`link.exe` access required.
/// Findings are emitted as `cargo:warning`s so they show up directly in the
/// build log. Remove this function (and its call site) once the mismatched
/// dependency has been identified and fixed.
fn diagnose_crt_mismatch() {
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_env != "msvc" {
        return;
    }

    if let Ok(out_dir) = env::var("OUT_DIR") {
        // OUT_DIR looks like .../target/<profile>/build/<crate>-<hash>/out;
        // walk back up to the shared `target/<profile>` directory that
        // holds both the `deps` rlibs and every crate's `build/*/out`
        // directory (where vendored C/C++ deps like aws-lc-sys/z3-sys/
        // libsqlite3-sys drop their compiled *.lib archives directly --
        // those are linked straight in and never get wrapped in an rlib,
        // so they were missed by an earlier, `deps`-only version of this
        // scan).
        if let Some(profile_dir) = Path::new(&out_dir)
            .ancestors()
            .find(|p| p.join("deps").is_dir())
            .and_then(|p| p.parent())
        {
            scan_dir_for_crt_markers_recursive(profile_dir);
        }
    }

    // Our own dependencies aren't the only objects linked in: rustup ships
    // prebuilt `std`/`core`/`panic_unwind`/etc. rlibs in the toolchain
    // sysroot that were compiled once upstream and can't retroactively pick
    // up this crate's `crt-static` target feature. Scan those too, since
    // they're a likely source of a stray `MSVCRT` reference.
    if let Ok(output) = Command::new("rustc").arg("--print").arg("sysroot").output() {
        if let Ok(sysroot) = String::from_utf8(output.stdout) {
            let target_triple = env::var("TARGET").unwrap_or_default();
            let libdir = Path::new(sysroot.trim())
                .join("lib/rustlib")
                .join(&target_triple)
                .join("lib");
            scan_dir_for_crt_markers_recursive(&libdir);
        }
    }
}

fn scan_dir_for_crt_markers_recursive(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_dir_for_crt_markers_recursive(&path);
            continue;
        }
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if ext != "rlib" && ext != "lib" {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        // Directives are plain ASCII text embedded in the .drectve section;
        // a lossy scan is enough to spot the markers.
        let text = String::from_utf8_lossy(&bytes);
        let has_libcmt = text.contains("LIBCMT") && !text.contains("LIBCMTD");
        let has_libcmtd = text.contains("LIBCMTD");
        let has_msvcrt = text.contains("MSVCRT") && !text.contains("MSVCRTD");
        let has_msvcrtd = text.contains("MSVCRTD");
        if has_libcmt || has_libcmtd || has_msvcrt || has_msvcrtd {
            println!(
                "cargo:warning=CRT scan: {} -> LIBCMT={has_libcmt} LIBCMTD={has_libcmtd} MSVCRT={has_msvcrt} MSVCRTD={has_msvcrtd}",
                path.display()
            );
        }
    }
}
