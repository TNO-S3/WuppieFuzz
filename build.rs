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
    suppress_benign_libcmt_relink_warning();
    regenerate_third_party_notices();
}

/// Regenerates `THIRD_PARTY_NOTICES` from the current dependency tree via
/// `cargo-about` (config: `about.toml`), so the file can never silently drift
/// from `Cargo.lock` the way it used to when it was hand-maintained. This is
/// best-effort: `cargo-about` is a separate binary that most contributors
/// won't have installed, so a missing tool or a failing invocation only
/// emits a `cargo:warning` rather than failing the build.
///
/// We ask cargo-about for raw JSON rather than rendering through a Handlebars
/// template, because cargo-about harvests license text per unique *exact
/// text* match found anywhere in a crate's source tree, not just its
/// top-level LICENSE file(s). For a given SPDX id this often yields several
/// textual variants across crates (and, for crates like `encoding_rs` that
/// embed a copy of their license as a doc-comment header in multiple source
/// files, even variants that trail off into unrelated source code). Grouping
/// and picking a clean representative ourselves avoids both problems.
fn regenerate_third_party_notices() {
    let manifest_dir = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).to_path_buf();
    println!("cargo:rerun-if-changed=about.toml");

    let output = Command::new("cargo")
        .args(["about", "generate", "--format", "json"])
        .current_dir(&manifest_dir)
        .output();

    let output = match output {
        Ok(output) => output,
        Err(err) => {
            println!(
                "cargo:warning=Skipping THIRD_PARTY_NOTICES regeneration: could not run `cargo about` ({err}). Install it with `cargo install cargo-about --features cli` to keep the file up to date."
            );
            return;
        }
    };

    if !output.status.success() {
        println!(
            "cargo:warning=Skipping THIRD_PARTY_NOTICES regeneration: `cargo about generate` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let notices = match render_notices_from_json(&output.stdout) {
        Ok(notices) => notices,
        Err(err) => {
            println!(
                "cargo:warning=Skipping THIRD_PARTY_NOTICES regeneration: couldn't parse `cargo about` output: {err}"
            );
            return;
        }
    };

    let notices_path = manifest_dir.join("THIRD_PARTY_NOTICES");
    if let Err(err) = std::fs::write(&notices_path, notices) {
        println!(
            "cargo:warning=Skipping THIRD_PARTY_NOTICES regeneration: failed to write {notices_path:?}: {err}"
        );
    }
}

/// Groups cargo-about's per-license-text entries by SPDX id, picks a single
/// shared body per id (cargo-about's own canonical/synthesized text when
/// available, else the shortest harvested variant), and then for every other
/// variant diffs its text against that body to recover the lines it adds
/// (almost always just its crate's copyright notice), so attributions aren't
/// silently dropped just because their crate's own LICENSE file wasn't
/// chosen as the shared body. Renders the result in the project's
/// established notices format.
fn render_notices_from_json(json_bytes: &[u8]) -> Result<String, String> {
    use std::collections::{BTreeMap, BTreeSet};

    let parsed: serde_json::Value =
        serde_json::from_slice(json_bytes).map_err(|err| err.to_string())?;
    let licenses = parsed["licenses"]
        .as_array()
        .ok_or("missing `licenses` array in cargo-about output")?;

    struct Variant {
        text: String,
        is_canonical: bool,
        /// (name, version) of the crates whose license text matches this
        /// variant exactly.
        crates: BTreeSet<(String, String)>,
    }

    struct Group {
        name: String,
        variants: Vec<Variant>,
        all_crates: BTreeSet<String>,
    }

    let mut groups: BTreeMap<String, Group> = BTreeMap::new();
    for license in licenses {
        let id = license["id"].as_str().unwrap_or_default().to_string();
        let name = license["name"].as_str().unwrap_or_default().to_string();
        let text = license["text"]
            .as_str()
            .unwrap_or_default()
            .trim()
            .to_string();
        let is_canonical = license["source_path"].is_null();
        let crates: BTreeSet<(String, String)> = license["used_by"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|u| {
                let name = u["crate"]["name"].as_str()?;
                let version = u["crate"]["version"].as_str().unwrap_or_default();
                Some((name.to_string(), version.to_string()))
            })
            .collect();

        let group = groups.entry(id).or_insert_with(|| Group {
            name: name.clone(),
            variants: Vec::new(),
            all_crates: BTreeSet::new(),
        });
        group
            .all_crates
            .extend(crates.iter().map(|(name, _)| name.clone()));
        group.variants.push(Variant {
            text,
            is_canonical,
            crates,
        });
    }

    let mut out = String::new();
    out.push_str(
        "===============================================================================\n\
         \x20                            THIRD-PARTY LICENSES\n\
         ===============================================================================\n\n\
         This product includes third-party software components, auto-generated with\n\
         cargo-about (see about.toml and build.rs). Do not edit this file by hand;\n\
         regenerate it instead.\n\n",
    );
    for (id, group) in &groups {
        // Prefer cargo-about's own canonical/synthesized text (not tied to
        // any one crate's file) as the shared body; otherwise fall back to
        // the shortest harvested variant, since a variant that accidentally
        // captured trailing content (e.g. a license embedded as a doc
        // comment followed by source code) is strictly longer than the
        // genuine standalone license text.
        let body_variant = group
            .variants
            .iter()
            .find(|v| v.is_canonical)
            .or_else(|| group.variants.iter().min_by_key(|v| v.text.len()))
            .expect("every group has at least one variant");
        let body_text = &body_variant.text;

        // For every other variant, diff it against the shared body and keep
        // only the lines it adds that look like a genuine copyright
        // notice (as opposed to e.g. unrelated trailing content, or
        // boilerplate license prose that merely happens to be reflowed
        // differently). Variants that render the same diff are merged so
        // each distinct notice is shown once, together with every crate it
        // applies to.
        let mut deviations: BTreeMap<String, BTreeSet<(String, String)>> = BTreeMap::new();
        for variant in &group.variants {
            if &variant.text == body_text {
                continue;
            }
            let notice: Vec<String> = diff_added_lines(body_text, &variant.text)
                .into_iter()
                .filter(|line| looks_like_copyright_notice(line))
                .map(|line| strip_comment_markers(&line))
                .collect();
            if notice.is_empty() {
                continue;
            }
            deviations
                .entry(notice.join("\n"))
                .or_default()
                .extend(variant.crates.iter().cloned());
        }

        // A crate name only needs its version appended for disambiguation if
        // it shows up under more than one distinct notice in this section
        // (e.g. because two of its own license files, or two of its
        // versions in Cargo.lock, carry different copyright lines);
        // otherwise showing the version everywhere would just be noise that
        // churns on every version bump.
        let mut notice_count_by_name: BTreeMap<&str, usize> = BTreeMap::new();
        for crates in deviations.values() {
            for name in crates
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<BTreeSet<_>>()
            {
                *notice_count_by_name.entry(name).or_default() += 1;
            }
        }

        out.push_str(
            "===============================================================================\n",
        );
        out.push_str(&format!("{id} LICENSE NOTICE\n\n"));
        out.push_str(&format!(
            "This product includes software licensed under the {}:\n\n",
            group.name
        ));
        out.push_str(strip_placeholder_copyright_lines(body_text).trim());
        out.push_str("\n\n");
        if !deviations.is_empty() {
            out.push_str("Copyright notices (differences from the text above):\n\n");
            for (notice, crates) in &deviations {
                let labels: BTreeSet<String> = crates
                    .iter()
                    .map(|(name, version)| {
                        if notice_count_by_name
                            .get(name.as_str())
                            .copied()
                            .unwrap_or(0)
                            > 1
                        {
                            format!("{name} {version}")
                        } else {
                            name.clone()
                        }
                    })
                    .collect();
                out.push_str("- ");
                out.push_str(&labels.into_iter().collect::<Vec<_>>().join(", "));
                out.push_str(":\n");
                for line in notice.lines() {
                    out.push_str("    ");
                    out.push_str(line);
                    out.push('\n');
                }
            }
            out.push('\n');
        }
        out.push_str("Components:\n\n");
        for name in &group.all_crates {
            out.push_str("- ");
            out.push_str(name);
            out.push('\n');
        }
        out.push('\n');
    }
    out.push_str(
        "===============================================================================\n",
    );

    Ok(out)
}

/// Line-level diff of `base` against `other`, returning the lines present in
/// `other` that aren't part of their longest common (line) subsequence with
/// `base` — i.e. the lines `other` adds or changes relative to `base`.
/// Blank lines are dropped, since differing blank-line counts aren't
/// meaningful content to report.
fn diff_added_lines(base: &str, other: &str) -> Vec<String> {
    let a: Vec<&str> = base.lines().collect();
    let b: Vec<&str> = other.lines().collect();
    let (n, m) = (a.len(), b.len());

    // dp[i][j] = length of the LCS of a[i..] and b[j..].
    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if a[i] == b[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }

    let (mut i, mut j) = (0, 0);
    let mut added = Vec::new();
    while i < n && j < m {
        if a[i] == b[j] {
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            i += 1;
        } else {
            added.push(b[j].trim().to_string());
            j += 1;
        }
    }
    added.extend(b[j..].iter().map(|line| line.trim().to_string()));
    added.retain(|line| !line.is_empty());
    added
}

/// Whether a single line looks like a genuine copyright attribution (e.g.
/// `Copyright (c) 2016 Jane Doe` or `© WHATWG (Apple, Google, Mozilla,
/// Microsoft)`), as opposed to unrelated content that merely starts with the
/// word "copyright" (e.g. a line-wrapped continuation of license boilerplate
/// like "...provided that the above\ncopyright notice and this permission
/// notice..."). Requiring a "(c)"/"©" mark or a 4-digit year in addition to
/// the leading "copyright"/"©" catches real notices while rejecting prose.
fn looks_like_copyright_notice(line: &str) -> bool {
    let trimmed = strip_comment_markers(line);
    let lower = trimmed.to_lowercase();
    let starts_with_copyright_mark = lower.starts_with("copyright") || trimmed.starts_with('©');
    let has_attribution_marker =
        lower.contains("(c)") || trimmed.contains('©') || contains_four_digit_year(&lower);
    starts_with_copyright_mark
        && has_attribution_marker
        && !is_unfilled_copyright_placeholder(&lower)
}

/// Strips common source-comment leaders (`//`, `#`, `*`) and surrounding
/// whitespace from a line, e.g. turning `// Copyright 2016 Jane Doe` (as
/// found in a crate's `.rs` file header) into `Copyright 2016 Jane Doe`.
fn strip_comment_markers(line: &str) -> String {
    line.trim()
        .trim_start_matches(['/', '#', '*', ' '])
        .trim()
        .to_string()
}

/// Whether `text` contains a run of 4 consecutive ASCII digits, i.e. plausibly a year.
fn contains_four_digit_year(text: &str) -> bool {
    text.as_bytes()
        .windows(4)
        .any(|window| window.iter().all(u8::is_ascii_digit))
}

/// Whether a (lowercased) line is an unfilled `Copyright (c) <year> <owner>`
/// style placeholder from a generic SPDX license template, rather than a real
/// attribution to a specific person or organization.
fn is_unfilled_copyright_placeholder(lowercased_line: &str) -> bool {
    const PLACEHOLDERS: [&str; 2] = ["<year> <owner>", "[yyyy] [name of copyright owner]"];
    PLACEHOLDERS
        .iter()
        .any(|placeholder| lowercased_line.contains(placeholder))
}

/// Strips unfilled `Copyright (c) <year> <owner>` placeholder lines out of a
/// license body before display, since real copyright holders are already
/// listed separately (see the `Copyright notices` section built from
/// `diff_added_lines`/`looks_like_copyright_notice`) and repeating an
/// unfilled placeholder alongside them would be confusing noise.
fn strip_placeholder_copyright_lines(text: &str) -> String {
    text.lines()
        .filter(|line| !is_unfilled_copyright_placeholder(&line.to_lowercase()))
        .collect::<Vec<_>>()
        .join("\n")
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

/// Silences the `LNK4098: defaultlib 'libcmt' conflicts with use of other
/// libs` linker warning on MSVC targets.
///
/// Investigated at length: every native/static dependency in the link (our
/// vendored `z3-sys`, `aws-lc-sys`, `libsqlite3-sys`, the Rust standard
/// library, and every intermediate object) consistently references only the
/// static, release CRT (`LIBCMT`) -- there is no genuine dynamic-vs-static
/// or debug-vs-release CRT mismatch. The warning is purely cosmetic: MSVC's
/// `link.exe` re-emits it whenever more than one input object embeds its own
/// `/DEFAULTLIB:LIBCMT` directive, which is unavoidable once Z3's build
/// produces dozens of separate static-library fragments that each redundantly
/// declare the (correct, matching) runtime. Rather than lose the benefits of
/// a fully static CRT (no VC++ Redistributable required for end users) to
/// work around a non-issue, just tell the linker to stop repeating a
/// duplicate-but-consistent default-library directive.
fn suppress_benign_libcmt_relink_warning() {
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_env == "msvc" {
        println!("cargo:rustc-link-arg=/IGNORE:4098");
    }
}
