# WuppieFuzz — Agent Instructions

WuppieFuzz is a **coverage-guided REST API fuzzer** built on [LibAFL](https://github.com/AFLplusplus/LibAFL), written in Rust (edition 2024). It accepts an OpenAPI specification and fuzzes the target API using a dependency graph to generate and mutate request sequences.

## Repository Layout

```
src/
  main.rs                  # CLI entry point (clap)
  configuration.rs         # All config structs (CorpusSequenceMode, PathGenerationConfig, …)
  fuzzer.rs                # Core fuzzing loop
  executor.rs              # HTTP request execution
  initial_corpus/
    dependency_graph/      # OpenAPI dependency graph + corpus generation
      mod.rs               # initial_corpus_from_api(), enumerate_paths(), …
      normalize.rs         # ParameterNormalization
  openapi/
    spec/mod.rs            # Spec wrapper around oas3::Spec
    examples.rs            # all_interesting_inputs_for_operations(), example generation
    mod.rs                 # QualifiedOperation
  input/mod.rs             # OpenApiInput, OpenApiRequest, Body, ParameterKind
  authentication/          # Auth strategies (Bearer, Basic, ApiKey, …)
  coverage_clients/        # JaCoCo, LCOV, Python coverage adapters
  reporting/               # HTML/JSON report generation
  openapi_mutator/         # Mutation strategies
.github/workflows/rust.yml # CI pipeline (formatting, clippy, build, test, coverage)
rustfmt.toml               # group_imports = "StdExternalCrate", imports_granularity = "Crate"
Cargo.toml                 # Single-crate workspace, edition 2024
```

## Developer Setup

After cloning, activate the shared git hooks once:

```sh
git config core.hooksPath .githooks
```

The pre-commit hook in `.githooks/pre-commit` runs `cargo fmt --check` and `cargo clippy` before every commit, catching CI failures locally before they reach the pipeline.

## Test-Driven Development Workflow

When implementing a new feature, follow this order:

1. **Plan tests first.** Before writing any implementation code, identify a minimal, meaningful set of tests that define the expected behaviour. Prefer unit tests co-located with the module under test (inside `mod tests { … }` blocks). Write the test stubs and assert on the expected outcomes.
2. **Confirm tests fail.** Run `cargo test <test_name>` to verify the new tests fail for the right reason (missing implementation, not a compile error in the test itself).
3. **Implement the feature.** Write only as much code as needed to make the tests pass. Avoid scope creep.
4. **Confirm tests pass.** Run `cargo test --workspace`.

## Scope Discipline

Only modify code that is directly required to implement the requested feature or fix. Do not touch unrelated lines, even if they could be improved — no incidental refactors, syntax sugar, style cleanups, or renamings outside the scope of the task. Leave existing code exactly as-is unless it must change.

## Rust Conventions

- **Error handling**: use `anyhow::Result` / `anyhow::anyhow!` for propagating errors. Avoid `unwrap()` and `expect()` outside of test code.
- **Imports**: `rustfmt.toml` enforces `group_imports = "StdExternalCrate"` and `imports_granularity = "Crate"` — let `cargo fmt` handle import ordering.
- **Key crates**: `oas3` (OpenAPI parsing), `petgraph` (dependency graph), `libafl` (fuzzer core), `clap` (CLI), `anyhow` (errors), `serde`/`serde_yaml` (serialization), `indexmap` (order-preserving maps).
- **Tests**: constructing a `Spec` in tests — use `Spec::from(oas3::Spec { … })` with `IndexMap` for paths. See `src/openapi/spec/mod.rs` for existing patterns.
- **Documentation**: the CI runs a non-blocking doc coverage check (`-D missing_docs`). Add doc comments to public items when practical.
