---
name: cleanup
description: "Clean up and simplify existing code: remove redundant tests, combine similar tests, simplify verbose Rust idioms. Use when: the user asks to clean up, simplify, or refactor code. Invoke with /cleanup. Scope is inferred from: explicit path argument, attached/referenced files, current editor file, or whole codebase (asks for confirmation)."
---

# Cleanup

Improve code quality by simplifying and consolidating existing code. Do not implement new features or change behaviour.

## Scope

Determine the scope from the most specific signal available, in this order:

1. **Explicit path argument** — if the user typed `/cleanup <path>`, restrict to that file or directory.
2. **Attached files** — if the user attached files to the chat (via `#file` or drag-and-drop), restrict to those files.
3. **Current editor file** — if the active editor file is visible in context, restrict to that file.
4. **Whole codebase** — if none of the above apply, apply to the whole codebase.

Ask the user to confirm before applying cleanup to the whole codebase.

In both cases, apply the same scope discipline as for feature work: only touch code that directly serves one of the cleanup goals below. Do not make incidental changes to unrelated lines while passing through a file.

## Cleanup Goals

1. **Simplify verbose code.** Replace unnecessarily verbose constructs with idiomatic Rust equivalents — e.g. manual loops that can be iterators, redundant clones, match arms that can be `if let`, etc.

2. **Remove redundant tests.** Delete tests that duplicate another test's coverage exactly, without adding a distinct case, edge case, or failure mode.

3. **Combine similar tests.** Where multiple `#[test]` functions assert the same thing with different inputs, consolidate into a table-driven test (a single test with an array of `(input, expected)` cases and a `for` loop). Preserve one test per distinct behaviour — do not merge tests that cover meaningfully different scenarios.

4. **Do not change public APIs.** Do not rename public functions, types, or modules, and do not change function signatures. Internal renames within a private scope are allowed if they improve clarity.

5. **Do not restructure modules.** Do not move code between files or modules.

## Done

After completing cleanup, run `cargo test --workspace` to confirm no behaviour was changed, then summarise what was simplified or removed.
