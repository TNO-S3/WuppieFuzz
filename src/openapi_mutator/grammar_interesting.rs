//! Mutates a string parameter value by generating payloads from small, randomized
//! grammars (regexes), rather than inserting one of a handful of fixed strings.
//!
//! This is inspired by LibAFL's Nautilus grammar-based mutator: instead of a
//! context-free derivation tree, we use lightweight regex "grammars" (already used
//! elsewhere in WuppieFuzz to generate values matching an OpenAPI schema's
//! `pattern`) to produce varied payloads for common vulnerability classes
//! (SQL/NoSQL/LDAP/command/template injection, XSS, path traversal, ...). Each
//! mutation samples a fresh string from a randomly chosen grammar, so the exact
//! numbers, quoting style, and alternatives differ between runs, unlike a static
//! wordlist.

use std::borrow::Cow;

use libafl::{
    Error,
    corpus::CorpusId,
    inputs::{BytesInput, ResizableMutator},
    mutators::{MutationResult, Mutator},
    state::HasRand,
};
use libafl_bolts::{Named, rands::Rand};
use rand::prelude::Distribution;

/// Regex-based "grammars" that generate varied payloads for common
/// vulnerability classes. Repetition inside each pattern is intentionally kept
/// small, so generated values stay short and readable.
const INTERESTING_GRAMMARS: [&str; 11] = [
    // SQL boolean-based tautology
    r"'( OR | AND )[0-9]{1,3}=[0-9]{1,3}(--)?",
    // SQL time-based blind injection
    r"'; ?(WAITFOR DELAY '0:0:[0-5][0-9]'|SLEEP\([0-5][0-9]\))--",
    // Reflected/stored XSS
    r"(<script>alert\((1|'XSS')\)</script>|<img src=x onerror=alert\([0-9]{1,3}\)>)",
    // Path traversal
    r"(\.\./){1,6}(etc/passwd|etc/shadow|windows/win\.ini)",
    // Server-side template injection (Jinja2/Twig-style double braces)
    r"\{\{[0-9]{1,2}\*[0-9]{1,2}\}\}",
    // Server-side template injection (Freemarker/JSP EL-style dollar braces)
    r"\$\{[0-9]{1,2}\*[0-9]{1,2}\}",
    // OS command injection
    r"(;|\||&&) ?(id|whoami|sleep [0-9]{1,2}|cat /etc/passwd)",
    // NoSQL (MongoDB-style) injection
    r#"\{"\$(ne|gt|regex)":(null|""|"\.\*")\}"#,
    // LDAP injection
    r"\*\)\(\|?(uid|cn)=\*",
    // Format string vulnerability
    r"%(s|x|n){2,10}",
    // XXE / external entity injection
    r#"<!ENTITY xxe SYSTEM "(file:///etc/passwd|http://[a-z]{3,8}\.[a-z]{2,3})">"#,
];

/// Maximum number of repetitions for unbounded quantifiers in the grammars
/// above (there are none currently, but this bounds any accidentally added).
const MAX_REPEAT: u32 = 10;

/// The mutator that generates a payload from a randomly chosen entry in
/// [`INTERESTING_GRAMMARS`], and sets it as the parameter value.
pub struct GrammarInterestingMutator {
    grammars: Vec<rand_regex::Regex>,
}

impl GrammarInterestingMutator {
    /// Create a new `GrammarInterestingMutator`, precompiling all grammars.
    #[must_use]
    pub fn new() -> Self {
        let grammars = INTERESTING_GRAMMARS
            .iter()
            .filter_map(
                |pattern| match rand_regex::Regex::compile(pattern, MAX_REPEAT) {
                    Ok(regex) => Some(regex),
                    Err(err) => {
                        log::warn!("Broken interesting grammar {pattern}, Error message: {err}");
                        None
                    }
                },
            )
            .collect();
        Self { grammars }
    }
}

impl Default for GrammarInterestingMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for GrammarInterestingMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("GrammarInterestingMutator")
    }
}

impl<S> Mutator<BytesInput, S> for GrammarInterestingMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        if self.grammars.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let grammar = state.rand_mut().choose(&self.grammars).unwrap();
        let value: String = grammar.sample(&mut rand::rng());
        input.resize(0, 0);
        input.extend(value.as_bytes());
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use libafl::inputs::HasMutatorBytes;
    use libafl_bolts::rands::StdRand;

    use super::*;

    /// A minimal `HasRand` implementation to drive the mutator in tests.
    struct DummyState {
        rand: StdRand,
    }

    impl HasRand for DummyState {
        type Rand = StdRand;

        fn rand(&self) -> &Self::Rand {
            &self.rand
        }

        fn rand_mut(&mut self) -> &mut Self::Rand {
            &mut self.rand
        }
    }

    #[test]
    fn all_grammars_compile() {
        let mutator = GrammarInterestingMutator::new();
        assert_eq!(mutator.grammars.len(), INTERESTING_GRAMMARS.len());
    }

    #[test]
    fn mutate_produces_non_empty_output() {
        let mut mutator = GrammarInterestingMutator::new();
        let mut state = DummyState {
            rand: StdRand::with_seed(42),
        };
        let mut input = BytesInput::from(Vec::new());
        let result = mutator.mutate(&mut state, &mut input).unwrap();
        assert_eq!(result, MutationResult::Mutated);
        assert!(!input.mutator_bytes().is_empty());
    }
}
