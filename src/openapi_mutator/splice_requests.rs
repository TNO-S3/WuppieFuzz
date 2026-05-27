//! Mutates a request series by splicing two sequences together.
//!
//! Inspired by the byte-level `SpliceMutator` in LibAFL: a split point is chosen
//! within the overlap of two request sequences, and the tail of a randomly-selected
//! corpus entry replaces the tail of the current input.

use core::num::NonZero;
use std::borrow::Cow;

use libafl::{
    Error,
    corpus::{Corpus, CorpusId, HasCurrentCorpusId},
    mutators::{MutationResult, Mutator},
    state::{HasCorpus, HasRand},
};
use libafl_bolts::{Named, rands::Rand};

use crate::input::OpenApiInput;

/// The `SpliceRequestsMutator` splices two request sequences from the corpus
/// together. It picks a random split point within the overlap of the current
/// input and a randomly-chosen corpus entry, then replaces the tail of the
/// current input with the tail of the corpus entry starting at that split point.
pub struct SpliceRequestsMutator;

impl SpliceRequestsMutator {
    #[must_use]
    /// Creates a new `SpliceRequestsMutator`.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for SpliceRequestsMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for SpliceRequestsMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("splicerequestsmutator")
    }
}

impl<S> Mutator<OpenApiInput, S> for SpliceRequestsMutator
where
    S: HasRand + HasCorpus<OpenApiInput> + HasCurrentCorpusId,
{
    fn mutate(&mut self, state: &mut S, input: &mut OpenApiInput) -> Result<MutationResult, Error> {
        let corpus_count = state.corpus().count();
        if corpus_count < 2 {
            return Ok(MutationResult::Skipped);
        }

        // Pick a random corpus entry that is not the current one.
        let current_id = state.current_corpus_id()?;
        let rand_idx = state.rand_mut().below(NonZero::new(corpus_count).unwrap());
        let mut other_id = state.corpus().nth(rand_idx);
        let mut attempts = 0;
        while Some(other_id) == current_id && attempts < 8 {
            let rand_idx = state.rand_mut().below(NonZero::new(corpus_count).unwrap());
            other_id = state.corpus().nth(rand_idx);
            attempts += 1;
        }
        if Some(other_id) == current_id {
            return Ok(MutationResult::Skipped);
        }

        // Determine the length of the other input without holding onto a borrow.
        let other_len = {
            let mut other_testcase = state.corpus().get(other_id)?.borrow_mut();
            other_testcase.load_input(state.corpus())?.0.len()
        };

        let cur_len = input.0.len();
        // The overlap region is [0, min_len). We need at least 2 requests in the
        // overlap so that there is a meaningful split point at index 1.
        let min_len = cur_len.min(other_len);
        if min_len < 2 {
            return Ok(MutationResult::Skipped);
        }

        // Choose split point in [1, min_len).
        let split_at = 1 + state.rand_mut().below(NonZero::new(min_len - 1).unwrap());

        // Clone the tail of the other input. We do this in its own scope so the
        // borrow on the corpus entry is released before we modify `input`.
        let other_tail: Vec<_> = {
            let other_testcase = state.corpus().get(other_id)?.borrow();
            let other = other_testcase
                .input()
                .as_ref()
                .expect("input was loaded above");
            other.0[split_at..].to_vec()
        };

        // Replace the tail of the current input.
        input.0.truncate(split_at);
        input.0.extend(other_tail);

        // Fix up references. Any reference in the spliced-in tail (indices >= split_at)
        // that points to a request index >= split_at is now stale — those request
        // indices come from a different sequence that is no longer present.
        // Additionally, as always, forward references must be broken everywhere.
        for (appears_in, param) in input.parameter_filter(&|v| v.is_reference()) {
            if appears_in >= split_at {
                let reference_index = param
                    .reference_index()
                    .expect("filtered by parameter_filter");
                if *reference_index >= split_at {
                    // This reference points into the (now replaced) old tail; break it.
                    param.break_reference_if_target(state.rand_mut(), |_| true);
                    continue;
                }
            }
            // Enforce the invariant that references never point to future requests.
            param.break_reference_if_target(state.rand_mut(), |refers_to| refers_to >= appears_in);
        }

        input.assert_valid(self.name());
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use libafl::{
        corpus::{Corpus, CorpusId, HasCurrentCorpusId, InMemoryCorpus, Testcase},
        mutators::{MutationResult, Mutator},
        state::{HasCorpus, HasRand},
    };
    use libafl_bolts::rands::StdRand;

    use super::SpliceRequestsMutator;
    use crate::{
        input::{Method, OpenApiInput},
        openapi_mutator::test_helpers::{linked_requests, simple_request},
        state::tests::TestOpenApiFuzzerState,
    };

    // ---------------------------------------------------------------------------
    // A minimal test state that adds a corpus and current-corpus-id on top of the
    // existing `TestOpenApiFuzzerState`.
    // ---------------------------------------------------------------------------
    struct SpliceTestState {
        inner: TestOpenApiFuzzerState,
        corpus: InMemoryCorpus<OpenApiInput>,
        current_corpus_id: Option<CorpusId>,
    }

    impl SpliceTestState {
        fn new() -> Self {
            Self {
                inner: TestOpenApiFuzzerState::new(),
                corpus: InMemoryCorpus::new(),
                current_corpus_id: None,
            }
        }

        /// Add an input to the corpus and return its id.
        fn add(&mut self, input: OpenApiInput) -> CorpusId {
            self.corpus
                .add(Testcase::new(input))
                .expect("failed to add to corpus")
        }

        /// Set which corpus entry is the "current" one being mutated.
        fn set_current(&mut self, id: CorpusId) {
            self.current_corpus_id = Some(id);
        }
    }

    impl HasRand for SpliceTestState {
        type Rand = StdRand;

        fn rand(&self) -> &Self::Rand {
            self.inner.rand()
        }

        fn rand_mut(&mut self) -> &mut Self::Rand {
            self.inner.rand_mut()
        }
    }

    impl HasCorpus<OpenApiInput> for SpliceTestState {
        type Corpus = InMemoryCorpus<OpenApiInput>;

        fn corpus(&self) -> &Self::Corpus {
            &self.corpus
        }

        fn corpus_mut(&mut self) -> &mut Self::Corpus {
            &mut self.corpus
        }
    }

    impl HasCurrentCorpusId for SpliceTestState {
        fn set_corpus_id(&mut self, id: CorpusId) -> Result<(), libafl::Error> {
            self.current_corpus_id = Some(id);
            Ok(())
        }

        fn clear_corpus_id(&mut self) -> Result<(), libafl::Error> {
            self.current_corpus_id = None;
            Ok(())
        }

        fn current_corpus_id(&self) -> Result<Option<CorpusId>, libafl::Error> {
            Ok(self.current_corpus_id)
        }
    }

    // ---------------------------------------------------------------------------
    // Helper: build a 3-request input by duplicating the first request twice
    // ---------------------------------------------------------------------------
    fn three_requests() -> OpenApiInput {
        let mut input = simple_request();
        input.0.push(input.0[0].clone());
        input.0[1].method = Method::Delete;
        input.0.push(input.0[0].clone());
        input
    }

    // ---------------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------------

    /// When the corpus has only one entry and that entry is the current one,
    /// the mutator must skip.
    #[test]
    fn skips_when_only_one_corpus_entry() -> anyhow::Result<()> {
        let mut state = SpliceTestState::new();
        let id = state.add(simple_request());
        state.set_current(id);

        let mut input = simple_request();
        let result = SpliceRequestsMutator::new().mutate(&mut state, &mut input)?;
        assert_eq!(result, MutationResult::Skipped);
        Ok(())
    }

    /// When both inputs have fewer than 2 requests in their overlap, splice must
    /// skip because there is no valid split point.
    #[test]
    fn skips_when_overlap_too_short() -> anyhow::Result<()> {
        let mut state = SpliceTestState::new();
        // Corpus entry: 1 request
        state.add(simple_request());
        let id2 = state.add(simple_request());
        state.set_current(id2);

        // Input under mutation: also 1 request → overlap is 1, no valid split
        let mut input = simple_request();
        let result = SpliceRequestsMutator::new().mutate(&mut state, &mut input)?;
        assert_eq!(result, MutationResult::Skipped);
        Ok(())
    }

    /// Splicing two 3-request sequences must produce an output whose length is
    /// exactly 3 (head from current + tail from other, split somewhere in [1,3)).
    #[test]
    fn splice_produces_correct_length() -> anyhow::Result<()> {
        for _ in 0..50 {
            let mut state = SpliceTestState::new();
            let other = three_requests();
            state.add(other);
            let cur_id = state.add(three_requests());
            state.set_current(cur_id);

            let mut input = three_requests();
            let result = SpliceRequestsMutator::new().mutate(&mut state, &mut input)?;

            // The split is somewhere in [1, 3), so the total length stays at 3.
            assert_eq!(result, MutationResult::Mutated);
            assert_eq!(input.0.len(), 3, "spliced length should equal min_len (3)");
        }
        Ok(())
    }

    /// After splicing, all references in the result must be valid (no forward
    /// references, no stale cross-sequence references).
    #[test]
    fn splice_breaks_invalid_references() -> anyhow::Result<()> {
        for _ in 0..50 {
            let mut state = SpliceTestState::new();
            // Use linked_requests (2 requests, second references the first)
            // as both corpus entry and input under mutation.
            state.add(linked_requests());
            let cur_id = state.add(linked_requests());
            state.set_current(cur_id);

            let mut input = linked_requests();
            let result = SpliceRequestsMutator::new().mutate(&mut state, &mut input)?;

            if result == MutationResult::Skipped {
                // Possible if corpus_count < 2 or no valid split — not expected here
                // but accept it if it happens
                continue;
            }

            // Validate: no parameter should still be a forward reference or a
            // stale reference pointing past its position.
            for (appears_in, param) in input.parameter_filter(&|v| v.is_reference()) {
                let refers_to = *param.reference_index().unwrap();
                assert!(
                    refers_to < appears_in,
                    "request {appears_in} holds a reference to {refers_to}, which is a forward reference"
                );
            }
        }
        Ok(())
    }

    /// If the two sequences are identical, the result—regardless of split—must
    /// be identical to the original (same method at each position).
    #[test]
    fn splice_of_identical_inputs_is_identity() -> anyhow::Result<()> {
        for _ in 0..20 {
            let mut state = SpliceTestState::new();
            let original = three_requests();
            state.add(original.clone());
            let cur_id = state.add(original.clone());
            state.set_current(cur_id);

            let mut input = original.clone();
            let result = SpliceRequestsMutator::new().mutate(&mut state, &mut input)?;

            assert_eq!(result, MutationResult::Mutated);
            // Content must be unchanged because both halves come from identical sequences.
            for (i, (a, b)) in input.0.iter().zip(original.0.iter()).enumerate() {
                assert_eq!(
                    a.method, b.method,
                    "request {i} method changed after splicing identical inputs"
                );
                assert_eq!(
                    a.path, b.path,
                    "request {i} path changed after splicing identical inputs"
                );
            }
        }
        Ok(())
    }

    /// When one sequence is longer than the other, the result must have exactly
    /// `min_len` entries (the overlap length).
    #[test]
    fn splice_respects_min_len_when_lengths_differ() -> anyhow::Result<()> {
        for _ in 0..30 {
            let mut state = SpliceTestState::new();
            let short = simple_request(); // length 1 — still too short for a split
            state.add(short.clone());
            // Make short 2 requests so overlap is valid
            let mut short2 = short.clone();
            short2.0.push(short.0[0].clone());
            let short2_len = short2.0.len(); // 2
            state.add(short2);

            let cur_id = state.add(three_requests()); // length 3
            state.set_current(cur_id);

            let mut input = three_requests(); // length 3
            let result = SpliceRequestsMutator::new().mutate(&mut state, &mut input)?;

            if result == MutationResult::Skipped {
                continue;
            }
            // The chosen other could be either length-1 or length-2.
            // Acceptable output lengths are 3 (overlap with 3-request entry)
            // or 2 (overlap with 2-request entry).
            let len = input.0.len();
            assert!(
                len == 3 || len == short2_len,
                "unexpected length {len} after splicing"
            );
        }
        Ok(())
    }
}
