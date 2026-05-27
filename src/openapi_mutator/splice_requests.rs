//! Mutates a request series by splicing two sequences together.
//!
//! Inspired by the byte-level `SpliceMutator` in LibAFL, but adapted for request
//! sequences with independent cut points: one cut in the current input and one cut
//! in a randomly-selected corpus input. The prefix of the current input is kept and
//! the suffix of the corpus input is appended, enabling broader recombination even
//! when two sequences have little semantic overlap.

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
/// together. It picks one split point in the current input and one split point in
/// a randomly-chosen corpus entry, then keeps the current prefix and appends the
/// corpus suffix.
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
        // If we hit the current entry, move to the next corpus slot deterministically.
        let current_id = state.current_corpus_id()?;
        let rand_idx = state.rand_mut().below(NonZero::new(corpus_count).unwrap());
        let mut other_idx = rand_idx;
        let mut other_id = state.corpus().nth(other_idx);
        if Some(other_id) == current_id {
            other_idx = (other_idx + 1) % corpus_count;
            other_id = state.corpus().nth(other_idx);
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
        if cur_len < 2 || other_len < 2 {
            return Ok(MutationResult::Skipped);
        }

        // Choose split points in [1, cur_len) and [1, other_len).
        let split_cur = 1 + state.rand_mut().below(NonZero::new(cur_len - 1).unwrap());
        let split_other = 1 + state.rand_mut().below(NonZero::new(other_len - 1).unwrap());

        // Clone the tail of the other input (from `split_other` to its end).
        // We do this in its own scope so the borrow on the corpus entry is
        // released before we modify `input`.
        let other_tail: Vec<_> = {
            let other_testcase = state.corpus().get(other_id)?.borrow();
            let other = other_testcase
                .input()
                .as_ref()
                .expect("input was loaded above");
            other.0[split_other..].to_vec()
        };

        // Replace the tail of the current input.
        input.0.truncate(split_cur);
        input.0.extend(other_tail);

        // Fix up references.
        // - For references in the spliced-in suffix:
        //   - If they point into the removed donor prefix (< split_other), break them.
        //   - If they point into the kept donor suffix (>= split_other), remap them
        //     to the new indices in the recombined sequence.
        // - Everywhere, enforce no-forward-reference invariant.
        for (appears_in, param) in input.parameter_filter(&|v| v.is_reference()) {
            if appears_in >= split_cur {
                let reference_index = param
                    .reference_index()
                    .expect("filtered by parameter_filter");

                if *reference_index < split_other {
                    // The target was in the removed donor prefix.
                    param.break_reference_if_target(state.rand_mut(), |_| true);
                    continue;
                }

                // The target was in the kept donor suffix.
                // Map donor index -> recombined index.
                *reference_index = *reference_index - split_other + split_cur;
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
        input::{
            Method, OpenApiInput, OpenApiRequest, ParameterContents,
            parameter::{OReference, ParameterKind},
        },
        openapi_mutator::test_helpers::{linked_requests, simple_request},
        parameter_access::{ParameterAccess, ParameterAccessElements},
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

    // Donor with 4 requests where request 2 references request 1.
    // When split_other == 1, both requests are in donor tail and the reference
    // should be remapped and preserved in the recombined input.
    fn donor_with_tail_internal_reference() -> OpenApiInput {
        let base = simple_request().0[0].clone();

        let req0 = OpenApiRequest {
            method: Method::Get,
            path: "/d0".to_string(),
            body: base.body.clone(),
            parameters: base.parameters.clone(),
        };
        let req1 = OpenApiRequest {
            method: Method::Get,
            path: "/d1".to_string(),
            body: base.body.clone(),
            parameters: base.parameters.clone(),
        };
        let mut req2 = OpenApiRequest {
            method: Method::Get,
            path: "/d2".to_string(),
            body: base.body.clone(),
            parameters: base.parameters.clone(),
        };
        req2.parameters.insert(
            (
                "id".to_string(),
                crate::input::parameter::ParameterKind::Query,
            ),
            ParameterContents::OReference(OReference {
                request_index: 1,
                parameter_access: ParameterAccess::request_body(
                    ParameterAccessElements::from_elements(&["id".to_string().into()]),
                ),
            }),
        );
        let req3 = OpenApiRequest {
            method: Method::Get,
            path: "/d3".to_string(),
            body: base.body,
            parameters: base.parameters,
        };

        OpenApiInput(vec![req0, req1, req2, req3])
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

    /// Splicing two 3-request sequences with independent cuts can produce length
    /// 2, 3, or 4.
    #[test]
    fn splice_produces_correct_length() -> anyhow::Result<()> {
        for _ in 0..50 {
            let mut state = SpliceTestState::new();
            let other = three_requests(); // length 3
            state.add(other);
            let cur_id = state.add(three_requests());
            state.set_current(cur_id);

            let mut input = three_requests();
            let result = SpliceRequestsMutator::new().mutate(&mut state, &mut input)?;

            // split_cur and split_other are independently chosen in [1, 3).
            // Therefore resulting length is split_cur + (3 - split_other) in {2,3,4}.
            if result == MutationResult::Skipped {
                continue;
            }
            assert!(
                (2..=4).contains(&input.0.len()),
                "spliced length should be in [2,4], got {}",
                input.0.len()
            );
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

    /// Tail references that point inside the retained donor tail should be
    /// remapped, not always broken.
    #[test]
    fn splice_remaps_tail_internal_reference() -> anyhow::Result<()> {
        let mut seen_mutation = false;
        let mut seen_preserved_reference = false;

        for _ in 0..300 {
            let mut state = SpliceTestState::new();
            state.add(donor_with_tail_internal_reference());
            let cur_id = state.add(three_requests());
            state.set_current(cur_id);

            let mut input = three_requests();
            let result = SpliceRequestsMutator::new().mutate(&mut state, &mut input)?;
            if result == MutationResult::Skipped {
                continue;
            }
            seen_mutation = true;

            // If donor request "/d2" ended up in the recombined suffix and still
            // has an OReference, it should point backward in the recombined input.
            if let Some((idx, req)) = input.0.iter().enumerate().find(|(_, r)| r.path == "/d2") {
                if let Some(param) = req
                    .parameters
                    .get(&("id".to_string(), ParameterKind::Query))
                {
                    if let ParameterContents::OReference(reference) = param {
                        let target = reference.request_index;
                        assert!(target < idx, "remapped tail reference must point backward");
                        seen_preserved_reference = true;
                        break;
                    }
                }
            }
        }

        assert!(seen_mutation, "expected at least one mutation in test loop");
        assert!(
            seen_preserved_reference,
            "expected to observe a preserved+remapped tail reference at least once"
        );
        Ok(())
    }

    /// With independent split points, even identical inputs can produce different
    /// outputs due to different cut locations. The mutator should still return a
    /// valid result and keep at least one request.
    #[test]
    fn splice_of_identical_inputs_remains_valid() -> anyhow::Result<()> {
        for _ in 0..20 {
            let mut state = SpliceTestState::new();
            let original = three_requests();
            state.add(original.clone());
            let cur_id = state.add(original.clone());
            state.set_current(cur_id);

            let mut input = original.clone();
            let result = SpliceRequestsMutator::new().mutate(&mut state, &mut input)?;

            if result == MutationResult::Skipped {
                continue;
            }
            assert!(!input.0.is_empty());
            assert!(input.0.len() <= original.0.len() + 1);
        }
        Ok(())
    }

    /// With independent split points and lengths 3 (current) and 2 (other), the
    /// result length can be either 2 or 3.
    #[test]
    fn splice_output_length_varies_with_two_cuts() -> anyhow::Result<()> {
        for _ in 0..30 {
            let mut state = SpliceTestState::new();

            // Corpus entry A: length 2 (short, but long enough for a split)
            let mut short = simple_request();
            short.0.push(short.0[0].clone());
            let short_len = short.0.len(); // 2
            state.add(short);

            // Corpus entry B: length 3
            let cur_id = state.add(three_requests()); // length 3
            state.set_current(cur_id);

            // Input under mutation: length 3
            let mut input = three_requests();
            let result = SpliceRequestsMutator::new().mutate(&mut state, &mut input)?;

            if result == MutationResult::Skipped {
                continue;
            }
            assert!(
                input.0.len() == short_len || input.0.len() == 3,
                "unexpected length {} for independent two-cut splice",
                input.0.len()
            );
        }
        Ok(())
    }
}
