//! Mutates a request series by removing a random request from it, if there are more
//! than one.

use std::borrow::Cow;

pub use libafl::mutators::mutations::*;
use libafl::{
    Error,
    corpus::CorpusId,
    mutators::{MutationResult, Mutator},
    state::HasRand,
};
use libafl_bolts::{Named, rands::Rand};

use crate::input::OpenApiInput;

/// The `RemoveRequestMutator` removes an existing request in the series,
/// but it will never leave a series empty.
pub struct RemoveRequestMutator;

impl RemoveRequestMutator {
    #[must_use]
    /// Creates a new RemoveRequestMutator
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for RemoveRequestMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for RemoveRequestMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("removerequestmutator")
    }
}

impl<S> Mutator<OpenApiInput, S> for RemoveRequestMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut OpenApiInput) -> Result<MutationResult, Error> {
        if input.0.len() < 2 {
            return Ok(MutationResult::Skipped);
        }
        let random_index = state
            .rand_mut()
            .below(core::num::NonZero::new(input.0.len()).unwrap());
        input.0.remove(random_index);

        // Don't forget to fix up the `ParameterContents::Reference`s contained in the
        // input requests!
        for (_, param) in input.parameter_filter(&|v| v.is_reference()) {
            // We have to break any `ParameterContents::Reference`s to the removed request
            param.break_reference_if_target(state.rand_mut(), |i| i == random_index);
            // We have to decrement the reference target by one if it is larger than
            // the random_index (but param might not be a reference anymore, so check!)
            if let Some(reference_index) = param.reference_index()
                && *reference_index > random_index
            {
                *reference_index -= 1
            }
        }
        input.assert_valid(self.name());
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use libafl::mutators::{MutationResult, Mutator};

    use super::RemoveRequestMutator;
    use crate::{
        input::{ParameterContents, parameter::ParameterKind},
        openapi_mutator::test_helpers::{linked_requests, simple_request},
        parameter_access::{ParameterAccess, ParameterAccessElements, RequestParameterAccess},
        state::tests::TestOpenApiFuzzerState,
    };

    /// Tests whether the mutator correctly removes a request from a list of 10 requests.
    #[test]
    fn remove_request() -> anyhow::Result<()> {
        for _ in 0..100 {
            let mut state = TestOpenApiFuzzerState::new();
            let mut input = simple_request();
            input.0.resize(10, input.0[0].clone());
            let mut mutator = RemoveRequestMutator;

            let result = mutator.mutate(&mut state, &mut input)?;

            assert_eq!(input.0.len(), 9);
            assert_eq!(result, MutationResult::Mutated);
        }
        Ok(())
    }

    /// Tests whether the mutator correctly keeps the request if it's the only one in the input.
    #[test]
    fn keep_single_request() -> anyhow::Result<()> {
        for _ in 0..100 {
            let mut state = TestOpenApiFuzzerState::new();
            let mut input = simple_request();
            let mut mutator = RemoveRequestMutator;

            let result = mutator.mutate(&mut state, &mut input)?;

            assert_eq!(input.0.len(), 1);
            assert_eq!(result, MutationResult::Skipped);
        }
        Ok(())
    }

    /// Tests whether the mutator correctly fixes any references that may have changed due to the removal of a request.
    #[test]
    fn fix_references_when_removing() -> anyhow::Result<()> {
        for _ in 0..100 {
            let mut state = TestOpenApiFuzzerState::new();
            let mut input = linked_requests();
            input.0.insert(0, input.0[0].clone());
            input.0[2].parameters.insert(
                ("id".into(), ParameterKind::Query),
                ParameterContents::OReference {
                    request_index: 1,
                    parameter_access: ParameterAccess::request_body(
                        ParameterAccessElements::from_elements(&["id".to_string().into()]),
                    ),
                },
            );

            let mut mutator = RemoveRequestMutator;
            let result = mutator.mutate(&mut state, &mut input)?;
            assert_eq!(result, MutationResult::Mutated);

            if input.0[1].path == "/with-query-parameter" {
                // If the first simple request was removed, we would expect a reference_index of 0.
                // But if the second simple request was removed, we would expect the parameter to have been changed to ParameterContents::Bytes.
                let parameter = input.0[1]
                    .get_mut_parameter(&RequestParameterAccess::Query("id".to_string()))
                    .expect("Could not find parameter after request removal");
                assert!(parameter.reference_index().is_none_or(|&mut idx| idx == 0));
            }
        }
        Ok(())
    }
}
