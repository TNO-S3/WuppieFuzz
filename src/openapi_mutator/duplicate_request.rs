//! Mutates a request series by duplicating an existing request.

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

/// The `DuplicateRequestMutator` duplicates an existing request in the series.
pub struct DuplicateRequestMutator;

impl DuplicateRequestMutator {
    #[must_use]
    /// Creates a new DuplicateRequestMutator
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for DuplicateRequestMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for DuplicateRequestMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("duplicaterequestmutator")
    }
}

impl<S> Mutator<OpenApiInput, S> for DuplicateRequestMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut OpenApiInput) -> Result<MutationResult, Error> {
        if input.0.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let random_index = state
            .rand_mut()
            .below(core::num::NonZero::new(input.0.len()).unwrap());
        input
            .0
            .insert(random_index + 1, input.0[random_index].clone());

        // Don't forget to fix up the `ParameterContents::Reference`s contained in the
        // input requests!
        for (_, param) in input.parameter_filter(&|v| v.is_reference()) {
            // We have to increment the reference target by one if it is larger than
            // the random_index
            let reference_index = param
                .reference_index()
                .expect("filtered by parameter_filter");
            if *reference_index > random_index {
                *reference_index += 1
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
    use indexmap::IndexMap;
    use libafl::mutators::{MutationResult, Mutator};

    use super::DuplicateRequestMutator;
    use crate::{
        input::{
            parameter::ParameterKind, Body, Method, OpenApiInput, OpenApiRequest, ParameterContents,
        },
        state::tests::TestOpenApiFuzzerState,
    };

    /// Tests whether the mutator correctly skips mutation if there's no requests.
    #[test]
    fn skip_when_empty() -> anyhow::Result<()> {
        for _ in 0..100 {
            let mut state = TestOpenApiFuzzerState::new();
            let mut input = OpenApiInput(vec![]);
            let mut mutator = DuplicateRequestMutator;

            let result = mutator.mutate(&mut state, &mut input)?;
            assert_eq!(result, MutationResult::Skipped);
        }

        Ok(())
    }

    /// Tests whether the mutator correctly duplicates a "simple" request (i.e. no parameters or body).
    #[test]
    fn duplicate_request_simple() -> anyhow::Result<()> {
        for _ in 0..100 {
            let mut state = TestOpenApiFuzzerState::new();
            let request = OpenApiRequest {
                method: Method::Get,
                path: "/simple".to_string(),
                body: Body::Empty,
                parameters: IndexMap::new(),
            };

            let mut input = OpenApiInput(vec![request]);
            let mut mutator = DuplicateRequestMutator;

            let result = mutator.mutate(&mut state, &mut input)?;
            assert_eq!(result, MutationResult::Mutated);
            assert_eq!(input.0[0].path, input.0[1].path);
            assert_eq!(input.0[0].method, input.0[1].method);
            assert_eq!(
                input.0[0].body_content_type(),
                input.0[1].body_content_type()
            );
        }

        Ok(())
    }

    /// Tests whether the mutator correctly duplicates a request containing a parameter reference.
    #[test]
    fn duplicate_request_with_reference() -> anyhow::Result<()> {
        for _ in 0..100 {
            let mut state = TestOpenApiFuzzerState::new();
            let mut parameters = IndexMap::new();
            parameters.insert(
                ("id".to_string(), ParameterKind::Query),
                ParameterContents::Reference {
                    request_index: 0,
                    parameter_name: "id".to_string(),
                },
            );
            let has_param = OpenApiRequest {
                method: Method::Get,
                path: "/with-query-parameter".to_string(),
                body: Body::Empty,
                parameters,
            };

            let has_return_value = OpenApiRequest {
                method: Method::Get,
                path: "/simple".to_string(),
                body: Body::Empty,
                parameters: IndexMap::new(),
            };

            let mut input = OpenApiInput(vec![has_return_value, has_param]);
            let mut mutator = DuplicateRequestMutator;

            let result = mutator.mutate(&mut state, &mut input)?;
            assert_eq!(result, MutationResult::Mutated);
            let new_request = &mut input.0[2];
            if new_request.path == "/with-query-parameter" {
                let parameter = new_request
                    .get_mut_parameter("id", ParameterKind::Query)
                    .expect("Parameter was not correctly duplicated");
                assert!(parameter.is_reference());
                assert_eq!(parameter.reference_index().copied(), Some(0));
            }
        }

        Ok(())
    }
}
