//! Mutates a request series by adding a new request to it. The new request is taken
//! at random from the API specification.

use std::borrow::Cow;

pub use libafl::mutators::mutations::*;
use libafl::{
    Error,
    corpus::CorpusId,
    mutators::{MutationResult, Mutator},
};
use libafl_bolts::{Named, rands::Rand};

use crate::{
    input::OpenApiInput,
    openapi::{QualifiedOperation, examples::example_request_for_operation},
    state::HasRandAndOpenAPI,
};

/// The `AddRequestMutator` adds a request to a random path from the specification
/// to the series of requests. The request is added at the end of the series, and
/// any parameters are filled with random bytes.
pub struct AddRequestMutator;

impl AddRequestMutator {
    #[must_use]
    /// Creates a new AddRequestMutator
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for AddRequestMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for AddRequestMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("addrequestmutator")
    }
}

impl<S> Mutator<OpenApiInput, S> for AddRequestMutator
where
    S: HasRandAndOpenAPI,
{
    fn mutate(&mut self, state: &mut S, input: &mut OpenApiInput) -> Result<MutationResult, Error> {
        let (rand, api) = state.rand_mut_and_openapi();

        let n_ops = api.operations().count();
        let new_path_i = rand.below(core::num::NonZero::new(n_ops).unwrap());

        let (new_path, new_method, new_op) = api.operations().nth(new_path_i).unwrap();
        let qualified_op = QualifiedOperation::new(new_path.to_owned(), new_method, new_op);
        let new_request = example_request_for_operation(api, qualified_op);

        input.0.push(new_request);

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

    use super::AddRequestMutator;
    use crate::{
        input::{Method, OpenApiInput},
        state::tests::TestOpenApiFuzzerState,
    };

    /// Tests whether the mutator adds a valid request (including parameters, if required for the chosen request).
    #[test]
    fn add_correct_request() -> anyhow::Result<()> {
        for _ in 0..100 {
            let mut state = TestOpenApiFuzzerState::new();
            let mut input = OpenApiInput(vec![]);
            let mut mutator = AddRequestMutator;

            let result = mutator.mutate(&mut state, &mut input)?;
            assert_eq!(result, MutationResult::Mutated);
            assert_eq!(input.0.len(), 1);
            assert!(TestOpenApiFuzzerState::PATHS.contains(&input.0[0].path.as_str()));
            assert!(
                input.0[0].method == Method::Get
                    || (input.0[0].path == "/simple" && input.0[0].method == Method::Delete)
            );
            if input.0[0].path == "/with-query-parameter"
                || input.0[0].path == "/with-path-parameter/{id}"
            {
                assert!(input.0[0].contains_parameter("id"));
            }
        }

        Ok(())
    }
}
