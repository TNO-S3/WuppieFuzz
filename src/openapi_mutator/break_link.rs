//! Mutates a request series by breaking a random link between requests. A link is a reference
//! in a request parameter to a value that should be in the response to an earlier request.
//! The link is replaced by a randomly generated static value.

use std::borrow::Cow;

pub use libafl::mutators::mutations::*;
use libafl::{
    Error,
    mutators::{MutationResult, Mutator},
    state::HasRand,
};
use libafl_bolts::Named;

use crate::input::OpenApiInput;

/// The `BreakConnectionMutator` removes a connection from the series of
/// requests. A connection is a `ParameterContents::Reference` variant in a
/// named parameter or a request body. The replacement is random binary
/// nonsense.
pub struct BreakLinkMutator;

impl BreakLinkMutator {
    #[must_use]
    /// Creates a new BreakLinkMutator
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for BreakLinkMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for BreakLinkMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("breaklinkmutator")
    }
}

impl<S> Mutator<OpenApiInput, S> for BreakLinkMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut OpenApiInput) -> Result<MutationResult, Error> {
        let reference_parameters = input
            .parameter_filter(&|v| v.is_reference())
            .map(|(_, v)| v);

        let random_param = match super::choose(state.rand_mut(), reference_parameters) {
            Some(parameter) => parameter,
            None => return Ok(MutationResult::Skipped),
        };
        random_param.break_reference_if_target(state.rand_mut(), |_| true);

        input.assert_valid(self.name());
        Ok(MutationResult::Mutated)
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _new_corpus_id: Option<libafl::corpus::CorpusId>,
    ) -> Result<(), Error> {
        Ok(())
    }
}
