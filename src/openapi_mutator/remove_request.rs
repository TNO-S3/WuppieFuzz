//! Mutates a request series by removing a random request from it, if there are more
//! than one.

use std::borrow::Cow;

use crate::input::OpenApiInput;
pub use libafl::mutators::mutations::*;
use libafl::{
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error,
};
use libafl_bolts::rands::Rand;
use libafl_bolts::Named;

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
        let random_index = state.rand_mut().below(input.0.len());
        input.0.remove(random_index);

        // Don't forget to fix up the `ParameterContents::Reference`s contained in the
        // input requests!
        for (_, param) in input.parameter_filter(&|v| v.is_reference()) {
            // We have to break any `ParameterContents::Reference`s to the removed request
            param.break_reference_if_target(state.rand_mut(), |i| i == random_index);
            // We have to decrement the reference target by one if it is larger than
            // the random_index (but param might not be a reference anymore, so check!)
            if let Some(reference_index) = param.reference_index() {
                if *reference_index > random_index {
                    *reference_index -= 1
                }
            }
        }
        input.assert_valid(self.name());
        Ok(MutationResult::Mutated)
    }
}
