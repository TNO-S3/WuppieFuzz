//! Mutates a request series by duplicating an existing request.

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
        let random_index = state.rand_mut().below(input.0.len());
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
}
