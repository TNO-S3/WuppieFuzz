//! Mutates a request series by swapping two requests.

use std::borrow::Cow;

pub use libafl::mutators::mutations::*;
use libafl::{
    Error,
    mutators::{MutationResult, Mutator},
    state::HasRand,
};
use libafl_bolts::{Named, rands::Rand};

use crate::input::OpenApiInput;

/// The `SwapRequestsMutator` swaps two requests in the series.
pub struct SwapRequestsMutator;

impl SwapRequestsMutator {
    #[must_use]
    /// Creates a new SwapRequestsMutator
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for SwapRequestsMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for SwapRequestsMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("swaprequestsmutator")
    }
}

impl<S> Mutator<OpenApiInput, S> for SwapRequestsMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut OpenApiInput) -> Result<MutationResult, Error> {
        if input.0.len() < 2 {
            return Ok(MutationResult::Skipped);
        }
        let random_index1 = state
            .rand_mut()
            .below(core::num::NonZero::new(input.0.len()).unwrap());
        let mut random_index2 = random_index1;
        while random_index2 == random_index1 {
            random_index2 = state
                .rand_mut()
                .below(core::num::NonZero::new(input.0.len()).unwrap());
        }
        input.0.swap(random_index1, random_index2);

        // Don't forget to fix up the `ParameterContents::Reference`s contained in the
        // input requests!
        for (appears_in, param) in input.parameter_filter(&|v| v.is_reference()) {
            // Swap reference targets if they refer to our swapped requests
            let reference_index = param
                .reference_index()
                .expect("filtered by parameter_filter");
            if *reference_index == random_index1 {
                *reference_index = random_index2
            } else if *reference_index == random_index2 {
                *reference_index = random_index1
            }
            // If this results in references to future requests, break them
            param.break_reference_if_target(state.rand_mut(), |refers_to| refers_to >= appears_in)
        }
        input.assert_valid(self.name());
        Ok(MutationResult::Mutated)
    }
}
