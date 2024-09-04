//! Mutates a request series by changing the path and method on one of the HTTP requests.
//! The new path and method are taken from the API specification.

use crate::{input::fix_input_parameters, input::OpenApiInput, state::HasRandAndOpenAPI};
pub use libafl::mutators::mutations::*;
use libafl::{
    mutators::{MutationResult, Mutator},
    Error,
};
use libafl_bolts::rands::Rand;
use libafl_bolts::Named;
use std::convert::TryInto;

/// The `DifferentPathMutator` changes an existing request from the series
/// to use a different path-plus-method-combination. Only combinations available
/// in the specification are used.
pub struct DifferentPathMutator;

impl DifferentPathMutator {
    #[must_use]
    /// Creates a new DifferentPathMutator
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for DifferentPathMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for DifferentPathMutator {
    fn name(&self) -> &str {
        "differentpathmutator"
    }
}

impl<S> Mutator<OpenApiInput, S> for DifferentPathMutator
where
    S: HasRandAndOpenAPI,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut OpenApiInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let (rand, api) = state.rand_mut_and_openapi();
        if input.0.is_empty() || api.operations().count() < 2 {
            return Ok(MutationResult::Skipped);
        }
        let random_input = rand.choose(&mut input.0);
        for _ in 0..100 {
            let n_ops = api.operations().count() as u64;
            let new_path_i = rand.below(n_ops) as usize;
            {
                let (new_path, new_method, _, _) = api.operations().nth(new_path_i).unwrap();
                // Only set "mutated" if it's actually different
                if new_path.eq_ignore_ascii_case(&random_input.path)
                    && new_method == random_input.method
                {
                    continue;
                }
                random_input.method = new_method.try_into().unwrap_or_else(|_| {
                    panic!(
                        "Picked unsupported HTTP method {} from the OpenAPI specification",
                        new_method
                    )
                });
                new_path.clone_into(&mut random_input.path);
            }
            fix_input_parameters(state, new_path_i, random_input);
            input.fix_broken_references(state.rand_mut_and_openapi().0);
            input.assert_valid(self.name());
            return Ok(MutationResult::Mutated);
        }
        // We didn't find a different operation - might happen in weird cases where the spec
        // contains two identical paths. Still, it's best not to hang.
        Ok(MutationResult::Skipped)
    }
}
