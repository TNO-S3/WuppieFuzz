//! Mutates a request series by changing the path and method on one of the HTTP requests.
//! The new path and method are taken from the API specification.

use std::{borrow::Cow, convert::TryInto};

pub use libafl::mutators::mutations::*;
use libafl::{
    Error,
    mutators::{MutationResult, Mutator},
};
use libafl_bolts::{Named, rands::Rand};

use crate::{
    input::{OpenApiInput, fix_input_parameters},
    state::HasRandAndOpenAPI,
};

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
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("differentpathmutator")
    }
}

impl<S> Mutator<OpenApiInput, S> for DifferentPathMutator
where
    S: HasRandAndOpenAPI,
{
    fn mutate(&mut self, state: &mut S, input: &mut OpenApiInput) -> Result<MutationResult, Error> {
        let (rand, api) = state.rand_mut_and_openapi();
        if input.0.is_empty() || api.operations().count() < 2 {
            return Ok(MutationResult::Skipped);
        }
        let random_input = rand.choose(&mut input.0).unwrap();
        for _ in 0..100 {
            let n_ops = api.operations().count();
            let new_path_i = rand.below(core::num::NonZero::new(n_ops).unwrap());
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
                        "Picked unsupported HTTP method {new_method} from the OpenAPI specification"
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
