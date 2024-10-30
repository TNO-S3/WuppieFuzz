//! Mutates a request series by changing the method (GET, POST, ...) of one of the HTTP
//! requests to a random different method.

use crate::configuration::{Configuration, MethodMutationStrategy};

use crate::{
    input::{fix_input_parameters, OpenApiInput},
    openapi::find_method_indices_for_path,
    state::HasRandAndOpenAPI,
};
pub use libafl::mutators::mutations::*;
use libafl::{
    mutators::{MutationResult, Mutator},
    Error,
};
use libafl_bolts::rands::Rand;
use libafl_bolts::Named;
use std::borrow::Cow;
use std::convert::TryInto;

/// The `DifferentMethodMutator` changes an existing request from the series
/// to use a different method. Only methods available for the current path
/// in the specification are used.
pub struct DifferentMethodMutator {
    method_mutation_strategy: MethodMutationStrategy,
}

impl DifferentMethodMutator {
    #[must_use]
    /// Creates a new DifferentMethodMutator
    pub fn new() -> Self {
        Self {
            method_mutation_strategy: Configuration::must_get().method_mutation_strategy,
        }
    }
}

impl Default for DifferentMethodMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for DifferentMethodMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("differentmethodmutator")
    }
}

impl<S> Mutator<OpenApiInput, S> for DifferentMethodMutator
where
    S: HasRandAndOpenAPI,
{
    fn mutate(&mut self, state: &mut S, input: &mut OpenApiInput) -> Result<MutationResult, Error> {
        if input.0.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let (rand, api) = state.rand_mut_and_openapi();

        let random_input = rand.choose(&mut input.0).unwrap();

        let available_methods: Vec<(&str, Option<usize>)> = match self.method_mutation_strategy {
            MethodMutationStrategy::FollowSpec => {
                // Find the operations in the API with this input's path, and select one
                // with a different method than the current input's method, if available
                find_method_indices_for_path(api, &random_input.path)
                    .iter()
                    .filter(|(m, _)| random_input.method != *m)
                    .cloned()
                    .map(|item| (item.0, Some(item.1)))
                    .collect::<Vec<_>>()
            }
            MethodMutationStrategy::Common5 => vec![
                ("post", None),
                ("get", None),
                ("put", None),
                ("patch", None),
                ("delete", None),
            ],
            MethodMutationStrategy::Common7 => vec![
                ("post", None),
                ("head", None),
                ("trace", None),
                ("get", None),
                ("put", None),
                ("patch", None),
                ("delete", None),
            ],
        };

        if available_methods.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        let (new_method, http_method_idx) = rand.choose(available_methods).unwrap();
        random_input.method = new_method.try_into().unwrap_or_else(|_| {
            panic!(
                "Tried to mutate into non-existing HTTP method {}",
                new_method
            )
        });

        if self.method_mutation_strategy == MethodMutationStrategy::FollowSpec {
            let http_method_idx = http_method_idx.expect("Mutating HTTP-method following spec should give us an index for the method, but it did not. I will use the request without fixing parameters, this likely results in an invalid request from the API's perspective.");
            fix_input_parameters(state, http_method_idx, random_input);
        }

        input.fix_broken_references(state.rand_mut_and_openapi().0);
        input.assert_valid(self.name());

        Ok(MutationResult::Mutated)
    }
}
