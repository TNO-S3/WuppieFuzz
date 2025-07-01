//! Mutates a request series by creating a link between to random requests. A link means
//! that a response value from a request is used as a parameter value in a later request.

use std::borrow::Cow;

pub use libafl::mutators::mutations::*;
use libafl::{
    Error,
    corpus::CorpusId,
    mutators::{MutationResult, Mutator},
};
use libafl_bolts::Named;

use crate::{
    input::{OpenApiInput, ParameterContents},
    state::HasRandAndOpenAPI,
};

/// The `EstablishLinkMutator` adds a connection to the series of requests.
/// A connection is a `ParameterContents::Reference` variant in a named parameter
/// or a request body.
pub struct EstablishLinkMutator;

impl EstablishLinkMutator {
    #[must_use]
    /// Creates a new EstablishLinkMutator
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for EstablishLinkMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for EstablishLinkMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("EstablishLinkMutator")
    }
}

impl<S> Mutator<OpenApiInput, S> for EstablishLinkMutator
where
    S: HasRandAndOpenAPI,
{
    fn mutate(&mut self, state: &mut S, input: &mut OpenApiInput) -> Result<MutationResult, Error> {
        let (rand, api) = state.rand_mut_and_openapi();

        // Build a list of (x, y),
        // x is the request index for which the response contains a parameter y
        // y is the parameter name
        let request_index_and_parameter_name_pairs = dbg!(input.return_values(api));
        if request_index_and_parameter_name_pairs.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        // Build a list of parameters with the same name as a return parameter from
        // an earlier request
        let concrete_parameters = input
            .0
            .iter_mut()
            .enumerate()
            // For each (enumerated) request in the series, collect its relevant
            // parameters
            .flat_map(|(current_request_index, request)| {
                let request_index_and_parameter_name_pairs =
                    &request_index_and_parameter_name_pairs; // allow the move|| later on
                request
                    .parameters
                    .iter_mut()
                    // only consider non-reference parameters for replacement with
                    // a reference
                    .filter(|(_, v)| !v.is_reference())
                    // filter: this variable occurs in an earlier request's return value
                    // maps to: (&mut param, the relevant index into return_values)
                    .filter_map(move |((name, _), param)| {
                        request_index_and_parameter_name_pairs
                            .iter()
                            // Find the first request index that had the desired parameter name in a response
                            .position(|(request_index, rv_name)| {
                                *request_index < current_request_index && name == rv_name
                            })
                            .map(|index_return_values| (param, index_return_values))
                    })
            });

        let random_link = match super::choose(rand, concrete_parameters) {
            Some(element) => element,
            None => return Ok(MutationResult::Skipped),
        };

        // Make the link
        *random_link.0 = ParameterContents::Reference {
            request_index: request_index_and_parameter_name_pairs[random_link.1].0,
            parameter_name: request_index_and_parameter_name_pairs[random_link.1]
                .1
                .to_owned(),
        };

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

    use super::EstablishLinkMutator;
    use crate::{
        input::{
            parameter::ParameterKind, Body, Method, OpenApiInput, OpenApiRequest, ParameterContents,
        },
        state::tests::TestOpenApiFuzzerState,
    };

    /// Tests whether the mutator correctly a link between an earlier request (to /simple) and a later parameter (id).
    #[test]
    fn establish_link() -> anyhow::Result<()> {
        for _ in 0..100 {
            let mut state = TestOpenApiFuzzerState::new();
            let mut parameters = IndexMap::new();
            parameters.insert(
                ("id".to_string(), ParameterKind::Query),
                ParameterContents::Bytes(vec![0x0, 0x1, 0x2]),
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
            let mut mutator = EstablishLinkMutator;

            let result = mutator.mutate(&mut state, &mut input)?;
            assert_eq!(result, MutationResult::Mutated);
            let parameter = input.0[1]
                .get_mut_parameter("id", ParameterKind::Query)
                .expect("Request got the wrong parameter");
            assert!(parameter.is_reference());
            assert_eq!(parameter.reference_index().copied(), Some(0));
        }

        Ok(())
    }

    /// Tests whether the mutator correctly skips mutation in cases where no link can be established.
    #[test]
    fn skip_establish_link() -> anyhow::Result<()> {
        for _ in 0..100 {
            // In this case, the mutator should skip mutation because the parameters are in the wrong order
            let mut state = TestOpenApiFuzzerState::new();
            let mut parameters = IndexMap::new();
            parameters.insert(
                ("id".to_string(), ParameterKind::Query),
                ParameterContents::Bytes(vec![0x0, 0x1, 0x2]),
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

            let mut input = OpenApiInput(vec![has_param, has_return_value]);
            let mut mutator = EstablishLinkMutator;

            let result = mutator.mutate(&mut state, &mut input)?;
            assert_eq!(result, MutationResult::Skipped);

            // In this case, the mutator should skip mutation because has_return_value has the wrong method
            let mut state = TestOpenApiFuzzerState::new();
            let has_param = OpenApiRequest {
                method: Method::Get,
                path: "/with-query-parameter".to_string(),
                body: Body::Empty,
                parameters: IndexMap::new(),
            };

            let has_return_value = OpenApiRequest {
                method: Method::Delete,
                path: "/simple".to_string(),
                body: Body::Empty,
                parameters: IndexMap::new(),
            };

            let mut input = OpenApiInput(vec![has_return_value, has_param]);
            let mut mutator = EstablishLinkMutator;

            let result = mutator.mutate(&mut state, &mut input)?;
            assert_eq!(result, MutationResult::Skipped);
        }

        Ok(())
    }
}
