//! Mutates a request series by adding a new request to it. The new request is taken
//! at random from the API specification.

use std::{borrow::Cow, collections::BTreeMap, convert::TryInto};

pub use libafl::mutators::mutations::*;
use libafl::{
    Error,
    corpus::CorpusId,
    mutators::{MutationResult, Mutator},
};
use libafl_bolts::{Named, rands::Rand};
use openapiv3::{OpenAPI, RequestBody};

use crate::{
    input::{
        Body, OpenApiInput, OpenApiRequest, ParameterContents, new_rand_input,
        parameter::ParameterKind,
    },
    openapi::JsonContent,
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

        let (new_path, new_method, new_op, _new_path_item) =
            api.operations().nth(new_path_i).unwrap();
        let (method, path) = (new_method.try_into().unwrap(), new_path.to_owned());

        let parameters: BTreeMap<(String, ParameterKind), ParameterContents> = new_op
            .parameters
            .iter()
            // Keep only concrete values and valid references
            .filter_map(|ref_or_param| ref_or_param.resolve(api).ok())
            // Convert to (parameter_name, parameter_kind) tuples
            .map(|param| (param.data.name.clone(), param.into()))
            .map(|name_kind| (name_kind, ParameterContents::Bytes(new_rand_input(rand))))
            .collect();
        let body_contents: Option<BTreeMap<String, ParameterContents>> = new_op
            .request_body
            .as_ref()
            .and_then(|ref_or_body| ref_or_body.resolve(api).ok())
            .map(|request_body| {
                field_names(api, request_body)
                    .unwrap_or_default()
                    .iter()
                    .map(|name| (name.clone(), ParameterContents::Bytes(new_rand_input(rand))))
                    .collect()
            });
        let body = match body_contents {
            Some(body_contents) => Body::build(api, new_op, Some(body_contents.into())),
            None => Body::Empty,
        };

        input.0.push(OpenApiRequest {
            method,
            path,
            parameters,
            body,
        });

        input.assert_valid(self.name());
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

fn field_names(api: &OpenAPI, request_body: &RequestBody) -> Option<Vec<String>> {
    match request_body
        .content
        .get_json_content()?
        .schema
        .as_ref()?
        .resolve(api)
        .kind
    {
        openapiv3::SchemaKind::Type(openapiv3::Type::Object(ref obj)) => {
            Some(obj.properties.keys().cloned().collect())
        }
        _ => None,
    }
}

#[cfg(test)]
mod test {
    use libafl::mutators::{MutationResult, Mutator};

    use crate::{input::{Method, OpenApiInput}, state::tests::TestOpenApiFuzzerState};

    use super::AddRequestMutator;

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
            assert!(input.0[0].method == Method::Get || (input.0[0].path == "/simple" && input.0[0].method == Method::Delete));
            if input.0[0].path == "/with-query-parameter" || input.0[0].path == "/with-path-parameter/{id}" {
                assert!(input.0[0].contains_parameter("id"));
            }
        }

        Ok(())
    }
}
