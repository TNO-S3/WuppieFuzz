//! A LibAFL mutator that acts on HTTP request chains.
//!
//! This module contains various mutators that are designed to act on chains of HTTP requests.
//! There are some mutators that act at the chain level, and remove requests from the chain or
//! reorder them, for instance. And there are other mutators that act on the contents of a
//! request, changing the parameter values (using a LibAFL byte sequence mutator, for example).

use core::num::NonZero;
use std::borrow::Cow;

use crate::input::parameter::SimpleValue;
use crate::input::{new_rand_input, OpenApiInput, ParameterContents};
use crate::state::OpenApiFuzzerState;
use libafl::corpus::Corpus;
use libafl::inputs::Input;
pub use libafl::mutators::mutations::*;
use libafl::{
    inputs::{BytesInput, HasMutatorBytes},
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error,
};
use libafl_bolts::rands::Rand;
use libafl_bolts::tuples::{tuple_list, tuple_list_type};
use libafl_bolts::Named;

pub mod add_request;
use add_request::AddRequestMutator;
pub mod different_path;
use different_path::DifferentPathMutator;
pub mod different_method;
use different_method::DifferentMethodMutator;
pub mod duplicate_request;
use duplicate_request::DuplicateRequestMutator;
pub mod swap_requests;
use swap_requests::SwapRequestsMutator;
pub mod remove_request;
use remove_request::RemoveRequestMutator;
pub mod break_link;
use break_link::BreakLinkMutator;
pub mod establish_link;
use establish_link::EstablishLinkMutator;
pub mod string_interesting;
use string_interesting::StringInterestingMutator;

/// Creates a tuple list containing all available mutators from this module.
pub fn havoc_mutations_openapi<C, I, R, SC>() -> tuple_list_type!(
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
    OpenApiMutator<OpenApiFuzzerState<I, C, R, SC>>,
)
where
    C: Corpus + 'static,
    I: Input + 'static,
    R: Rand + 'static,
    SC: Corpus + 'static,
{
    tuple_list!(
        OpenApiMutator::from_bytes_mutator(Box::new(BitFlipMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(ByteAddMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(ByteDecMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(ByteFlipMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(ByteIncMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(ByteInterestingMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(ByteNegMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(ByteRandMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(BytesCopyMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(BytesDeleteMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(BytesExpandMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(BytesInsertCopyMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(BytesInsertMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(BytesRandInsertMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(BytesRandSetMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(BytesSetMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(BytesSwapMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(DwordAddMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(DwordInterestingMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(QwordAddMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(StringInterestingMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(WordAddMutator::new())),
        OpenApiMutator::from_bytes_mutator(Box::new(WordInterestingMutator::new())),
        OpenApiMutator::from_series_mutator(Box::new(AddRequestMutator::new())),
        OpenApiMutator::from_series_mutator(Box::new(DifferentPathMutator::new())),
        OpenApiMutator::from_series_mutator(Box::new(DifferentMethodMutator::new())),
        OpenApiMutator::from_series_mutator(Box::new(DuplicateRequestMutator::new())),
        OpenApiMutator::from_series_mutator(Box::new(SwapRequestsMutator::new())),
        OpenApiMutator::from_series_mutator(Box::new(RemoveRequestMutator::new())),
        OpenApiMutator::from_series_mutator(Box::new(BreakLinkMutator::new())),
        OpenApiMutator::from_series_mutator(Box::new(EstablishLinkMutator::new())),
    )
}

/// The main mutator for our inputs (series of REST API requests).
/// It has two variants, Contents mutates the contents of parameter values using
/// LibAFL mutators, while Series inserts or deletes requests, or changes their order.
pub enum OpenApiMutator<S>
where
    S: HasRand,
{
    /// Mutator that manipulates the contents of one request in a chain
    Contents(Box<dyn Mutator<BytesInput, S>>),
    /// Mutator that manipulates the order or number of request in the chain
    Series(Box<dyn Mutator<OpenApiInput, S>>),
}

impl<S> Named for OpenApiMutator<S>
where
    S: HasRand,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("OpenApiMutator")
    }
}

impl<S> Default for OpenApiMutator<S>
where
    S: HasRand,
{
    fn default() -> Self {
        Self::Contents(Box::new(BitFlipMutator::new()))
    }
}

impl<S> OpenApiMutator<S>
where
    S: HasRand,
{
    /// Creates a new request-contents-mutator given a BytesInput mutator
    #[must_use]
    pub fn from_bytes_mutator(mutator: Box<dyn Mutator<BytesInput, S>>) -> Self {
        Self::Contents(mutator)
    }

    /// Creates a new request-series-mutator given an OpenApiInput mutator
    #[must_use]
    pub fn from_series_mutator(mutator: Box<dyn Mutator<OpenApiInput, S>>) -> Self {
        Self::Series(mutator)
    }
}

impl<S> Mutator<OpenApiInput, S> for OpenApiMutator<S>
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut OpenApiInput) -> Result<MutationResult, Error> {
        match self {
            OpenApiMutator::Contents(contents_mutator) => {
                // We want a list of all parameter values that we can change.
                // Hence we visit each input and collect references to any parameter contents
                // that are not references to earlier requests' outputs.
                let concrete_parameters = input
                    .parameter_filter(&|value| !value.is_reference())
                    .map(|(_, v)| v);

                let random_param = match choose(state.rand_mut(), concrete_parameters) {
                    Some(parameter) => parameter,
                    None => return Ok(MutationResult::Skipped),
                };

                // Choose the JSON mutators or the ASCII mutators depending on parameter variant
                mutate_parameter_contents(random_param, state, contents_mutator.as_mut())
            }
            OpenApiMutator::Series(b) => b.mutate(state, input),
        }
    }
}

/// Mutate leaf value in-place
fn mutate_leaf_value<S: HasRand>(
    state: &mut S,
    contents_mutator: &mut dyn Mutator<BytesInput, S>,
    leaf_value: &mut SimpleValue,
) -> MutationResult {
    match leaf_value {
        SimpleValue::Null => MutationResult::Skipped,
        SimpleValue::Bool(ref mut b) => {
            *b = !*b;
            MutationResult::Mutated
        }
        SimpleValue::Number(ref mut n) => mutate_number(state, n),
        SimpleValue::String(ref mut s) => mutate_string(state, contents_mutator, s),
    }
}

/// Mutate number in-place
fn mutate_number<S: HasRand>(state: &mut S, n: &mut serde_json::value::Number) -> MutationResult {
    // A small chance to get a special value that might just lead to interesting errors
    match state.rand_mut().below(NonZero::new(100).unwrap()) {
        0 => {
            *n = (-1).into();
            return MutationResult::Mutated;
        }
        1 => {
            *n = u64::MAX.into();
            return MutationResult::Mutated;
        }
        _ => (),
    };
    if let Some(x) = n.as_u64() {
        *n = match x as usize {
            0 => 0.into(),
            x_usz => state
                .rand_mut()
                .below(NonZero::new(x_usz.saturating_mul(2)).unwrap())
                .into(),
        };
        return MutationResult::Mutated;
    };
    if let Some(x) = n.as_i64() {
        // always negative
        *n = (state.rand_mut().below(
            NonZero::new(x.wrapping_neg().saturating_mul(4) as usize)
                .unwrap_or(NonZero::new(usize::MAX).unwrap()), // larger values could otherwise be truncated
        ) as i64
            + x.saturating_mul(2))
        .into();
        return MutationResult::Mutated;
    };
    if let Some(mut x) = n.as_f64() {
        // always finite
        let x_sgn = x.signum();
        x *= x_sgn;
        let x_int = x.round() as u64;
        let x_int_new = match x_int as usize {
            0 => 0,
            x_usz => state
                .rand_mut()
                .below(NonZero::new(x_usz.saturating_mul(4)).unwrap()),
        };
        let n_new = serde_json::value::Number::from_f64((x_int_new as f64) - 2.0 * x);
        if let Some(n_new) = n_new {
            *n = n_new;
            return MutationResult::Mutated;
        }
    };
    MutationResult::Skipped
}

/// Mutate string in-place
fn mutate_string<S: HasRand>(
    state: &mut S,
    contents_mutator: &mut dyn Mutator<BytesInput, S>,
    s: &mut String,
) -> MutationResult {
    let mut bytes_input = s.as_bytes().into();

    // Apply byte-wise mutation using the inner AFL mutator.
    // If it fails, or didn't do anything, stop here
    if let Ok(MutationResult::Skipped) | Err(_) = contents_mutator.mutate(state, &mut bytes_input) {
        return MutationResult::Skipped;
    };

    // Parse the ASCII string to a &str
    let new_s = String::from_utf8_lossy(bytes_input.bytes());
    if *s == new_s {
        return MutationResult::Skipped;
    }
    *s = new_s.into_owned();
    MutationResult::Mutated
}

/// Mutate parameter contents in-place
fn mutate_parameter_contents<S: HasRand>(
    param_contents: &mut ParameterContents,
    state: &mut S,
    contents_mutator: &mut dyn Mutator<BytesInput, S>,
) -> Result<MutationResult, Error> {
    // Used if we pick an element from an array or object to mutate
    let random_element;
    match param_contents {
        ParameterContents::Object(obj_properties) => {
            random_element = match state.rand_mut().choose(obj_properties.values_mut()) {
                None => {
                    log::info!("Tried to mutate empty object; skipping. If this happens a lot WuppieFuzz may need improvement on this.");
                    return Ok(MutationResult::Skipped);
                }
                Some(element) => element,
            };
        }
        ParameterContents::Array(arr_contents) => {
            random_element = if let Some(element) = state.rand_mut().choose(arr_contents.iter_mut())
            {
                element
            } else {
                // Generate a new element for this empty array
                arr_contents.push(ParameterContents::Bytes(new_rand_input(state.rand_mut())));
                return Ok(MutationResult::Mutated);
            };
        }
        ParameterContents::LeafValue(leaf) => {
            return Ok(mutate_leaf_value(state, contents_mutator, leaf))
        }
        ParameterContents::Bytes(contents) => {
            // The ASCII mutators operate on the LibAFL `BytesInput` type. This requires
            // conversions.
            let mut new_value = BytesInput::from(contents.clone());
            let mutation_result = contents_mutator.mutate(state, &mut new_value);
            if mutation_result.is_ok() {
                // The ASCII mutators might not actually change a value, since bit 0 of all bytes is always 0.
                // To prevent duplicate inputs, we check explicitly if it actually changed anything.
                if contents == new_value.bytes() {
                    return Ok(MutationResult::Skipped);
                }
                *param_contents = ParameterContents::Bytes(new_value.bytes().to_owned())
            }
            return mutation_result;
        }
        ParameterContents::Reference { .. } => unreachable!(
            "Non-nested reference parameters should have been filtered out of concrete_parameters"
        ),
    }
    if let ParameterContents::Reference { .. } = random_element {
        log::warn!("Tried to mutate nested reference. If this happens a lot some solution should be implemented here. Skipping for now.");
        Ok(MutationResult::Skipped)
    } else {
        // This was nested in an array or object, recursively mutate
        mutate_parameter_contents(random_element, state, contents_mutator)
    }
}

/// This is an alternative for `Rand::choose`, which requires the given iterator
/// to have a known length. For `Filter` and the like, that means they need
/// an intermediate conversion to a Vec. This `choose` exhausts `from` and
/// returns one of its elements uniformly at random, making as many calls to
/// `rand.below` as `from` has elements. If `from` contains no items, `choose`
/// returns `None`.
///
/// The algorithm keeps one element on hand at all times as its result, and each
/// item after the first has a 1/(number of items seen so far) chance to replace
/// it.
pub fn choose<R, I, T>(rand: &mut R, from: I) -> Option<T>
where
    R: Rand,
    I: IntoIterator<Item = T>,
{
    from.into_iter()
        .zip(1..)
        .fold(None, |result, (element, count)| {
            match rand.below(NonZero::new(count).unwrap()) {
                0 => Some(element),
                _ => result,
            }
        })
}
