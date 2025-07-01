//! Mutates a string parameter value by inserting certain special values in it
//! that are designed to trigger certain classes of bugs.

use std::borrow::Cow;

use libafl::{
    Error,
    inputs::{BytesInput, ResizableMutator},
    mutators::{MutationResult, Mutator},
    state::HasRand,
};
use libafl_bolts::{Named, rands::Rand};

/// Interesting values to randomly insert into string parameter values.
/// These are designed to catch parser errors and SQL injections.
pub const INTERESTING_STR: [&[u8]; 6] = [b"'", b"\"", b"' OR 1=1", b"\" OR 1=1", b"'--", b"\"--"];

/// The mutator that inserts strings from INTERESTING_STR into values.
pub struct StringInterestingMutator;

impl StringInterestingMutator {
    /// Create a new StringInterestingMutator
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for StringInterestingMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for StringInterestingMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("StringInterestingMutator")
    }
}

impl<S> Mutator<BytesInput, S> for StringInterestingMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        input.resize(0, 0);
        input.extend(state.rand_mut().choose(INTERESTING_STR).unwrap());
        Ok(MutationResult::Mutated)
    }
}
