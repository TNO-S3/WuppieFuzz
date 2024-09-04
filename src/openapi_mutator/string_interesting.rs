//! Mutates a string parameter value by inserting certain special values in it
//! that are designed to trigger certain classes of bugs.

use libafl::{
    inputs::{BytesInput, HasBytesVec},
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error,
};
use libafl_bolts::{rands::Rand, Named};

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
    fn name(&self) -> &str {
        "StringInterestingMutator"
    }
}

impl<S> Mutator<BytesInput, S> for StringInterestingMutator
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut BytesInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        input.bytes_mut().clear();
        input
            .bytes_mut()
            .extend_from_slice(state.rand_mut().choose(INTERESTING_STR));
        Ok(MutationResult::Mutated)
    }
}
