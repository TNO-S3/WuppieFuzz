//! Mutates a string parameter value by inserting certain special values in it
//! that are designed to trigger certain classes of bugs.

use std::borrow::Cow;

use libafl::{
    Error,
    corpus::CorpusId,
    inputs::{BytesInput, ResizableMutator},
    mutators::{MutationResult, Mutator},
    state::HasRand,
};
use libafl_bolts::{Named, rands::Rand};

/// Interesting values to randomly insert into string parameter values.
/// These are designed to catch parser errors and SQL injections.
pub const INTERESTING_STR: [&[u8]; 12] = [
    b"'",
    b"\"",
    b"' OR 1=1",
    b"\" OR 1=1",
    b"'--",
    b"\"--",
    b"' AND 1=1--",                          // content-based inference SQLi
    b"' AND 1=2--",                          // content-based inference SQLi
    b"'; WAITFOR DELAY '0:0:59'--", // context-based, time-based inference SQLi for MS SQL Server (timeout)
    b"' AND IF(1=1, SLEEP(59), 0)--", // context-based, time-based inference SQLi for MySQL (timeout)
    b"' AND (SELECT 1 FROM pg_sleep(59))--", // context-based, time-based inference SQLi for PostgreSQL (timeout)
    b"' AND (SELECT 1/0 WHERE 1=1)--", // context-based, error-based inference SQLi (divide by 0)
];

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

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}
