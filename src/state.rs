use core::{fmt::Debug, time::Duration};
use openapiv3::OpenAPI;
use serde::{Deserialize, Serialize};
use std::{
    cell::{Ref, RefMut},
    marker::PhantomData,
    path::PathBuf,
};

use libafl::{
    corpus::{Corpus, HasCurrentCorpusId},
    feedbacks::Feedback,
    inputs::Input,
    prelude::{CorpusId, HasTestcase, Testcase, UsesInput},
    schedulers::powersched::SchedulerMetadata,
    stages::{HasCurrentStage, StageId},
    state::{
        HasCorpus, HasExecutions, HasImported, HasLastFoundTime, HasLastReportTime, HasMaxSize,
        HasRand, HasSolutions, HasStartTime, State, Stoppable,
    },
    Error, HasMetadata, HasNamedMetadata,
};
use libafl_bolts::{
    bolts_prelude::StdRand,
    rands::Rand,
    serdeany::{NamedSerdeAnyMap, SerdeAnyMap},
};

/// OpenApiFuzzerState is an object needed by LibAFL.
///
/// We have a bespoke one so we're able to pass the api spec to mutators,
/// which get a reference to the state object as argument to the mutate method.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "
        C: serde::Serialize + for<'a> serde::Deserialize<'a>,
        SC: serde::Serialize + for<'a> serde::Deserialize<'a>,
        R: serde::Serialize + for<'a> serde::Deserialize<'a>
    ")]
pub struct OpenApiFuzzerState<I, C, R, SC> {
    /// RNG instance
    rand: R,
    /// How many times the executor ran the harness/target
    executions: u64,
    /// At what time the fuzzing started
    start_time: Duration,
    /// The corpus
    corpus: C,
    /// Solutions corpus
    solutions: SC,
    /// The current stage
    current_stage: Option<StageId>,
    /// The current corpus Id
    current_corpus_id: Option<CorpusId>,
    /// Metadata stored for this state by one of the components
    metadata: SerdeAnyMap,
    /// Metadata stored with names
    named_metadata: NamedSerdeAnyMap,
    /// MaxSize testcase size for mutators that appreciate it
    max_size: usize,
    /// The last time something new was found
    last_found_time: Duration,
    #[cfg(feature = "std")]
    /// Remaining initial inputs to load, if any
    remaining_initial_files: Option<Vec<PathBuf>>,
    phantom: PhantomData<I>,
    api: OpenAPI,
}

impl<I, C, R, SC> State for OpenApiFuzzerState<I, C, R, SC>
where
    C: Corpus<Input = Self::Input>,
    R: Rand,
    SC: Corpus<Input = Self::Input>,
    Self: UsesInput,
{
}

impl<I, C, R, SC> HasCurrentStage for OpenApiFuzzerState<I, C, R, SC> {
    fn set_current_stage_idx(&mut self, idx: StageId) -> Result<(), Error> {
        self.current_stage = Some(idx);
        Ok(())
    }

    fn clear_stage(&mut self) -> Result<(), Error> {
        self.current_stage = None;
        Ok(())
    }

    fn current_stage_idx(&self) -> Result<Option<StageId>, Error> {
        Ok(self.current_stage)
    }
}

impl<I, C, R, SC> HasCurrentCorpusId for OpenApiFuzzerState<I, C, R, SC> {
    fn set_corpus_id(&mut self, id: CorpusId) -> Result<(), Error> {
        self.current_corpus_id = Some(id);
        Ok(())
    }

    fn clear_corpus_id(&mut self) -> Result<(), Error> {
        self.current_corpus_id = None;
        Ok(())
    }

    fn current_corpus_id(&self) -> Result<Option<CorpusId>, Error> {
        Ok(self.current_corpus_id)
    }
}

impl<I, C, R, SC> Stoppable for OpenApiFuzzerState<I, C, R, SC>
where
    R: Rand,
    Self: UsesInput,
{
    fn stop_requested(&self) -> bool {
        false
    }

    fn request_stop(&mut self) {
        todo!("Stopping not implemented")
    }

    fn discard_stop_request(&mut self) {}
}

impl<I, C, R, SC> HasRand for OpenApiFuzzerState<I, C, R, SC>
where
    I: Input,
    C: Corpus,
    R: Rand,
    SC: Corpus,
{
    type Rand = R;

    /// The rand instance
    #[inline]
    fn rand(&self) -> &Self::Rand {
        &self.rand
    }

    /// The rand instance (mut)
    #[inline]
    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand
    }
}

impl<I, C, R, SC> HasTestcase for OpenApiFuzzerState<I, C, R, SC>
where
    I: Input,
    C: Corpus<Input = <Self as UsesInput>::Input>,
    R: Rand,
{
    /// To get the testcase
    fn testcase(&self, id: CorpusId) -> Result<Ref<Testcase<<Self as UsesInput>::Input>>, Error> {
        Ok(self.corpus().get(id)?.borrow())
    }

    /// To get mutable testcase
    fn testcase_mut(
        &self,
        id: CorpusId,
    ) -> Result<RefMut<Testcase<<Self as UsesInput>::Input>>, Error> {
        Ok(self.corpus().get(id)?.borrow_mut())
    }
}

impl<I, C, R, SC> UsesInput for OpenApiFuzzerState<I, C, R, SC>
where
    I: Input,
{
    type Input = I;
}

impl<I, C, R, SC> HasCorpus for OpenApiFuzzerState<I, C, R, SC>
where
    I: Input,
    C: Corpus<Input = <Self as UsesInput>::Input>,
    R: Rand,
{
    type Corpus = C;

    /// Returns the corpus
    #[inline]
    fn corpus(&self) -> &Self::Corpus {
        &self.corpus
    }

    /// Returns the mutable corpus
    #[inline]
    fn corpus_mut(&mut self) -> &mut Self::Corpus {
        &mut self.corpus
    }
}

impl<I, C, R, SC> HasSolutions for OpenApiFuzzerState<I, C, R, SC>
where
    I: Input,
    SC: Corpus<Input = <Self as UsesInput>::Input>,
{
    type Solutions = SC;

    /// Returns the solutions corpus
    #[inline]
    fn solutions(&self) -> &SC {
        &self.solutions
    }

    /// Returns the solutions corpus (mutable)
    #[inline]
    fn solutions_mut(&mut self) -> &mut SC {
        &mut self.solutions
    }
}

impl<I, C, R, SC> HasMetadata for OpenApiFuzzerState<I, C, R, SC>
where
    I: Input,
    C: Corpus,
    R: Rand,
    SC: Corpus,
{
    /// Get all the metadata into a HashMap
    #[inline]
    fn metadata_map(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    /// Get all the metadata into a HashMap (mutable)
    #[inline]
    fn metadata_map_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl<I, C, R, SC> HasExecutions for OpenApiFuzzerState<I, C, R, SC>
where
    I: Input,
    C: Corpus,
    R: Rand,
    SC: Corpus,
{
    /// The executions counter
    #[inline]
    fn executions(&self) -> &u64 {
        &self.executions
    }

    /// The executions counter (mut)
    #[inline]
    fn executions_mut(&mut self) -> &mut u64 {
        &mut self.executions
    }
}

impl<C, I, R, SC> HasMaxSize for OpenApiFuzzerState<I, C, R, SC>
where
    I: Input,
    C: Corpus,
    R: Rand,
    SC: Corpus,
{
    fn max_size(&self) -> usize {
        self.max_size
    }

    fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size
    }
}

impl<C, I, R, SC> HasStartTime for OpenApiFuzzerState<I, C, R, SC>
where
    I: Input,
    C: Corpus,
    R: Rand,
    SC: Corpus,
{
    /// The starting time
    #[inline]
    fn start_time(&self) -> &Duration {
        &self.start_time
    }

    /// The starting time (mut)
    #[inline]
    fn start_time_mut(&mut self) -> &mut Duration {
        &mut self.start_time
    }
}

impl<I, C, R, SC> HasNamedMetadata for OpenApiFuzzerState<I, C, R, SC> {
    /// Get all the metadata into an HashMap
    #[inline]
    fn named_metadata_map(&self) -> &NamedSerdeAnyMap {
        &self.named_metadata
    }

    /// Get all the metadata into an HashMap (mutable)
    #[inline]
    fn named_metadata_map_mut(&mut self) -> &mut NamedSerdeAnyMap {
        &mut self.named_metadata
    }
}

impl<I, C, R, SC> HasLastReportTime for OpenApiFuzzerState<I, C, R, SC>
where
    I: Input,
    C: Corpus,
    R: Rand,
    SC: Corpus,
{
    fn last_report_time(&self) -> &Option<Duration> {
        todo!()
    }

    fn last_report_time_mut(&mut self) -> &mut Option<Duration> {
        todo!()
    }
}

impl<C, I, R, SC> HasImported for OpenApiFuzzerState<I, C, R, SC> {
    fn imported(&self) -> &usize {
        todo!()
    }

    fn imported_mut(&mut self) -> &mut usize {
        todo!()
    }
}

impl<C, I, R, SC> HasLastFoundTime for OpenApiFuzzerState<I, C, R, SC> {
    fn last_found_time(&self) -> &Duration {
        &self.last_found_time
    }

    fn last_found_time_mut(&mut self) -> &mut Duration {
        &mut self.last_found_time
    }
}

impl<C, I, R, SC> OpenApiFuzzerState<I, C, R, SC>
where
    I: Input,
    C: Corpus<Input = I>,
    R: Rand,
    SC: Corpus<Input = I>,
{
    /// Creates a new `State`, taking ownership of all of the individual components during fuzzing.
    pub fn new<F, O>(
        rand: R,
        corpus: C,
        solutions: SC,
        feedback: &mut F,
        objective: &mut O,
        api: OpenAPI,
    ) -> Result<Self, Error>
    where
        F: Feedback<Self>,
        O: Feedback<Self>,
    {
        let mut state = Self {
            rand,
            executions: 0,
            start_time: Duration::from_millis(0),
            metadata: SerdeAnyMap::default(),
            named_metadata: NamedSerdeAnyMap::default(),
            corpus,
            solutions,
            max_size: libafl::state::DEFAULT_MAX_SIZE,
            #[cfg(feature = "std")]
            remaining_initial_files: None,
            phantom: PhantomData,
            api,
            current_stage: None,
            current_corpus_id: None,
            last_found_time: Duration::default(),
        };
        state.add_metadata(SchedulerMetadata::new(None));

        feedback.init_state(&mut state)?;
        objective.init_state(&mut state)?;
        Ok(state)
    }
}

// Necessary because of borrow checking conflicts
pub trait HasRandAndOpenAPI {
    type Rand: Rand;
    fn rand_mut_and_openapi(&mut self) -> (&mut Self::Rand, &OpenAPI);
}

impl<C, I, R, SC> HasRandAndOpenAPI for OpenApiFuzzerState<I, C, R, SC>
where
    I: Input,
    C: Corpus,
    R: Rand,
    SC: Corpus,
{
    type Rand = <Self as HasRand>::Rand;
    fn rand_mut_and_openapi(&mut self) -> (&mut Self::Rand, &OpenAPI) {
        (&mut self.rand, &self.api)
    }
}

/// The event manager needs a state object when tracking coverage, but it doesn't use it.
/// Keeping many references to the state around so we can give the event manager a reference
/// to the state when tracking coverage is complicated. Making a Nop-State on demand is
/// cheap and since it's not used, works fine. Might even be optimized out.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct NopState<I> {
    metadata: SerdeAnyMap,
    rand: StdRand,
    phantom: PhantomData<I>,
}

impl<I> NopState<I> {
    /// Create a new State that does nothing (for tests)
    #[must_use]
    pub fn new() -> Self {
        NopState {
            metadata: SerdeAnyMap::new(),
            rand: StdRand::default(),
            phantom: PhantomData,
        }
    }
}

impl<I> UsesInput for NopState<I>
where
    I: Input,
{
    type Input = I;
}

impl<I> HasExecutions for NopState<I> {
    fn executions(&self) -> &u64 {
        unimplemented!()
    }

    fn executions_mut(&mut self) -> &mut u64 {
        unimplemented!()
    }
}

impl<I> HasMetadata for NopState<I> {
    fn metadata_map(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    fn metadata_map_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl<I> HasRand for NopState<I> {
    type Rand = StdRand;

    fn rand(&self) -> &Self::Rand {
        &self.rand
    }

    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand
    }
}

impl<I> HasImported for NopState<I> {
    fn imported(&self) -> &usize {
        unimplemented!()
    }

    fn imported_mut(&mut self) -> &mut usize {
        unimplemented!()
    }
}

impl<I> State for NopState<I> where I: Input {}

impl<I> Stoppable for NopState<I>
where
    I: Input,
{
    fn stop_requested(&self) -> bool {
        false
    }

    fn request_stop(&mut self) {}

    fn discard_stop_request(&mut self) {}
}

impl<I> HasCurrentStage for NopState<I>
where
    I: Input,
{
    fn set_current_stage_idx(&mut self, _idx: StageId) -> Result<(), Error> {
        todo!()
    }

    fn clear_stage(&mut self) -> Result<(), Error> {
        todo!()
    }

    fn current_stage_idx(&self) -> Result<Option<StageId>, Error> {
        Ok(None)
    }
}

impl<I> HasCurrentCorpusId for NopState<I>
where
    I: Input,
{
    fn set_corpus_id(&mut self, _id: CorpusId) -> Result<(), Error> {
        todo!()
    }

    fn clear_corpus_id(&mut self) -> Result<(), Error> {
        todo!()
    }

    fn current_corpus_id(&self) -> Result<Option<CorpusId>, Error> {
        Ok(None)
    }
}
