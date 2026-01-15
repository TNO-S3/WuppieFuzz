use core::{fmt::Debug, time::Duration};
use std::{
    cell::{Ref, RefMut},
    marker::PhantomData,
    path::PathBuf,
};

use libafl::{
    Error, HasMetadata, HasNamedMetadata,
    corpus::{
        Corpus, CorpusId, HasCurrentCorpusId, HasTestcase, InMemoryOnDiskCorpus, OnDiskCorpus,
        Testcase,
    },
    feedbacks::{CrashLogic, ExitKindFeedback, StateInitializer},
    inputs::Input,
    schedulers::powersched::SchedulerMetadata,
    stages::StageId,
    state::{
        HasCorpus, HasCurrentStageId, HasExecutions, HasImported, HasLastFoundTime,
        HasLastReportTime, HasMaxSize, HasRand, HasSolutions, HasStartTime, Stoppable,
    },
};
use libafl_bolts::{
    current_nanos,
    rands::{Rand, StdRand},
    serdeany::{NamedSerdeAnyMap, SerdeAnyMap},
};
use serde::{Deserialize, Serialize};

use crate::{openapi::spec::Spec, types::CombinedFeedbackType};

/// OpenApiFuzzerState is an object needed by LibAFL.
///
/// We have a bespoke one so we're able to pass the api spec to mutators,
/// which get a reference to the state object as argument to the mutate method.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OpenApiFuzzerState<I> {
    /// RNG instance
    rand: StdRand,
    /// How many times the executor ran the harness/target
    executions: u64,
    /// Request to stop
    stop_requested: bool,
    /// At what time the fuzzing started
    start_time: Duration,
    /// The corpus
    corpus: InMemoryOnDiskCorpus<I>,
    /// Solutions corpus
    solutions: OnDiskCorpus<I>,
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
    api: Spec,
}

impl<I> HasCurrentStageId for OpenApiFuzzerState<I> {
    fn set_current_stage_id(&mut self, idx: StageId) -> Result<(), Error> {
        self.current_stage = Some(idx);
        Ok(())
    }

    fn clear_stage_id(&mut self) -> Result<(), Error> {
        self.current_stage = None;
        Ok(())
    }

    fn current_stage_id(&self) -> Result<Option<StageId>, Error> {
        Ok(self.current_stage)
    }
}

impl<I> HasCurrentCorpusId for OpenApiFuzzerState<I> {
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

impl<I> Stoppable for OpenApiFuzzerState<I> {
    fn stop_requested(&self) -> bool {
        self.stop_requested
    }

    fn request_stop(&mut self) {
        self.stop_requested = true;
    }

    fn discard_stop_request(&mut self) {
        self.stop_requested = false;
    }
}

impl<I> HasRand for OpenApiFuzzerState<I> {
    type Rand = StdRand;

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

impl<I> HasTestcase<I> for OpenApiFuzzerState<I>
where
    I: Input,
{
    /// To get the testcase
    fn testcase(&self, id: CorpusId) -> Result<Ref<'_, Testcase<I>>, Error> {
        Ok(self.corpus().get(id)?.borrow())
    }

    /// To get mutable testcase
    fn testcase_mut(&self, id: CorpusId) -> Result<RefMut<'_, Testcase<I>>, Error> {
        Ok(self.corpus().get(id)?.borrow_mut())
    }
}

impl<I> HasLastFoundTime for OpenApiFuzzerState<I> {
    /// Return the number of new paths that imported from other fuzzers
    #[inline]
    fn last_found_time(&self) -> &Duration {
        &self.last_found_time
    }

    /// Return the number of new paths that imported from other fuzzers
    #[inline]
    fn last_found_time_mut(&mut self) -> &mut Duration {
        &mut self.last_found_time
    }
}

impl<I> HasCorpus<I> for OpenApiFuzzerState<I>
where
    I: Input,
{
    type Corpus = InMemoryOnDiskCorpus<I>;

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

impl<I> HasSolutions<I> for OpenApiFuzzerState<I>
where
    I: Input,
{
    type Solutions = OnDiskCorpus<I>;

    /// Returns the solutions corpus
    #[inline]
    fn solutions(&self) -> &OnDiskCorpus<I> {
        &self.solutions
    }

    /// Returns the solutions corpus (mutable)
    #[inline]
    fn solutions_mut(&mut self) -> &mut OnDiskCorpus<I> {
        &mut self.solutions
    }
}

impl<I> HasMetadata for OpenApiFuzzerState<I>
where
    I: Input,
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

impl<I> HasExecutions for OpenApiFuzzerState<I>
where
    I: Input,
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

impl<I> HasMaxSize for OpenApiFuzzerState<I>
where
    I: Input,
{
    fn max_size(&self) -> usize {
        self.max_size
    }

    fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size
    }
}

impl<I> HasStartTime for OpenApiFuzzerState<I>
where
    I: Input,
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

impl<I> HasNamedMetadata for OpenApiFuzzerState<I> {
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

impl<I> HasLastReportTime for OpenApiFuzzerState<I>
where
    I: Input,
{
    fn last_report_time(&self) -> &Option<Duration> {
        todo!()
    }

    fn last_report_time_mut(&mut self) -> &mut Option<Duration> {
        todo!()
    }
}

impl<I> HasImported for OpenApiFuzzerState<I> {
    fn imported(&self) -> &usize {
        todo!()
    }

    fn imported_mut(&mut self) -> &mut usize {
        todo!()
    }
}

impl<I> OpenApiFuzzerState<I>
where
    I: Input,
{
    /// Creates a new `State`, taking ownership of all of the individual components during fuzzing.
    pub fn new<F, O>(
        rand: StdRand,
        corpus: InMemoryOnDiskCorpus<I>,
        solutions: OnDiskCorpus<I>,
        feedback: &mut F,
        objective: &mut O,
        api: Spec,
    ) -> Result<Self, Error>
    where
        F: StateInitializer<Self>,
        O: StateInitializer<Self>,
    {
        let mut state = Self {
            rand,
            executions: 0,
            stop_requested: false,
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

    /// Creates a new partially initialized `State`, which needs to be `initialize`d later.
    pub fn new_uninit(initial_corpus: InMemoryOnDiskCorpus<I>, api: Spec) -> Result<Self, Error> {
        let mut state = Self {
            rand: StdRand::with_seed(current_nanos()),
            executions: 0,
            stop_requested: false,
            start_time: Duration::from_millis(0),
            metadata: SerdeAnyMap::default(),
            named_metadata: NamedSerdeAnyMap::default(),
            corpus: initial_corpus,
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            solutions: OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
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
        Ok(state)
    }

    pub fn initialize(
        mut self,
        objective: &mut ExitKindFeedback<CrashLogic>,
        collective_feedback: &mut CombinedFeedbackType,
    ) -> anyhow::Result<Self> {
        collective_feedback.init_state(&mut self)?;
        objective.init_state(&mut self)?;
        Ok(self)
    }
}

// Necessary because of borrow checking conflicts
pub trait HasRandAndOpenAPI {
    type Rand: Rand;
    fn rand_mut_and_openapi(&mut self) -> (&mut Self::Rand, &Spec);
}

impl<I> HasRandAndOpenAPI for OpenApiFuzzerState<I>
where
    I: Input,
{
    type Rand = <Self as HasRand>::Rand;
    fn rand_mut_and_openapi(&mut self) -> (&mut Self::Rand, &Spec) {
        (&mut self.rand, &self.api)
    }
}

#[cfg(test)]
pub mod tests {
    use libafl::state::HasRand;
    use libafl_bolts::rands::StdRand;

    use super::HasRandAndOpenAPI;
    use crate::openapi::spec::Spec;

    pub struct TestOpenApiFuzzerState {
        rand: StdRand,
        openapi: Spec,
    }

    impl TestOpenApiFuzzerState {
        /// The paths that occur in the spec provided by this test state.
        pub const PATHS: [&'static str; 3] = [
            "/simple",
            "/with-path-parameter/{id}",
            "/with-query-parameter",
        ];

        pub fn new() -> Self {
            const DUMMY_SPEC: &str = r#"
            openapi: 3.0.4
            info:
                title: Dummy API
                description: Dummy OpenAPI spec used to test the mutators
                version: 0.1.0

            paths:
                /simple:
                    get:
                        responses:
                            "200":
                                description: OK
                                content:
                                    application/json:
                                        schema:
                                            type: object
                                            properties:
                                                id:
                                                    type: integer
                                                    description: The user ID.
                    delete:
                        responses:
                            "200":
                                description: OK
                /with-path-parameter/{id}:
                    get:
                        responses:
                            "200":
                                description: OK
                        parameters:
                            - name: id
                              in: path
                              description: ID
                              required: true
                              schema:
                                  type: integer
                                  format: int64
                /with-query-parameter:
                    get:
                        responses:
                            "200":
                                description: OK
                        parameters:
                            - name: id
                              in: query
                              description: ID
                              required: true
                              schema:
                                  type: integer
                                  format: int64
            "#;

            Self {
                rand: StdRand::new(),
                openapi: serde_yaml::from_str(DUMMY_SPEC)
                    .expect("Failed to parse dummy OpenAPI spec"),
            }
        }
    }

    impl HasRandAndOpenAPI for TestOpenApiFuzzerState {
        type Rand = StdRand;

        fn rand_mut_and_openapi(&mut self) -> (&mut Self::Rand, &Spec) {
            (&mut self.rand, &self.openapi)
        }
    }

    impl HasRand for TestOpenApiFuzzerState {
        type Rand = StdRand;

        fn rand(&self) -> &Self::Rand {
            &self.rand
        }

        fn rand_mut(&mut self) -> &mut Self::Rand {
            &mut self.rand
        }
    }
}
