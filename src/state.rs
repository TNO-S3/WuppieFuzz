use core::{fmt::Debug, time::Duration};
use std::{
    cell::{Ref, RefMut},
    marker::PhantomData,
    path::PathBuf,
};

use libafl::{
    Error, HasMetadata, HasNamedMetadata,
    corpus::{Corpus, CorpusId, HasCurrentCorpusId, HasTestcase, Testcase},
    feedbacks::StateInitializer,
    inputs::Input,
    schedulers::powersched::SchedulerMetadata,
    stages::StageId,
    state::{
        HasCorpus, HasCurrentStageId, HasExecutions, HasImported, HasLastFoundTime,
        HasLastReportTime, HasMaxSize, HasRand, HasSolutions, HasStartTime, Stoppable,
    },
};
use libafl_bolts::{
    rands::Rand,
    serdeany::{NamedSerdeAnyMap, SerdeAnyMap},
};
use openapiv3::OpenAPI;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

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
    /// Request to stop
    stop_requested: bool,
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

impl<I, C, R, SC> HasCurrentStageId for OpenApiFuzzerState<I, C, R, SC> {
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

impl<I, C, R, SC> Stoppable for OpenApiFuzzerState<I, C, R, SC> {
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

impl<I, C, R, SC> HasRand for OpenApiFuzzerState<I, C, R, SC>
where
    R: Rand,
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

impl<I, C, R, SC> HasTestcase<I> for OpenApiFuzzerState<I, C, R, SC>
where
    C: Corpus<I>,
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

impl<I, C, R, SC> HasLastFoundTime for OpenApiFuzzerState<I, C, R, SC> {
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

impl<I, C, R, SC> HasCorpus<I> for OpenApiFuzzerState<I, C, R, SC>
where
    C: Corpus<I>,
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

impl<I, C, R, SC> HasSolutions<I> for OpenApiFuzzerState<I, C, R, SC>
where
    I: Input,
    SC: Corpus<I>,
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
    C: Corpus<I>,
    R: Rand,
    SC: Corpus<I>,
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
    C: Corpus<I>,
    R: Rand,
    SC: Corpus<I>,
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
    C: Corpus<I>,
    R: Rand,
    SC: Corpus<I>,
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
    C: Corpus<I>,
    R: Rand,
    SC: Corpus<I>,
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
    C: Corpus<I>,
    R: Rand,
    SC: Corpus<I>,
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

impl<C, I, R, SC> OpenApiFuzzerState<I, C, R, SC>
where
    I: Input,
    C: Corpus<I>,
    R: Rand,
    SC: Corpus<I>,
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
        F: StateInitializer<Self>,
        O: StateInitializer<Self>,
        C: Serialize + DeserializeOwned,
        SC: Serialize + DeserializeOwned,
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
}

// Necessary because of borrow checking conflicts
pub trait HasRandAndOpenAPI {
    type Rand: Rand;
    fn rand_mut_and_openapi(&mut self) -> (&mut Self::Rand, &OpenAPI);
}

impl<C, I, R, SC> HasRandAndOpenAPI for OpenApiFuzzerState<I, C, R, SC>
where
    I: Input,
    C: Corpus<I>,
    R: Rand,
    SC: Corpus<I>,
{
    type Rand = <Self as HasRand>::Rand;
    fn rand_mut_and_openapi(&mut self) -> (&mut Self::Rand, &OpenAPI) {
        (&mut self.rand, &self.api)
    }
}

#[cfg(test)]
pub mod tests {
    use libafl::state::HasRand;
    use libafl_bolts::rands::StdRand;
    use openapiv3::OpenAPI;

    use super::HasRandAndOpenAPI;

    pub struct TestOpenApiFuzzerState {
        rand: StdRand,
        openapi: OpenAPI,
    }

    impl TestOpenApiFuzzerState {
        /// The paths that occur in the spec provided by this test state.
        pub const PATHS: [&'static str; 3] = [
            "/simple",
            "/with-path-parameter/{id}",
            "/with-query-parameter",
        ];

        pub fn new() -> Self {
            const DUMMY_SPEC: &'static str = r#"
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

        fn rand_mut_and_openapi(&mut self) -> (&mut Self::Rand, &openapiv3::OpenAPI) {
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
