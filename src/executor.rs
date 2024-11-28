use std::borrow::BorrowMut;

use libafl::{
    events::{EventFirer, EventRestarter},
    prelude::{Executor, ExitKind, HasObservers, ObserversTuple, UsesObservers},
    state::{HasExecutions, UsesState},
};
use libafl_bolts::prelude::RefIndexable;

use crate::input::OpenApiInput;

type FuzzerState = crate::state::OpenApiFuzzerState<
    OpenApiInput,
    libafl::corpus::InMemoryOnDiskCorpus<OpenApiInput>,
    libafl_bolts::rands::RomuDuoJrRand,
    libafl::corpus::OnDiskCorpus<OpenApiInput>,
>;

pub struct SequenceExecutor<'h, H, OT>
where
    H: FnMut(&OpenApiInput) -> Result<ExitKind, libafl::Error> + ?Sized,
    OT: ObserversTuple<FuzzerState>,
{
    harness_fn: &'h mut H,
    observers: OT,
    phantom: std::marker::PhantomData<H>,
}

impl<'h, EM, Z, H, OT> Executor<EM, Z> for SequenceExecutor<'h, H, OT>
where
    H: FnMut(&OpenApiInput) -> Result<ExitKind, libafl::Error> + ?Sized,
    Z: UsesState<State = FuzzerState>,
    EM: UsesState<State = FuzzerState> + EventFirer<State = FuzzerState> + EventRestarter,
    OT: ObserversTuple<FuzzerState>,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut Self::State,
        _event_manager: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, libafl::Error> {
        *state.executions_mut() += 1;

        self.pre_exec(state, input);

        let ret = self.harness_fn.borrow_mut()(input);

        self.post_exec(state, input);
        ret
    }
}

impl<'h, H, OT> SequenceExecutor<'h, H, OT>
where
    H: FnMut(&OpenApiInput) -> Result<ExitKind, libafl::Error> + ?Sized,
    OT: ObserversTuple<FuzzerState>,
{
    pub fn new(harness_fn: &'h mut H, observers: OT) -> Self {
        Self {
            harness_fn,
            observers,
            phantom: std::marker::PhantomData,
        }
    }
    fn pre_exec(&mut self, state: &mut FuzzerState, input: &OpenApiInput) {}
    fn post_exec(&mut self, state: &mut FuzzerState, input: &OpenApiInput) {}
}

impl<'h, H, OT> UsesState for SequenceExecutor<'h, H, OT>
where
    H: FnMut(&OpenApiInput) -> Result<ExitKind, libafl::Error> + ?Sized,
    OT: ObserversTuple<FuzzerState>,
{
    type State = FuzzerState;
}

impl<'h, H, OT> UsesObservers for SequenceExecutor<'h, H, OT>
where
    H: FnMut(&OpenApiInput) -> Result<ExitKind, libafl::Error> + ?Sized,
    OT: ObserversTuple<FuzzerState>,
{
    type Observers = OT;
}

impl<'h, H, OT> HasObservers for SequenceExecutor<'h, H, OT>
where
    H: FnMut(&OpenApiInput) -> Result<ExitKind, libafl::Error> + ?Sized,
    OT: ObserversTuple<FuzzerState>,
{
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}
