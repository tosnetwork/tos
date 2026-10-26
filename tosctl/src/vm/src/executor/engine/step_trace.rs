/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! Per-step trace for conformance tests, built only with the `step_trace`
//! feature. Its events are the C++ VM's test-build trace events, so the two
//! traces can be compared line by line: one step event per fetched
//! instruction, implicit JMPREF or implicit RET, after the step counter is
//! incremented and before the instruction runs; one load event after each
//! charged cell load.

use std::cell::RefCell;

use chain_block::UInt256;

/// One step as both VMs report it.
pub struct StepEvent {
    pub steps: u32,
    pub gas_remaining: i64,
    pub stack_depth: usize,
    pub child: bool,
    pub code_hash: Option<UInt256>,
    pub offset: usize,
}

pub trait StepTraceSink {
    fn on_step(&mut self, event: &StepEvent);
    fn on_cell_load(&mut self, steps: u32, hash: &UInt256, first: bool);
}

thread_local! {
    static SINK: RefCell<Option<Box<dyn StepTraceSink>>> = const { RefCell::new(None) };
}

/// Installs the sink of the current thread and returns the previous one;
/// `None`, the default, records nothing.
pub fn set_step_trace_sink(sink: Option<Box<dyn StepTraceSink>>) -> Option<Box<dyn StepTraceSink>> {
    SINK.with(|slot| slot.replace(sink))
}

pub(super) fn step(event: impl FnOnce() -> StepEvent) {
    SINK.with(|slot| {
        if let Some(sink) = slot.borrow_mut().as_mut() {
            sink.on_step(&event());
        }
    });
}

pub(super) fn cell_load(steps: u32, hash: &UInt256, first: bool) {
    SINK.with(|slot| {
        if let Some(sink) = slot.borrow_mut().as_mut() {
            sink.on_cell_load(steps, hash, first);
        }
    });
}
