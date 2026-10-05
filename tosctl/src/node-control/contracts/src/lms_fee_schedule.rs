// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Read-only fee-leaf scheduling for the fixed H20/W4 wallet profile.
//!
//! This is not a signer or a durable reservation. Before signing, a single-writer
//! custody provider must durably reserve the returned leaf and retain its high
//! water even for failed, expired, unbroadcast or forked-out signatures. An old
//! snapshot is not intact state. Restore also requires revoking the old writer.
//! All times and chain counters must come from finalized, proof-checked state;
//! neither wall-clock time nor unverified RPC results are acceptable inputs.

pub const SLOT_SECONDS: u32 = 3600;
pub const LEAVES_PER_SLOT: u32 = 4;
pub const LEAF_COUNT: u32 = 1 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeeRoute {
    pub global_id: i32,
    pub network: [u8; 32],
    pub vault: [u8; 32],
    pub tree_id: [u8; 32],
    pub epoch0: u32,
}

/// The caller must obtain these fields from its protected reservation journal.
/// The counter is the first leaf not reserved, not the chain's accepted counter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntactState {
    pub route: FeeRoute,
    pub next_unreserved: u32,
    pub last_proven_time: u32,
}

/// Opaque, route-bound barrier created once when state continuity is lost.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoreBarrier {
    route: FeeRoute,
    observed_time: u32,
    resume_at: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Continuity {
    Intact(IntactState),
    Restored(RestoreBarrier),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduleError {
    BeforeEpoch,
    WrongRoute,
    StaleProof,
    InvalidCounter,
    Exhausted,
    WaitUntil(u32),
    TimeOverflow,
}

/// A proposal for an atomic durable reservation, never permission to sign by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReservationPlan {
    pub leaf: u32,
    pub next_state: IntactState,
}

fn slot(route: &FeeRoute, proven_time: u32) -> Result<u32, ScheduleError> {
    let elapsed = proven_time.checked_sub(route.epoch0).ok_or(ScheduleError::BeforeEpoch)?;
    Ok(elapsed / SLOT_SECONDS)
}

fn first_leaf(slot: u32) -> Result<u32, ScheduleError> {
    let leaf = slot.checked_mul(LEAVES_PER_SLOT).ok_or(ScheduleError::Exhausted)?;
    if leaf >= LEAF_COUNT {
        return Err(ScheduleError::Exhausted);
    }
    Ok(leaf)
}

fn next_boundary(route: &FeeRoute, current_slot: u32) -> Result<u32, ScheduleError> {
    let next = current_slot.checked_add(1).ok_or(ScheduleError::Exhausted)?;
    first_leaf(next)?;
    let offset = next.checked_mul(SLOT_SECONDS).ok_or(ScheduleError::TimeOverflow)?;
    route.epoch0.checked_add(offset).ok_or(ScheduleError::TimeOverflow)
}

impl RestoreBarrier {
    /// Even at an exact slot boundary, a restored writer cannot prove that the
    /// current slot was unused. It waits for the next boundary observed on chain.
    pub fn new(route: FeeRoute, proven_time: u32) -> Result<Self, ScheduleError> {
        let current = slot(&route, proven_time)?;
        let resume_at = next_boundary(&route, current)?;
        Ok(Self { route, observed_time: proven_time, resume_at })
    }

    pub fn resume_at(&self) -> u32 {
        self.resume_at
    }
}

/// Select only a current-slot leaf. The vault's previous-slot delivery allowance
/// is not permission to generate new signatures for that previous slot.
pub fn plan_reservation(
    route: FeeRoute,
    proven_time: u32,
    chain_next_leaf: u32,
    continuity: Continuity,
) -> Result<ReservationPlan, ScheduleError> {
    if chain_next_leaf > LEAF_COUNT {
        return Err(ScheduleError::InvalidCounter);
    }
    let local_next = match continuity {
        Continuity::Intact(state) => {
            if state.route != route {
                return Err(ScheduleError::WrongRoute);
            }
            if proven_time < state.last_proven_time {
                return Err(ScheduleError::StaleProof);
            }
            if state.next_unreserved > LEAF_COUNT {
                return Err(ScheduleError::InvalidCounter);
            }
            state.next_unreserved
        }
        Continuity::Restored(barrier) => {
            if barrier.route != route {
                return Err(ScheduleError::WrongRoute);
            }
            if proven_time < barrier.observed_time {
                return Err(ScheduleError::StaleProof);
            }
            if proven_time < barrier.resume_at {
                return Err(ScheduleError::WaitUntil(barrier.resume_at));
            }
            0
        }
    };
    let current = slot(&route, proven_time)?;
    let first = first_leaf(current)?;
    let end = first.checked_add(LEAVES_PER_SLOT).ok_or(ScheduleError::Exhausted)?;
    let leaf = first.max(chain_next_leaf).max(local_next);
    if leaf >= LEAF_COUNT {
        return Err(ScheduleError::Exhausted);
    }
    if leaf >= end {
        // Never reserve ahead of proven chain time, even if a caller reports a
        // future high water. Wait until that leaf's slot rather than reusing one.
        let offset = (leaf / LEAVES_PER_SLOT)
            .checked_mul(SLOT_SECONDS)
            .ok_or(ScheduleError::TimeOverflow)?;
        return Err(ScheduleError::WaitUntil(
            route.epoch0.checked_add(offset).ok_or(ScheduleError::TimeOverflow)?,
        ));
    }
    let next_unreserved = leaf.checked_add(1).ok_or(ScheduleError::Exhausted)?;
    Ok(ReservationPlan {
        leaf,
        next_state: IntactState { route, next_unreserved, last_proven_time: proven_time },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route() -> FeeRoute {
        FeeRoute { global_id: 42, network: [1; 32], vault: [2; 32], tree_id: [3; 32], epoch0: 100 }
    }

    fn intact(next_unreserved: u32, time: u32) -> Continuity {
        Continuity::Intact(IntactState { route: route(), next_unreserved, last_proven_time: time })
    }

    #[test]
    fn exported_but_unbroadcast_and_reorged_leaves_stay_burned() -> Result<(), ScheduleError> {
        let a = plan_reservation(route(), 7300, 0, intact(0, 100))?;
        assert_eq!(a.leaf, 8);
        let b = plan_reservation(route(), 7301, 0, Continuity::Intact(a.next_state))?;
        assert_eq!(b.leaf, 9);
        let c = plan_reservation(route(), 7302, 11, Continuity::Intact(b.next_state))?;
        assert_eq!(c.leaf, 11);
        assert_eq!(
            plan_reservation(route(), 7303, 0, Continuity::Intact(c.next_state)),
            Err(ScheduleError::WaitUntil(10900))
        );
        Ok(())
    }

    #[test]
    fn restore_waits_even_at_exact_boundary_and_ignores_old_counter() -> Result<(), ScheduleError> {
        for observed in [7300, 7301, 10899] {
            let barrier = RestoreBarrier::new(route(), observed)?;
            assert_eq!(barrier.resume_at(), 10900);
            assert_eq!(
                plan_reservation(route(), 10899, 0, Continuity::Restored(barrier)),
                Err(ScheduleError::WaitUntil(10900))
            );
            assert_eq!(
                plan_reservation(route(), 10900, 0, Continuity::Restored(barrier))?.leaf,
                12
            );
            assert_eq!(
                plan_reservation(route(), 14500, 0, Continuity::Restored(barrier))?.leaf,
                16
            );
        }
        Ok(())
    }

    #[test]
    fn every_leaf_is_current_slot_only() -> Result<(), ScheduleError> {
        for q in 0..LEAF_COUNT {
            let time = 100 + (q / 4) * 3600;
            assert_eq!(plan_reservation(route(), time, 0, intact(q, time))?.leaf, q);
        }
        assert_eq!(
            plan_reservation(route(), 100 + (LEAF_COUNT / 4) * 3600, 0, intact(0, 100)),
            Err(ScheduleError::Exhausted)
        );
        Ok(())
    }

    #[test]
    fn fail_closed_on_identity_time_counters_and_calendar_overflow() {
        assert_eq!(
            plan_reservation(route(), 99, 0, intact(0, 99)),
            Err(ScheduleError::BeforeEpoch)
        );
        assert_eq!(
            plan_reservation(route(), 7300, 0, intact(8, 7301)),
            Err(ScheduleError::StaleProof)
        );
        assert_eq!(
            plan_reservation(route(), 7300, LEAF_COUNT + 1, intact(0, 100)),
            Err(ScheduleError::InvalidCounter)
        );
        assert_eq!(
            plan_reservation(route(), 7300, 0, intact(LEAF_COUNT + 1, 100)),
            Err(ScheduleError::InvalidCounter)
        );
        assert_eq!(
            plan_reservation(route(), 7300, LEAF_COUNT, intact(0, 100)),
            Err(ScheduleError::Exhausted)
        );
        for changed in [
            FeeRoute { vault: [4; 32], ..route() },
            FeeRoute { tree_id: [4; 32], ..route() },
            FeeRoute { network: [4; 32], ..route() },
            FeeRoute { global_id: 43, ..route() },
            FeeRoute { epoch0: 101, ..route() },
        ] {
            assert_eq!(
                plan_reservation(changed, 7300, 0, intact(8, 100)),
                Err(ScheduleError::WrongRoute)
            );
        }
        assert_eq!(
            RestoreBarrier::new(FeeRoute { epoch0: u32::MAX, ..route() }, u32::MAX),
            Err(ScheduleError::TimeOverflow)
        );
        assert_eq!(
            RestoreBarrier::new(route(), 100 + (LEAF_COUNT / 4 - 1) * 3600),
            Err(ScheduleError::Exhausted)
        );
    }
}
