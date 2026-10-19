//! Portable Unix custody state for the fixed H20/W4 fee profile.
//!
//! Reuses the exact desktop scheduling, durable reservation and cache code.
//! This is not a chain proof verifier, private-key backend or broadcast service.
//! The platform adapter must validate current proofs, verify signatures using
//! reviewed crypto, and respect expiry/consumption before exporting retries.

#[path = "../../node-control/contracts/src/lms_fee_journal.rs"]
pub mod lms_fee_journal;
#[path = "../../node-control/contracts/src/lms_fee_schedule.rs"]
pub mod lms_fee_schedule;

pub mod ffi;
