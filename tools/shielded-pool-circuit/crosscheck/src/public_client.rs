//! Offline public-pool proving, as the production prover crate provides it.
//! The sandbox keeps using it through this path so a proof the cross-check
//! accepts is a proof of the same code a spender runs.

pub use shielded_pool_prover::{fresh_nonzero_field, PublicClient};

impl From<shielded_pool_prover::Error> for crate::CrossCheckError {
    fn from(error: shielded_pool_prover::Error) -> Self {
        crate::CrossCheckError::Fixture(error.to_string())
    }
}
