//! Owned-note balance: scan hits ∖ spent nullifiers.
//!
//! The chain never sees a wallet balance (§9.2). Balance is purely a local
//! computation: sum `value` for every owned note whose `nullifier` has not
//! been spent on-chain. We check each owned note against
//! `uno_getNullifierStatus` to filter out spent entries.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::rpc_client::RpcClient;
use crate::scan::OwnedNote;

/// Balance summary for CLI output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balance {
    pub total_nano: u128,
    pub unspent_count: usize,
    pub spent_count: usize,
    /// Plaintext unspent notes, in global-index order (stable for tests).
    pub unspent: Vec<OwnedNote>,
}

/// Compute balance from a scan result + live nullifier queries.
pub async fn balance_for_notes(rpc: &RpcClient, owned: &[OwnedNote]) -> Result<Balance> {
    let mut total: u128 = 0;
    let mut unspent = Vec::new();
    let mut spent_count = 0;

    for note in owned {
        let status = rpc.get_nullifier_status(&note.nullifier).await?;
        if status.spent {
            spent_count += 1;
        } else {
            total = total.saturating_add(note.value as u128);
            unspent.push(note.clone());
        }
    }

    Ok(Balance {
        total_nano: total,
        unspent_count: unspent.len(),
        spent_count,
        unspent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balance_struct_serializes() {
        let b = Balance {
            total_nano: 1_000_000,
            unspent_count: 2,
            spent_count: 1,
            unspent: vec![],
        };
        let s = serde_json::to_string(&b).unwrap();
        assert!(s.contains("total_nano"));
    }
}
