/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */
//! The contract release this SDK speaks to.
//!
//! The service contracts' storage, getters and signing domains change between
//! releases, and an instance keeps the code it was deployed with. Decoding an
//! older instance's getters with this release's layout reads the wrong
//! fields, and a signature built for this release's domain is one the older
//! code refuses. Callers therefore compare an instance's deployed code with
//! the code this SDK builds before decoding its state or signing for it.

use chain_block::{Cell, read_single_root_boc};

use crate::{DisputeContract, ProofAttestationContract, ServiceActorContract, TaskEscrowContract};

/// A contract whose deployed code must match the release this SDK builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionedContract {
    TaskEscrow,
    Dispute,
    ProofAttestation,
    ServiceActor,
}

impl VersionedContract {
    pub fn name(self) -> &'static str {
        match self {
            Self::TaskEscrow => "Task Escrow",
            Self::Dispute => "Dispute",
            Self::ProofAttestation => "Proof Attestation",
            Self::ServiceActor => "Service Actor",
        }
    }

    /// The code this SDK deploys and whose getters and signing domains it
    /// implements.
    pub fn supported_code(self) -> anyhow::Result<Cell> {
        match self {
            Self::TaskEscrow => TaskEscrowContract::code(),
            Self::Dispute => DisputeContract::code(),
            Self::ProofAttestation => ProofAttestationContract::code(),
            Self::ServiceActor => ServiceActorContract::code(),
        }
    }

    /// Refuses an instance whose deployed code is not the supported release.
    pub fn require_supported_code(self, deployed: &Cell) -> anyhow::Result<()> {
        let supported = self.supported_code()?.repr_hash();
        let deployed = deployed.repr_hash();
        if deployed != supported {
            anyhow::bail!(
                "unsupported {} contract version {}; this tosctl supports {}",
                self.name(),
                deployed.as_hex_string(),
                supported.as_hex_string()
            );
        }
        Ok(())
    }

    /// [`Self::require_supported_code`] for the code BOC an account query
    /// returns. An account without code is refused: it is not an instance of
    /// any release.
    pub fn require_supported_code_boc(self, deployed: Option<&[u8]>) -> anyhow::Result<()> {
        let boc = deployed.ok_or_else(|| {
            anyhow::anyhow!("{} account has no deployed code to check", self.name())
        })?;
        let code = read_single_root_boc(boc).map_err(|e| {
            anyhow::anyhow!("{} deployed code is not a valid BOC: {e}", self.name())
        })?;
        self.require_supported_code(&code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_supported_code_of_each_contract_is_accepted() {
        for contract in [
            VersionedContract::TaskEscrow,
            VersionedContract::Dispute,
            VersionedContract::ProofAttestation,
            VersionedContract::ServiceActor,
        ] {
            let code = contract.supported_code().unwrap();
            contract.require_supported_code(&code).unwrap();
        }
    }

    #[test]
    fn another_contracts_code_is_refused_with_both_hashes() {
        let other = DisputeContract::code().unwrap();
        let error =
            VersionedContract::TaskEscrow.require_supported_code(&other).unwrap_err().to_string();
        assert!(error.contains("unsupported Task Escrow contract version"), "{error}");
        assert!(error.contains(&other.repr_hash().as_hex_string()), "{error}");
        let supported = TaskEscrowContract::code().unwrap().repr_hash().as_hex_string();
        assert!(error.contains(&format!("this tosctl supports {supported}")), "{error}");
    }

    #[test]
    fn an_account_without_code_is_refused() {
        let error = VersionedContract::Dispute.require_supported_code_boc(None).unwrap_err();
        assert!(error.to_string().contains("no deployed code"), "{error}");
    }
}
