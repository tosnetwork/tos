/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! Rust SDK for TOS's native AI-actor contracts: Agent Account, Task Escrow,
//! Capability Registry, Service Actor, Dispute and Proof Attestation.
//!
//! Each contract module (e.g. [`agent_account`], [`task_escrow`]) exposes,
//! independent of the `tosctl` CLI or any vault/key-management choice:
//!
//! - deterministic StateInit / deploy-data construction (`build_state_init`,
//!   `calculate_address`)
//! - operation-message body builders (e.g. `TaskEscrowContract::accept`)
//! - get-method result decoding (`decode_data`, transport-agnostic)
//!
//! Signing and network submission (JSON-RPC or otherwise) are the caller's
//! responsibility -- see `examples/agent_sdk_walkthrough.rs` for an
//! end-to-end construction walkthrough that runs without `tosctl`.
pub mod agent_account;
pub mod attestation;
pub mod capability_registry;
pub mod chain_provider;
pub mod config_contract;
pub mod contract_codes;
pub mod dispute;
pub mod elector;
pub mod liquid_controller;
pub mod nominator;
pub mod nominator_pool;
pub mod aipow_commitment;
pub mod aipow_distributor;
pub mod aipow_merkle;
pub mod aipow_settlement;
pub mod proof_attestation;
pub mod provider;
pub mod service_actor;
pub mod smart_contract;
pub mod task_escrow;
pub mod stack_utils;
pub mod wallet;

pub use agent_account::{
    AgentAccountContract, AgentAccountData, AgentAccountInit, AgentAccountPolicyUpdate,
};
pub use attestation::{
    domain_bound_hash, resolve_domain_hash, service_actor_terms_hash, service_respond_domain_hash,
    settle_domain_hash,
};
pub use capability_registry::{
    CapabilityRegistryContract, CapabilityRegistryData, CapabilityRegistryInit,
};
pub use chain_provider::{ChainProvider, DefaultChainProvider, contract_provider_from};
pub use config_contract::{
    ConfigContractImpl, ConfigContractWrapper, ConfigProposal, ProposedParam,
};
pub use dispute::{
    DISPUTE_STATUS_EVIDENCE_SUBMITTED, DISPUTE_STATUS_OPEN, DISPUTE_STATUS_RESOLVED,
    DisputeContract, DisputeData, DisputeInit, RULING_CLAIMANT, RULING_NONE, RULING_RESPONDENT,
    RULING_SPLIT,
};
pub use elector::{ElectionsInfo, ElectorWrapper, ElectorWrapperImpl, Participant};
pub use liquid_controller::{ControllerData, ControllerWrapper, ControllerWrapperImpl, LoanBalanceRequirement};
pub use nominator::{NOMINATOR_POOL_WORKCHAIN, NominatorWrapper, NominatorWrapperImpl};
pub use nominator_pool::{NominatorData, NominatorPoolData, NominatorPoolWrapper, NominatorPoolWrapperImpl};
pub use aipow_commitment::{
    AIPOW_COMMITMENT_STATUS_CHALLENGED, AIPOW_COMMITMENT_STATUS_COMMITTED,
    AIPOW_COMMITMENT_STATUS_FINAL, AIPOW_COMMITMENT_STATUS_REJECTED, AIPOW_COMMITMENT_VERSION,
    AipowCommitmentContract, AipowCommitmentData, AipowCommitmentInit,
};
pub use aipow_distributor::{
    compute_matured, AipowClaim, AipowDistributorContract, AipowDistributorData,
    AipowDistributorInit, AipowMaturation, AIPOW_DISTRIBUTOR_CLAIM_OPCODE,
    AIPOW_DISTRIBUTOR_FORFEIT_OPCODE, AIPOW_DISTRIBUTOR_PAYOUT_OPCODE, AIPOW_DISTRIBUTOR_VERSION,
    AIPOW_MATURATION_EPOCH_SECONDS, AIPOW_MATURATION_IMMEDIATE_BPS, AIPOW_MATURATION_STREAM_EPOCHS,
    AIPOW_MIN_CLAIM_VALUE,
};
pub use aipow_settlement::{
    AipowCandidate, AipowSettlementContract, AipowSettlementData, AipowSettlementInit,
    AIPOW_SETTLEMENT_REGISTER_OPCODE, AIPOW_SETTLEMENT_SKIP_OPCODE, AIPOW_SETTLEMENT_VERSION,
};
pub use proof_attestation::{ProofAttestationContract, ProofAttestationData, ProofAttestationInit};
pub use provider::ContractProvider;
pub use service_actor::{
    PendingRequestData, RefundData, ServiceActorContract, ServiceActorData, ServiceActorInit,
};
pub use smart_contract::SmartContract;
pub use task_escrow::{TaskEscrowContract, TaskEscrowData, TaskEscrowInit};
pub use wallet::{Wallet, WalletContract};
