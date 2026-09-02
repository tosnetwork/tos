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
pub mod agent_account_custody;
pub mod attestation;
pub mod capability_registry;
pub mod chain_provider;
pub mod config_contract;
pub mod contract_codes;
pub mod dispute;
pub mod dns;
pub mod elector;
pub mod liquid_controller;
pub mod nominator;
pub mod nominator_pool;
pub mod proof_attestation;
pub mod provider;
pub mod service_actor;
pub mod smart_contract;
pub mod stack_utils;
pub mod task_escrow;
pub mod wallet;

pub use agent_account::{
    AGENT_ACCOUNT_MAX_ACTION_VALUE, AGENT_UPDATE_POLICY_OPCODE, AgentAccountContract,
    AgentAccountData, AgentAccountInit, AgentAccountPolicyUpdate,
};
pub use agent_account_custody::{
    AgentAccountCustodyJournal, ControllerActionClaim, ControllerActionRecord,
    ControllerActionResolutionEvidence, ControllerActionStatus, EconomicActionAuthorization,
    EconomicEffectAuthorization, agent_account_task_body_hash,
    controller_resolution_evidence_digest,
};
pub use attestation::{
    domain_bound_hash, resolve_domain_hash, service_actor_terms_hash, service_respond_domain_hash,
    settle_domain_hash,
};
pub use capability_registry::{
    CapabilityRegistryContract, CapabilityRegistryData, CapabilityRegistryInit,
};
pub use chain_provider::{
    ChainProvider, DefaultChainProvider, MasterchainCheckpoint, contract_provider_from,
};
pub use config_contract::{
    ConfigContractImpl, ConfigContractWrapper, ConfigProposal, ProposedParam,
};
pub use dispute::{
    DISPUTE_STATUS_EVIDENCE_SUBMITTED, DISPUTE_STATUS_OPEN, DISPUTE_STATUS_RESOLVED,
    DisputeContract, DisputeData, DisputeInit, RULING_CLAIMANT, RULING_NONE, RULING_RESPONDENT,
    RULING_SPLIT,
};
pub use elector::{ElectionsInfo, ElectorWrapper, ElectorWrapperImpl, Participant};
pub use liquid_controller::{
    ControllerData, ControllerWrapper, ControllerWrapperImpl, LoanBalanceRequirement,
};
pub use nominator::{NOMINATOR_POOL_WORKCHAIN, NominatorWrapper, NominatorWrapperImpl};
pub use nominator_pool::{
    NominatorData, NominatorPoolData, NominatorPoolWrapper, NominatorPoolWrapperImpl,
    NominatorPosition,
};
pub use proof_attestation::{ProofAttestationContract, ProofAttestationData, ProofAttestationInit};
pub use provider::ContractProvider;
pub use service_actor::{
    PendingRequestData, RefundData, ServiceActorContract, ServiceActorData, ServiceActorInit,
};
pub use smart_contract::SmartContract;
pub use task_escrow::{TaskEscrowContract, TaskEscrowData, TaskEscrowInit};
pub use wallet::{Wallet, WalletContract};
