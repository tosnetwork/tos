/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
/// Configuration contract implementation
mod config_impl;
/// Messages for configuration contract
pub mod messages;
/// Decoding of `get_proposal` as the node serves it
mod proposal_read;
/// Proposals read from the contract's stored account (the large-state path)
pub mod proposal_state;
/// Proposal reads on a bounded worker, returning flat results
pub mod proposal_transport;
/// Wrapper trait for configuration contract get-methods
mod wrapper;

pub use config_impl::ConfigContractImpl;
pub use proposal_read::{
    PROPOSAL_FIELDS, decode_proposal, decode_proposal_expiry, decode_proposal_list,
};
pub use proposal_transport::{ProposalAnswer, ProposalRead};
pub use wrapper::{ConfigContractWrapper, ConfigProposal, ProposalHash, ProposedParam};
