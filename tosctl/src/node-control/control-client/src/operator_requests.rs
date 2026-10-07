use crate::{
    client_adnl::{ToFromTL, downcast},
    operator_reads::*,
};
use chain_block::UInt256;
use tl_api::{AnyBoxedSerialize, TLObject, tos};

pub(crate) struct GetElectorStateRqRs;
impl ToFromTL for GetElectorStateRqRs {
    type Rq = ElectorStateRequest;
    type Rs = ElectorState;
    fn query_name() -> Option<&'static str> {
        Some("getElectorState")
    }
    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        rq.validate()?;
        Ok(tos::rpc::engine::validator::GetElectorState {
            block: rq.block.clone(),
            wallets: rq.wallets.iter().map(|w| UInt256::from(*w)).collect(),
        }
        .into_tl_object())
    }
    fn deserialize_response(request: &Self::Rq, answer: TLObject) -> anyhow::Result<Self::Rs> {
        let response = Self::deserialize(answer)?;
        response.validate_request(request)?;
        Ok(response)
    }
    fn deserialize(answer: TLObject) -> anyhow::Result<Self::Rs> {
        downcast::<tos::engine::validator::ElectorState>(answer)?.only().try_into()
    }
}
pub(crate) struct GetConfigProposalsRqRs;
impl ToFromTL for GetConfigProposalsRqRs {
    type Rq = ConfigProposalsRequest;
    type Rs = ConfigProposals;
    fn query_name() -> Option<&'static str> {
        Some("getConfigProposals")
    }
    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        if let Some(block) = &rq.block {
            anyhow::ensure!(block.shard().is_masterchain(), "requested block is not masterchain");
        }
        Ok(tos::rpc::engine::validator::GetConfigProposals { block: rq.block.clone() }
            .into_tl_object())
    }
    fn deserialize_response(request: &Self::Rq, answer: TLObject) -> anyhow::Result<Self::Rs> {
        let response = Self::deserialize(answer)?;
        response.validate_request(request)?;
        Ok(response)
    }
    fn deserialize(answer: TLObject) -> anyhow::Result<Self::Rs> {
        downcast::<tos::engine::validator::ConfigProposals>(answer)?.only().try_into()
    }
}
pub(crate) struct GetConfigProposalRqRs;
impl ToFromTL for GetConfigProposalRqRs {
    type Rq = ConfigProposalRequest;
    type Rs = ConfigProposalDetail;
    fn query_name() -> Option<&'static str> {
        Some("getConfigProposal")
    }
    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        if let Some(block) = &rq.block {
            anyhow::ensure!(block.shard().is_masterchain(), "requested block is not masterchain");
        }
        Ok(tos::rpc::engine::validator::GetConfigProposal {
            block: rq.block.clone(),
            hash: UInt256::from(rq.hash),
        }
        .into_tl_object())
    }
    fn deserialize_response(request: &Self::Rq, answer: TLObject) -> anyhow::Result<Self::Rs> {
        let response = Self::deserialize(answer)?;
        response.validate_request(request)?;
        Ok(response)
    }
    fn deserialize(answer: TLObject) -> anyhow::Result<Self::Rs> {
        downcast::<tos::engine::validator::ConfigProposalDetail>(answer)?.only().try_into()
    }
}
