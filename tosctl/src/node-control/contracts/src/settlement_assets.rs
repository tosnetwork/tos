/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Reader-side checks for ConfigParam 84 (recognized settlement assets).
//!
//! A ConfigParam 84 record of origin kind 1 names a minter created by the TOS
//! token bridge. A reader does not take the record's word for that: it
//! re-derives the master's address from the record and the master's own
//! account state exactly as the bridge does, and refuses any mismatch. A vote
//! can therefore recognize only a minter that the bridge actually created.
//!
//! The derivation mirrors `calculate_minter_address` in
//! `crosschain/token-bridge/tvm/contracts/token-bridge.fc` and
//! `pack_minter_initial_data` in `crosschain/token-bridge/tvm/contracts/utils.fc`.

use chain_block::{
    AccountId, BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, SettlementAsset,
    SettlementAssetOrigin, SettlementAssetOriginKind, SliceData, TokenBridgeParams, UInt256,
};

/// The workchain every bridge minter, and so every recognized master, lives on.
pub const MASTER_WORKCHAIN: i32 = 0;
/// The workchain the token bridge itself lives on.
pub const BRIDGE_WORKCHAIN: i32 = -1;

/// The bridge ConfigParam that serves a source chain, as fixed by the bridge
/// parameter files under `crosschain/token-bridge/tvm/params/`.
pub fn bridge_config_param(source_chain_id: u32) -> Option<u32> {
    match source_chain_id {
        1 => Some(79),         // Ethereum
        56 => Some(81),        // BNB Smart Chain
        137 => Some(82),       // Polygon
        728126428 => Some(83), // Tron
        _ => None,
    }
}

/// The minter content cell the bridge derives a master from:
/// `chain_id:uint32 token_address:uint160 decimals:uint8`.
pub fn wrapped_token_data(origin: &SettlementAssetOrigin, decimals: u8) -> anyhow::Result<Cell> {
    let mut b = BuilderData::new();
    b.append_u32(origin.source_chain_id)?;
    b.append_raw(&origin.source_token, 160)?;
    b.append_u8(decimals)?;
    b.into_cell()
}

/// Appends `bits` zero bits.
fn zeros(b: &mut BuilderData, bits: usize) -> anyhow::Result<()> {
    let bytes = vec![0u8; bits.div_ceil(8)];
    b.append_raw(&bytes, bits)?;
    Ok(())
}

/// `pack_minter_initial_data(content, token_wallet_code, bridge_address)`.
pub fn minter_initial_data(
    content: Cell,
    wallet_code: Cell,
    bridge: &MsgAddressInt,
) -> anyhow::Result<Cell> {
    let mut tail = BuilderData::new();
    bridge.write_to(&mut tail)?;
    zeros(&mut tail, 64 + 64 + 1)?; // bridge_life, born_lt, terminal
    zeros(&mut tail, 64 + 64)?; // mint_watermark, mint_compaction
    zeros(&mut tail, 64 + 64)?; // next_notice, bridge_burn_ack
    zeros(&mut tail, 32)?; // holders_count
    zeros(&mut tail, 3)?; // mints, notices, holders: empty dictionaries
    let mut data = BuilderData::new();
    zeros(&mut data, 128)?; // total_supply
    zeros(&mut data, 4 * 4)?; // in_flight, mint_reserve, burn_reserve, stranded: Coins 0
    data.checked_append_reference(content)?;
    data.checked_append_reference(wallet_code)?;
    data.checked_append_reference(tail.into_cell()?)?;
    data.into_cell()
}

/// The account id `calculate_minter_address` gives for these code and data:
/// the hash of `StateInit{code, data}` without split depth, special or library.
pub fn minter_account_id(minter_code: Cell, data: Cell) -> anyhow::Result<UInt256> {
    let mut init = BuilderData::new();
    zeros(&mut init, 2)?; // split_depth, special: none
    init.append_bit_one()?;
    init.checked_append_reference(minter_code)?;
    init.append_bit_one()?;
    init.checked_append_reference(data)?;
    init.append_bit_zero()?; // library: empty
    Ok(init.into_cell()?.repr_hash())
}

/// What a reader fetched from finalized state to check one record, all at one
/// masterchain block.
pub struct MasterEvidence<'a> {
    /// The master account's code.
    pub code: &'a Cell,
    /// The master account's data.
    pub data: &'a Cell,
    /// The bridge ConfigParam of the record's source chain (79, 81, 82 or 83).
    pub bridge_params: &'a TokenBridgeParams,
}

/// Re-derives the master from the record and its evidence and refuses any
/// mismatch (USDC settlement design 3.1, steps 1-3).
pub fn verify_settlement_asset(
    master: &UInt256,
    asset: &SettlementAsset,
    evidence: &MasterEvidence<'_>,
) -> anyhow::Result<()> {
    let origin = &asset.origin;
    anyhow::ensure!(
        origin.kind == SettlementAssetOriginKind::TokenBridge,
        "master {master:x}: origin kind {} has no verification rule; refuse it",
        origin.kind.name()
    );
    anyhow::ensure!(
        bridge_config_param(origin.source_chain_id).is_some(),
        "master {master:x}: source chain {} has no token bridge parameter",
        origin.source_chain_id
    );
    // Step 2: the master runs the recorded minter code.
    anyhow::ensure!(
        evidence.code.repr_hash() == asset.minter_code_hash,
        "master {master:x}: its code hash {:x} is not the recorded minter code hash {:x}",
        evidence.code.repr_hash(),
        asset.minter_code_hash
    );
    // The minter's storage: content, wallet code, then the bridge block.
    let data = evidence.data;
    anyhow::ensure!(
        data.references_count() == 3,
        "master {master:x}: account data is not a token minter's storage"
    );
    let content = data.reference(0)?;
    let wallet_code = data.reference(1)?;
    let mut bridge_block = SliceData::load_cell(data.reference(2)?)?;
    // Step 2: get_wrapped_token_data equals the origin, and the content's decimals
    // are the recorded decimals.
    let expected_content = wrapped_token_data(origin, asset.decimals)?;
    anyhow::ensure!(
        content.repr_hash() == expected_content.repr_hash(),
        "master {master:x}: minter content (chain id, token, decimals) differs from the record"
    );
    // Step 1: the wallet code preimage is checked against the recorded hash.
    anyhow::ensure!(
        wallet_code.repr_hash() == asset.wallet_code_hash,
        "master {master:x}: its wallet code hash {:x} is not the recorded wallet code hash {:x}",
        wallet_code.repr_hash(),
        asset.wallet_code_hash
    );
    let bridge = MsgAddressInt::with_standart(
        None,
        BRIDGE_WORKCHAIN as i8,
        AccountId::from(origin.bridge_address.clone()),
    )?;
    let stored_bridge: MsgAddressInt =
        chain_block::Deserializable::construct_from(&mut bridge_block)
            .map_err(|err| anyhow::anyhow!("master {master:x}: minter bridge address: {err}"))?;
    anyhow::ensure!(
        stored_bridge == bridge,
        "master {master:x}: the minter is driven by {stored_bridge}, not the recorded bridge {bridge}"
    );
    // Step 1: the key is the canonical account id of the derived address.
    let derived = minter_account_id(
        evidence.code.clone(),
        minter_initial_data(expected_content, wallet_code, &bridge)?,
    )?;
    anyhow::ensure!(
        &derived == master,
        "master {master:x}: the record derives {MASTER_WORKCHAIN}:{derived:x}, not the listed master"
    );
    // Step 3: the source chain's bridge ConfigParam names the recorded bridge.
    anyhow::ensure!(
        evidence.bridge_params.bridge_address.clone().get_next_hash()? == origin.bridge_address,
        "master {master:x}: the bridge ConfigParam for chain {} names another bridge",
        origin.source_chain_id
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_block::{Coins, SettlementAssetStatus};

    fn leaf(byte: u8) -> Cell {
        let mut b = BuilderData::new();
        b.append_u8(byte).unwrap();
        b.into_cell().unwrap()
    }

    struct Synthetic {
        master: UInt256,
        asset: SettlementAsset,
        code: Cell,
        data: Cell,
        params: TokenBridgeParams,
    }

    /// A minter state built to derive exactly; `content` and `stored_bridge`
    /// replace what the account data holds without changing the derivation.
    fn synthetic(chain: u32, content: Option<Cell>, stored_bridge: Option<UInt256>) -> Synthetic {
        let origin = SettlementAssetOrigin {
            kind: SettlementAssetOriginKind::TokenBridge,
            bridge_address: UInt256::from([0x33; 32]),
            source_chain_id: chain,
            source_token: [0x44; 20],
        };
        let code = leaf(1);
        let wallet = leaf(2);
        let bridge =
            MsgAddressInt::with_standart(None, -1, origin.bridge_address.clone().into()).unwrap();
        let expected = wrapped_token_data(&origin, 6).unwrap();
        let master = minter_account_id(
            code.clone(),
            minter_initial_data(expected.clone(), wallet.clone(), &bridge).unwrap(),
        )
        .unwrap();
        let stored = match stored_bridge {
            Some(other) => MsgAddressInt::with_standart(None, -1, other.into()).unwrap(),
            None => bridge,
        };
        let data =
            minter_initial_data(content.unwrap_or(expected), wallet.clone(), &stored).unwrap();
        let params = TokenBridgeParams {
            bridge_address: origin.bridge_address.clone().into(),
            oracles_address: UInt256::default().into(),
            oracles: Default::default(),
            state_flags: 0,
            prices: Default::default(),
            external_chain_address: UInt256::default().into(),
        };
        let asset = SettlementAsset {
            status: SettlementAssetStatus::Active,
            decimals: 6,
            minter_code_hash: code.repr_hash(),
            wallet_code_hash: wallet.repr_hash(),
            max_liability_per_actor: Coins::from(1u64),
            origin,
        };
        Synthetic { master, asset, code, data, params }
    }

    fn check(s: &Synthetic) -> anyhow::Result<()> {
        verify_settlement_asset(
            &s.master,
            &s.asset,
            &MasterEvidence { code: &s.code, data: &s.data, bridge_params: &s.params },
        )
    }

    #[test]
    fn a_consistent_synthetic_minter_verifies() {
        check(&synthetic(1, None, None)).unwrap();
    }

    #[test]
    fn a_source_chain_without_a_bridge_parameter_is_refused() {
        assert!(check(&synthetic(5, None, None)).is_err());
        assert_eq!(bridge_config_param(5), None);
        assert_eq!(bridge_config_param(728126428), Some(83));
    }

    #[test]
    fn minter_content_that_differs_from_the_record_is_refused() {
        let mut b = BuilderData::new();
        b.append_u32(1).unwrap();
        b.append_raw(&[0x44; 20], 160).unwrap();
        b.append_u8(18).unwrap();
        assert!(check(&synthetic(1, Some(b.into_cell().unwrap()), None)).is_err());
    }

    #[test]
    fn a_minter_driven_by_another_bridge_is_refused() {
        assert!(check(&synthetic(1, None, Some(UInt256::from([0x66; 32])))).is_err());
    }
}
