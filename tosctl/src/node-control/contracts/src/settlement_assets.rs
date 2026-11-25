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
    /// The data of the bridge account `-1:origin.bridge_address`.
    pub bridge_data: &'a Cell,
}

/// The minter and wallet code a token bridge creates its minters with: refs 0
/// and 1 of its storage, after `born:uint64 evm_chain:uint32 evm_bridge:uint160
/// generation:uint32 gen_start:uint64 gen_state:uint2 collector:MsgAddressInt`
/// (`load_data` in crosschain/token-bridge/tvm/contracts/token-bridge.fc).
pub fn bridge_codes(bridge_data: &Cell) -> anyhow::Result<(Cell, Cell)> {
    let mut slice = SliceData::load_cell(bridge_data.clone())?;
    slice.get_next_bits(64 + 32 + 160 + 32 + 64 + 2)?;
    let _collector: MsgAddressInt = chain_block::Deserializable::construct_from(&mut slice)?;
    anyhow::ensure!(
        slice.remaining_bits() == 0 && slice.remaining_references() == 3,
        "the bridge account's data is not a token bridge's storage"
    );
    Ok((slice.reference(0)?, slice.reference(1)?))
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
    // The bridge's own codes: a minter with any other code is not one this bridge
    // created, even if its storage names the bridge.
    let (bridge_minter_code, bridge_wallet_code) =
        bridge_codes(evidence.bridge_data).map_err(|err| {
            anyhow::anyhow!("master {master:x}: bridge {:x}: {err}", origin.bridge_address)
        })?;
    anyhow::ensure!(
        asset.minter_code_hash == bridge_minter_code.repr_hash()
            && asset.wallet_code_hash == bridge_wallet_code.repr_hash(),
        "master {master:x}: the recorded code hashes are not the bridge's minter and wallet code"
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
    // Step 1: the key is the canonical account id of the address the bridge derives,
    // with the bridge's own codes.
    let derived = minter_account_id(
        bridge_minter_code,
        minter_initial_data(expected_content, bridge_wallet_code, &bridge)?,
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

    /// A token bridge's storage holding `minter` and `wallet` as its codes.
    fn bridge_storage(minter: Cell, wallet: Cell) -> Cell {
        let mut b = BuilderData::new();
        zeros(&mut b, 64 + 32 + 160 + 32 + 64 + 2).unwrap();
        MsgAddressInt::with_standart(None, 0, UInt256::from([0x42; 32]).into())
            .unwrap()
            .write_to(&mut b)
            .unwrap();
        b.checked_append_reference(minter).unwrap();
        b.checked_append_reference(wallet).unwrap();
        b.checked_append_reference(leaf(0)).unwrap();
        b.into_cell().unwrap()
    }

    struct Synthetic {
        master: UInt256,
        asset: SettlementAsset,
        code: Cell,
        data: Cell,
        params: TokenBridgeParams,
        bridge_data: Cell,
    }

    struct Variation {
        chain: u32,
        content: Option<Cell>,
        stored_bridge: Option<UInt256>,
        /// The bridge's codes, when they are not the minter's own.
        bridge_codes: Option<(Cell, Cell)>,
    }

    const PLAIN: Variation =
        Variation { chain: 1, content: None, stored_bridge: None, bridge_codes: None };

    /// A minter whose record, code and data derive its own address exactly.
    fn synthetic(v: Variation) -> Synthetic {
        let origin = SettlementAssetOrigin {
            kind: SettlementAssetOriginKind::TokenBridge,
            bridge_address: UInt256::from([0x33; 32]),
            source_chain_id: v.chain,
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
        let stored = match v.stored_bridge {
            Some(other) => MsgAddressInt::with_standart(None, -1, other.into()).unwrap(),
            None => bridge,
        };
        let data =
            minter_initial_data(v.content.unwrap_or(expected), wallet.clone(), &stored).unwrap();
        let (bridge_minter, bridge_wallet) =
            v.bridge_codes.unwrap_or_else(|| (code.clone(), wallet.clone()));
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
        Synthetic {
            master,
            asset,
            code,
            data,
            params,
            bridge_data: bridge_storage(bridge_minter, bridge_wallet),
        }
    }

    fn check(s: &Synthetic) -> anyhow::Result<()> {
        verify_settlement_asset(
            &s.master,
            &s.asset,
            &MasterEvidence {
                code: &s.code,
                data: &s.data,
                bridge_params: &s.params,
                bridge_data: &s.bridge_data,
            },
        )
    }

    fn refusal(s: &Synthetic) -> String {
        check(s).expect_err("refused").to_string()
    }

    #[test]
    fn a_minter_built_with_the_bridges_own_codes_verifies() {
        check(&synthetic(PLAIN)).unwrap();
    }

    #[test]
    fn a_foreign_code_minter_that_names_the_real_bridge_is_refused() {
        // The minter, its record and its data agree with each other and name the
        // bridge, but the bridge creates its minters with other code.
        let s = synthetic(Variation { bridge_codes: Some((leaf(7), leaf(8))), ..PLAIN });
        assert!(refusal(&s).contains("not the bridge's minter and wallet code"));
        let s = synthetic(Variation { bridge_codes: Some((leaf(1), leaf(8))), ..PLAIN });
        assert!(refusal(&s).contains("not the bridge's minter and wallet code"));
        let s = synthetic(Variation { bridge_codes: Some((leaf(7), leaf(2))), ..PLAIN });
        assert!(refusal(&s).contains("not the bridge's minter and wallet code"));
    }

    #[test]
    fn a_bridge_whose_storage_does_not_parse_is_refused() {
        let mut s = synthetic(PLAIN);
        s.bridge_data = leaf(9);
        assert!(refusal(&s).contains("bridge"));
        s.bridge_data = {
            let fresh = synthetic(PLAIN);
            let mut extra = BuilderData::from_cell(&fresh.bridge_data).unwrap();
            extra.append_bit_zero().unwrap();
            extra.into_cell().unwrap()
        };
        assert!(refusal(&s).contains("not a token bridge's storage"));
    }

    #[test]
    fn a_source_chain_without_a_bridge_parameter_is_refused() {
        assert!(
            refusal(&synthetic(Variation { chain: 5, ..PLAIN }))
                .contains("no token bridge parameter")
        );
        assert_eq!(bridge_config_param(5), None);
        assert_eq!(bridge_config_param(728126428), Some(83));
    }

    #[test]
    fn minter_content_that_differs_from_the_record_is_refused() {
        let mut b = BuilderData::new();
        b.append_u32(1).unwrap();
        b.append_raw(&[0x44; 20], 160).unwrap();
        b.append_u8(18).unwrap();
        let s = synthetic(Variation { content: Some(b.into_cell().unwrap()), ..PLAIN });
        assert!(refusal(&s).contains("minter content"));
    }

    #[test]
    fn a_minter_driven_by_another_bridge_is_refused() {
        let s = synthetic(Variation { stored_bridge: Some(UInt256::from([0x66; 32])), ..PLAIN });
        assert!(refusal(&s).contains("is driven by"));
    }
}
