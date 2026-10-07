// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Exact ConfigParam 48 v1 decoding. Callers must bind its proof checkpoint.
use chain_block::{Cell, CellType, HashmapE, HashmapType, SliceData};

pub(crate) fn require_primary(cell: &Cell, network: &[u8; 32], now: u32) -> anyhow::Result<()> {
    anyhow::ensure!(
        cell.cell_type() == CellType::Ordinary && cell.level() == 0,
        "ordinary retirement policy required"
    );
    let mut s = SliceData::load_cell(cell.clone())?;
    anyhow::ensure!(s.get_next_byte()? == 0xa1, "retirement policy version");
    anyhow::ensure!(s.get_next_hash()?.as_array() == network, "retirement policy network mismatch");
    s.get_next_u64()?; // Sequence is authenticated; transitions are enforced by governance.
    let retired = s.get_next_u16()?;
    anyhow::ensure!(retired & !2 == 0, "unknown retirement bits");
    let root = s.get_next_dictionary()?;
    anyhow::ensure!(
        s.get_next_hash()?.to_hex_string()
            == "5e4380aedc95f8cb72de55f7506de0269b47c03ad1d1ed0e5184c332544262c0",
        "retirement specification mismatch"
    );
    anyhow::ensure!(
        s.remaining_bits() == 0 && s.remaining_references() == 0,
        "retirement policy trailing data"
    );
    let mut deadline = 0;
    if let Some(root) = root {
        anyhow::ensure!(
            root.cell_type() == CellType::Ordinary && root.level() == 0,
            "ordinary retirement schedule required"
        );
        let dict = HashmapE::with_hashmap(8, Some(root));
        let mut seen = false;
        dict.iterate_slices(|mut key, mut entry| {
            anyhow::ensure!(!seen && key.get_next_byte()? == 1, "unsupported retirement schedule");
            seen = true;
            anyhow::ensure!(
                entry.remaining_bits() == 32 && entry.remaining_references() == 0,
                "retirement deadline shape"
            );
            deadline = entry.get_next_u32()?;
            anyhow::ensure!(deadline > 0, "zero retirement deadline");
            Ok(true)
        })?;
        anyhow::ensure!(seen, "empty retirement schedule root");
    }
    anyhow::ensure!(retired & 2 == 0 && (deadline == 0 || now < deadline), "primary suite retired");
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use chain_block::{BuilderData, IBitstring, Serializable};
    pub(crate) fn policy(
        network: [u8; 32],
        retired: u16,
        schedule: &[(u8, u32)],
        valid_spec: bool,
    ) -> Cell {
        let mut d = HashmapE::with_bit_len(8);
        for (suite, time) in schedule {
            let mut k = BuilderData::new();
            k.append_u8(*suite).unwrap();
            let mut v = BuilderData::new();
            v.append_u32(*time).unwrap();
            d.set(SliceData::load_builder(k).unwrap(), &SliceData::load_builder(v).unwrap())
                .unwrap();
        }
        let mut b = BuilderData::new();
        b.append_u8(0xa1).unwrap();
        b.append_u256(&network).unwrap();
        b.append_u64(7).unwrap();
        b.append_u16(retired).unwrap();
        d.write_to(&mut b).unwrap();
        let spec: [u8; 32] = if valid_spec {
            hex::decode("5e4380aedc95f8cb72de55f7506de0269b47c03ad1d1ed0e5184c332544262c0")
                .unwrap()
                .try_into()
                .unwrap()
        } else {
            [0; 32]
        };
        b.append_u256(&spec).unwrap();
        b.into_cell().unwrap()
    }
    #[test]
    fn primary_policy_strict_retirement() {
        assert!(require_primary(&policy([1; 32], 0, &[], true), &[1; 32], 4620).is_ok());
        assert!(require_primary(&policy([1; 32], 0, &[(1, 4621)], true), &[1; 32], 4620).is_ok());
        for (network, retired, schedule, spec, reason) in [
            ([2; 32], 0, vec![], true, "network"),
            ([1; 32], 2, vec![], true, "retired"),
            ([1; 32], 4, vec![], true, "unknown retirement bits"),
            ([1; 32], 0, vec![(1, 4620)], true, "retired"),
            ([1; 32], 0, vec![(1, 4619)], true, "retired"),
            ([1; 32], 0, vec![(2, 4700)], true, "unsupported"),
            ([1; 32], 0, vec![(1, 4700), (2, 4800)], true, "unsupported"),
            ([1; 32], 0, vec![(1, 0)], true, "zero retirement deadline"),
            ([1; 32], 0, vec![], false, "specification"),
        ] {
            match require_primary(&policy(network, retired, &schedule, spec), &[1; 32], 4620) {
                Ok(_) => panic!("accepted invalid primary policy: {reason}"),
                Err(e) => assert!(e.to_string().contains(reason), "{reason}: {e}"),
            }
        }
    }
}
