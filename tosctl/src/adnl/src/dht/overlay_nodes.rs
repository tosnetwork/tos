/*
 * Copyright (C) 2026 TOS Blockchain Teams.
 * Licensed under the GNU General Public License v3.0.
 */

use super::{DhtNode, DhtValue, OverlayNodeDescriptor, OverlayNodesDescriptor, OverlayUtils};
use chain_block::{fail, Result};
use rand::Rng;
use tl_api::{serialize_boxed, IntoBoxed};

// Match dht::DhtValue::max_value_size() in the native implementation.
pub(super) const MAX_OVERLAY_NODES_BYTES: usize = 768;

/// Merge already authenticated node records. The outer, unsigned TTL is only
/// retention metadata: it cannot override a node's own signed version.
pub(super) fn merge_overlay_nodes(
    old: Option<&DhtValue>,
    incoming: &DhtValue,
    verified_nodes: &[OverlayNodeDescriptor],
    now: i32,
) -> Result<DhtValue> {
    let old = old.filter(|value| value.ttl > now);
    let old_nodes = match old {
        // Oversized historical discovery cache entries are disposable, not
        // chain state. Do not deserialize an unbounded old list inside a retry.
        Some(value) if value.value.len() <= MAX_OVERLAY_NODES_BYTES => {
            DhtNode::deserialize_overlay_nodes(&value.value)?
        }
        _ => Vec::new(),
    };
    let mut merged: Vec<OverlayNodeDescriptor> = Vec::new();
    for node in old_nodes.iter().chain(verified_nodes.iter()) {
        if !OverlayUtils::node_version_is_fresh(node.version, now) {
            continue;
        }
        if let Some(previous) = merged.iter_mut().find(|previous| previous.id == node.id) {
            if node.version > previous.version {
                *previous = node.clone();
            }
            // An unchanged record must not cancel other records in the batch.
            continue;
        }
        merged.push(node.clone());
    }
    if merged.is_empty() {
        fail!("No fresh overlay nodes to store");
    }

    let mut result = incoming.clone();
    if let Some(old) = old {
        result.ttl = result.ttl.max(old.ttl);
    }
    loop {
        let bytes = serialize_boxed(&OverlayNodesDescriptor { nodes: merged.clone() }.into_boxed())?;
        if bytes.len() <= MAX_OVERLAY_NODES_BYTES {
            result.value = bytes.into();
            return Ok(result);
        }
        // As in the C++ DHT, bound the complete serialized list, not just the
        // incoming list. Random trimming avoids a permanent public-key bias.
        if merged.len() <= 1 {
            fail!("Overlay node cannot fit in the DHT value limit");
        }
        let index = rand::thread_rng().gen_range(0..merged.len());
        merged.swap_remove(index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_block::UInt256;
    use tl_api::tos::{
        dht::{key::Key, keydescription::KeyDescription, UpdateRule},
        pub_::publickey::Ed25519,
    };

    // Merge-only fixtures: cryptographic admission is tested separately by
    // receive_policy_tests. These records deliberately do not claim valid signatures.
    fn node(id: u8, version: i32, flags: i32) -> OverlayNodeDescriptor {
        OverlayNodeDescriptor {
            id: Ed25519 { key: UInt256::with_array([id; 32]) }.into_boxed(),
            overlay: UInt256::with_array([9; 32]),
            flags,
            version,
            signature: vec![0; 64].into(),
            certificate: Default::default(),
        }
    }

    fn value(nodes: Vec<OverlayNodeDescriptor>, ttl: i32) -> Result<DhtValue> {
        Ok(DhtValue {
            key: KeyDescription {
                id: tl_api::tos::pub_::publickey::Overlay { name: vec![9; 32].into() }.into_boxed(),
                key: Key { id: UInt256::with_array([9; 32]), idx: 0, name: b"nodes".to_vec().into() },
                update_rule: UpdateRule::Dht_UpdateRule_OverlayNodes,
                signature: Default::default(),
            },
            value: serialize_boxed(&OverlayNodesDescriptor { nodes }.into_boxed())?.into(),
            ttl,
            signature: Default::default(),
        })
    }

    #[test]
    fn unchanged_record_and_lower_outer_ttl_do_not_block_new_policy() -> Result<()> {
        let now = 1_800_000_000;
        let a = node(1, now - 10, 0);
        let b = node(2, now - 10, 0);
        let b_new = node(2, now, 2);
        let old = value(vec![a.clone(), b], now + 600)?;
        for incoming_nodes in [vec![a.clone(), b_new.clone()], vec![b_new.clone(), a.clone()]] {
            let incoming = value(incoming_nodes.clone(), now + 100)?;
            let merged = merge_overlay_nodes(Some(&old), &incoming, &incoming_nodes, now)?;
            assert_eq!(merged.ttl, old.ttl);
            let nodes = DhtNode::deserialize_overlay_nodes(&merged.value)?;
            assert_eq!(nodes.len(), 2);
            assert!(nodes.contains(&a));
            assert!(nodes.contains(&b_new));
        }
        Ok(())
    }

    #[test]
    fn duplicates_and_old_versions_cannot_undo_an_update() -> Result<()> {
        let now = 1_800_000_000;
        let current = node(1, now, 2);
        let older = node(1, now - 1, 0);
        let equal = node(1, now, 0);
        let fresh = node(2, now, 0);
        let old = value(vec![current.clone()], now + 100)?;
        let incoming_nodes = vec![older, equal, fresh.clone(), fresh.clone()];
        let incoming = value(incoming_nodes.clone(), now + 200)?;
        let merged = merge_overlay_nodes(Some(&old), &incoming, &incoming_nodes, now)?;
        let nodes = DhtNode::deserialize_overlay_nodes(&merged.value)?;
        assert_eq!(nodes.len(), 2);
        assert!(nodes.contains(&current));
        assert!(nodes.contains(&fresh));
        assert_eq!(merged.ttl, incoming.ttl);
        Ok(())
    }

    #[test]
    fn merged_value_is_bounded_and_expired_outer_value_is_discarded() -> Result<()> {
        let now = 1_800_000_000;
        let old_nodes = (1..=4).map(|id| node(id, now, 0)).collect::<Vec<_>>();
        let new_nodes = (5..=8).map(|id| node(id, now, 2)).collect::<Vec<_>>();
        let old = value(old_nodes, now + 100)?;
        let incoming = value(new_nodes.clone(), now + 100)?;
        assert!(old.value.len() <= MAX_OVERLAY_NODES_BYTES);
        assert!(incoming.value.len() <= MAX_OVERLAY_NODES_BYTES);
        let merged = merge_overlay_nodes(Some(&old), &incoming, &new_nodes, now)?;
        assert!(merged.value.len() <= MAX_OVERLAY_NODES_BYTES);
        assert!(!DhtNode::deserialize_overlay_nodes(&merged.value)?.is_empty());

        let mut expired = old;
        expired.ttl = now;
        let merged = merge_overlay_nodes(Some(&expired), &incoming, &new_nodes, now)?;
        assert_eq!(DhtNode::deserialize_overlay_nodes(&merged.value)?, new_nodes);
        Ok(())
    }

    #[test]
    fn cached_future_record_cannot_pin_policy_and_stale_records_are_removed() -> Result<()> {
        let now = 1_800_000_000;
        let valid = node(1, now, 0);
        let old = value(vec![node(1, i32::MAX, 2), node(2, now - 601, 0)], now + 600)?;
        let incoming_nodes = vec![valid.clone()];
        let incoming = value(incoming_nodes.clone(), now + 100)?;
        let merged = merge_overlay_nodes(Some(&old), &incoming, &incoming_nodes, now)?;
        assert_eq!(DhtNode::deserialize_overlay_nodes(&merged.value)?, vec![valid]);
        Ok(())
    }
}
