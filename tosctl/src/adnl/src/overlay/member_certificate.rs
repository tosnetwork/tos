/*
 * Copyright (C) 2026 TOS Blockchain Teams.
 * Licensed under the GNU General Public License v3.0.
 */

use crate::common::add_unbound_object_to_map_with_update;
use chain_block::{fail, KeyId, KeyOption, Result, UInt256};
use std::{collections::HashMap, convert::TryInto, sync::Arc};
use tl_api::{
    serialize_boxed,
    tos::{
        adnl::id::short::Short as AdnlShortId,
        overlay::{membercertificate::MemberCertificate, membercertificateid::MemberCertificateId},
    },
    IntoBoxed,
};

pub(super) struct SlaveInfo {
    node_id: Arc<KeyId>,
    // Cache the complete authenticated certificate, not just its expiry and owner.
    certificate: MemberCertificate,
}

pub(super) type RootMembers = HashMap<Arc<KeyId>, lockfree::map::Map<u32, SlaveInfo>>;

fn check_slot_order(peer: &Arc<KeyId>, cert: &MemberCertificate, old: &SlaveInfo) -> Result<()> {
    if cert.expire_at < old.certificate.expire_at {
        fail!("Certificate rejected, because we know of newer one at the same slot");
    }
    if cert.expire_at == old.certificate.expire_at
        && UInt256::from_slice(peer.data()) < UInt256::from_slice(old.node_id.data())
    {
        fail!("Certificate rejected, because we know another one at the same slot");
    }
    Ok(())
}

pub(super) fn validate_member_certificate(
    root_members: &RootMembers,
    max_slaves: usize,
    peer: &Arc<KeyId>,
    cert: &MemberCertificate,
    now: u32,
) -> Result<()> {
    // The TL field is signed. Casting a negative expiry to u32 would make an
    // already expired certificate appear valid until close to 2106.
    if i64::from(cert.expire_at) < i64::from(now) - 3 {
        fail!("Certificate is expired, expire_at: {}, current time: {}", cert.expire_at, now);
    }
    if cert.slot < 0 || cert.slot as usize >= max_slaves {
        fail!("Certificate has invalid slot: {}", cert.slot);
    }
    let issuer: Arc<dyn KeyOption> = (&cert.issued_by).try_into()?;
    let Some(slaves) = root_members.get(issuer.id()) else {
        fail!("Certificate is issued by unknown member: {}", cert.issued_by);
    };
    let slot = cert.slot as u32;
    if let Some(guard) = slaves.get(&slot) {
        let old = guard.val();
        check_slot_order(peer, cert, old)?;
        if old.node_id == *peer && &old.certificate == cert {
            return Ok(());
        }
    }

    let signed = MemberCertificateId {
        node: AdnlShortId { id: UInt256::with_array(*peer.data()) },
        flags: cert.flags,
        slot: cert.slot,
        expire_at: cert.expire_at,
    }
    .into_boxed();
    issuer.verify(&serialize_boxed(&signed)?, &cert.signature)?;

    // This callback can be retried by the lock-free map. Recheck the current
    // winner here; an earlier snapshot must not overwrite a concurrent renewal.
    add_unbound_object_to_map_with_update(slaves, slot, |old| {
        if let Some(old) = old {
            check_slot_order(peer, cert, old)?;
            if old.node_id == *peer && &old.certificate == cert {
                return Ok(None);
            }
        }
        Ok(Some(SlaveInfo { node_id: peer.clone(), certificate: cert.clone() }))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_block::Ed25519KeyOption;

    fn signed_certificate(
        issuer: &Arc<dyn KeyOption>,
        peer: &Arc<KeyId>,
        expiry: i32,
        flags: i32,
    ) -> Result<MemberCertificate> {
        let signed = MemberCertificateId {
            node: AdnlShortId { id: UInt256::with_array(*peer.data()) },
            flags,
            slot: 0,
            expire_at: expiry,
        }
        .into_boxed();
        Ok(MemberCertificate {
            issued_by: issuer.try_into()?,
            flags,
            slot: 0,
            expire_at: expiry,
            signature: issuer.sign(&serialize_boxed(&signed)?)?.into(),
        })
    }

    #[test]
    fn cached_tuple_does_not_authenticate_changed_certificate() -> Result<()> {
        let issuer = Ed25519KeyOption::generate()?;
        let peer = Ed25519KeyOption::generate()?;
        let roots = HashMap::from([(issuer.id().clone(), lockfree::map::Map::new())]);
        let now = 1_800_000_000;
        let valid = signed_certificate(&issuer, peer.id(), now as i32 + 100, 0)?;
        validate_member_certificate(&roots, 1, peer.id(), &valid, now)?;
        validate_member_certificate(&roots, 1, peer.id(), &valid, now)?;

        let mut forged = valid.clone();
        forged.flags ^= 1;
        assert!(validate_member_certificate(&roots, 1, peer.id(), &forged, now).is_err());
        forged = valid.clone();
        forged.signature[0] ^= 1;
        assert!(validate_member_certificate(&roots, 1, peer.id(), &forged, now).is_err());
        assert_eq!(roots.get(issuer.id()).unwrap().get(&0).unwrap().val().certificate, valid);
        Ok(())
    }

    #[test]
    fn renewal_is_validated_and_cannot_be_rolled_back() -> Result<()> {
        let issuer = Ed25519KeyOption::generate()?;
        let peer = Ed25519KeyOption::generate()?;
        let roots = HashMap::from([(issuer.id().clone(), lockfree::map::Map::new())]);
        let now = 1_800_000_000;
        let old = signed_certificate(&issuer, peer.id(), now as i32 + 100, 0)?;
        let new = signed_certificate(&issuer, peer.id(), now as i32 + 200, 1)?;
        validate_member_certificate(&roots, 1, peer.id(), &old, now)?;
        validate_member_certificate(&roots, 1, peer.id(), &new, now)?;
        assert!(validate_member_certificate(&roots, 1, peer.id(), &old, now).is_err());
        assert_eq!(roots.get(issuer.id()).unwrap().get(&0).unwrap().val().certificate, new);
        Ok(())
    }

    #[test]
    fn negative_expiry_and_wrong_owner_are_rejected() -> Result<()> {
        let issuer = Ed25519KeyOption::generate()?;
        let peer = Ed25519KeyOption::generate()?;
        let other = Ed25519KeyOption::generate()?;
        let roots = HashMap::from([(issuer.id().clone(), lockfree::map::Map::new())]);
        let now = 1_800_000_000;
        let expired = signed_certificate(&issuer, peer.id(), -1, 0)?;
        assert!(validate_member_certificate(&roots, 1, peer.id(), &expired, now).is_err());
        let valid = signed_certificate(&issuer, peer.id(), now as i32 + 100, 0)?;
        assert!(validate_member_certificate(&roots, 1, other.id(), &valid, now).is_err());
        assert!(roots.get(issuer.id()).unwrap().get(&0).is_none());
        Ok(())
    }
}
