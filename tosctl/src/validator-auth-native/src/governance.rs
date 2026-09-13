use crate::registry::RegistryState;
use tos_validator_auth::{
    codec::{decode, encode, Error},
    context::{admin_session_id, make_duty, ChainContext},
    crypto::object_id,
    lifecycle::select_identity_keys,
    transfer::ObjectReader,
    types::*,
    verify::{key_reference, RegistrySnapshot, VerifiedCertificate},
};
/// The current governing committee and inclusion-time registry are independently
/// trusted native inputs. This does not replace voting rules or apply an update.
pub fn verify_current_governance<F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>>(
    chain: &ChainContext,
    governing: &RegistrySnapshot,
    current: &RegistryState,
    update: &Update,
    evidence: &Authorizations,
    inclusion: u32,
    reader: &mut ObjectReader<F>,
) -> Result<VerifiedCertificate, Error> {
    if !matches!(update.operation, 4 | 6) || update.identity != [0; 32] {
        return Err(Error("governance-target"));
    }
    if !evidence.owner.is_empty()
        || !evidence.possession.is_empty()
        || !evidence.administration.is_empty()
        || evidence.governance.len() != 1
    {
        return Err(Error("governance-authorizations"));
    }
    if current.coordinate() != inclusion || current.chain_domain() != &chain.chain_domain {
        return Err(Error("governance-current-state"));
    }
    if current.current_policy() != governing.policy_id() {
        return Err(Error("governance-current-policy"));
    }
    let committee = governing.committee();
    if committee.workchain != -1 || committee.shard != 1 << 63 {
        return Err(Error("governance-committee"));
    }
    let age = inclusion.checked_sub(committee.anchor_mc).ok_or(Error("admin-freshness"))?;
    if age > 128 {
        return Err(Error("admin-freshness"));
    }
    let auth = &evidence.governance[0];
    if auth.update_id != object_id("update", update)? || auth.committee != *governing.committee_id()
    {
        return Err(Error("governance-binding"));
    }
    let expected = make_duty(
        chain,
        governing,
        admin_session_id(chain, &[0; 32])?,
        5,
        update.nonce,
        &encode(update)?,
    )?;
    let certificate = decode::<Certificate>(&reader.resolve(&auth.certificate, 4)?)?;
    let verified = governing.verify_certificate(&certificate, &expected)?;
    for record in &certificate.records {
        let identity =
            current.identities.get(&record.identity).ok_or(Error("governance-current-identity"))?;
        let keys = select_identity_keys(identity, current, inclusion, &[(5, 1, 1)])?;
        let reference = key_reference(&keys[0])?;
        let component = &record.components[0];
        if reference
            != (Keyref {
                suite: component.suite,
                parameters: component.parameters,
                epoch: component.epoch,
                key_id: component.key_id,
            })
        {
            return Err(Error("governance-current-key"));
        }
    }
    Ok(verified)
}
