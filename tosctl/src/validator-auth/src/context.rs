use crate::{
    codec::{decode, encode, Error, Hash},
    crypto::{digest, object_id, AdmittedKey},
    types::*,
    verify::{key_reference, signing_statement, validate_payload, RegistrySnapshot},
};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainContext {
    pub network: i32,
    pub genesis_root: Hash,
    pub genesis_file: Hash,
    pub chain_domain: Hash,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionOrigin {
    pub native_options_hash: Hash,
    pub vertical_seqno: u32,
    pub key_block_seqno: u32,
}
fn chain(context: &ChainContext) -> Result<(), Error> {
    if context.genesis_root == [0; 32]
        || context.genesis_file == [0; 32]
        || context.chain_domain == [0; 32]
    {
        return Err(Error("chain-context"));
    }
    Ok(())
}
fn prefix(context: &ChainContext) -> Result<Vec<u8>, Error> {
    chain(context)?;
    let mut bytes = Vec::with_capacity(68);
    bytes.extend_from_slice(&context.network.to_be_bytes());
    bytes.extend_from_slice(&context.genesis_root);
    bytes.extend_from_slice(&context.genesis_file);
    Ok(bytes)
}
pub fn session_id(
    context: &ChainContext,
    snapshot: &RegistrySnapshot,
    origin: &SessionOrigin,
) -> Result<Hash, Error> {
    let mut bytes = prefix(context)?;
    bytes.extend_from_slice(snapshot.committee_id());
    bytes.extend_from_slice(&origin.native_options_hash);
    bytes.extend_from_slice(&origin.vertical_seqno.to_be_bytes());
    bytes.extend_from_slice(&origin.key_block_seqno.to_be_bytes());
    digest("session", &bytes)
}
pub fn admin_session_id(context: &ChainContext, target: &Hash) -> Result<Hash, Error> {
    let mut bytes = prefix(context)?;
    bytes.extend_from_slice(target);
    digest("admin-session", &bytes)
}
pub fn make_duty(
    context: &ChainContext,
    snapshot: &RegistrySnapshot,
    session: Hash,
    role: u8,
    position: u64,
    payload: &[u8],
) -> Result<Duty, Error> {
    if payload.len() > 4096 {
        return Err(Error("payload-bound"));
    }
    chain(context)?;
    if session == [0; 32] {
        return Err(Error("session"));
    }
    let mut bytes = Vec::with_capacity(1 + payload.len());
    bytes.push(role);
    bytes.extend_from_slice(payload);
    let duty = Duty {
        network: context.network,
        genesis_root: context.genesis_root,
        genesis_file: context.genesis_file,
        policy: *snapshot.policy_id(),
        committee: *snapshot.committee_id(),
        session,
        workchain: if role == 5 { -1 } else { snapshot.committee().workchain },
        shard: if role == 5 { 1 << 63 } else { snapshot.committee().shard },
        anchor_mc: snapshot.committee().anchor_mc,
        catchain: snapshot.committee().catchain,
        position,
        role,
        payload_hash: digest("payload", &bytes)?,
    };
    validate_payload(&duty, payload)?;
    Ok(duty)
}
pub fn possession_preimage(
    context: &ChainContext,
    update: &Update,
    key: &Key,
) -> Result<Vec<u8>, Error> {
    if context.chain_domain == [0; 32] {
        return Err(Error("chain-domain"));
    }
    let raw = encode(update)?;
    let key_id = object_id("key", key)?;
    if raw.len() > 32768 {
        return Err(Error("blob-bound"));
    }
    let mut bytes = b"TOS/P0/pop/v1\0".to_vec();
    bytes.extend_from_slice(&context.network.to_be_bytes());
    bytes.extend_from_slice(&context.chain_domain);
    bytes.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&raw);
    bytes.extend_from_slice(&key_id);
    Ok(bytes)
}
pub fn verify_possession(
    context: &ChainContext,
    update: &Update,
    key: &Key,
    proof: &PossessionAuth,
) -> Result<(), Error> {
    if !matches!(update.operation, 1 | 2)
        || update.identity != key.identity
        || key.suite != 1
        || key.parameters != 1
        || !(1..=5).contains(&key.role)
        || key.capacity_domain != [0; 32]
        || key.capacity_limit != 0
    {
        return Err(Error("possession-key"));
    }
    if update.new_key != encode(key)? {
        return Err(Error("possession-key"));
    }
    if proof.update_id != object_id("update", update)? || proof.key != key_reference(key)? {
        return Err(Error("possession-binding"));
    }
    let admitted = AdmittedKey::admit(&key.public_key)?;
    let preimage = possession_preimage(context, update, key)?;
    if !admitted.verify(&preimage, &proof.signature) {
        return Err(Error("possession-signature"));
    }
    Ok(())
}
/// Only the target's currently active role-5 keys confer identity authority.
/// This does not grant governance weight or reuse retired session authority.
pub fn verify_identity_certificate(
    certificate: &Certificate,
    expected: &Duty,
    identity: &Identity,
    keys: &[Key],
    inclusion: u32,
) -> Result<(), Error> {
    if encode(certificate)?.len() > 524288 {
        return Err(Error("certificate-budget"));
    }
    let age = inclusion.checked_sub(expected.anchor_mc).ok_or(Error("admin-freshness"))?;
    if age > 128 {
        return Err(Error("admin-freshness"));
    }
    if certificate.duty != *expected
        || expected.role != 5
        || expected.workchain != -1
        || expected.shard != 1 << 63
    {
        return Err(Error("identity-context"));
    }
    validate_payload(expected, &certificate.payload)?;
    let update = decode::<Update>(&certificate.payload)?;
    if update.identity != identity.identity {
        return Err(Error("identity-target"));
    }
    if certificate.records.len() != 1
        || certificate.records[0].identity != identity.identity
        || keys.len() != 1
        || certificate.records[0].components.len() != 1
    {
        return Err(Error("identity-components"));
    }
    let key = &keys[0];
    let component = &certificate.records[0].components[0];
    if key.valid_from > inclusion
        || key.valid_until <= inclusion
        || key.epoch == 0
        || key.identity != identity.identity
        || key.role != 5
        || key.suite != 1
        || key.parameters != 1
    {
        return Err(Error("identity-key"));
    }
    let reference = key_reference(key)?;
    let active = identity.active.iter().any(|r| r.role == 5 && r.key == reference);
    let signed = Keyref {
        suite: component.suite,
        parameters: component.parameters,
        epoch: component.epoch,
        key_id: component.key_id,
    };
    if !active || reference != signed {
        return Err(Error("identity-key-binding"));
    }
    let admitted = AdmittedKey::admit(&key.public_key)?;
    let statement = signing_statement(expected, &certificate.records[0])?;
    if !admitted.verify(&statement, &component.signature) {
        return Err(Error("identity-signature"));
    }
    Ok(())
}
