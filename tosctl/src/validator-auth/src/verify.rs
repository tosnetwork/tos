use crate::{
    codec::{decode, encode, Error, Hash},
    crypto::{digest, object_id, AdmittedKey},
    types::*,
};
use std::collections::{BTreeMap, BTreeSet};
pub const MAX_WEIGHT: u64 = u64::MAX / 3;
pub fn key_reference(k: &Key) -> Result<Keyref, Error> {
    Ok(Keyref {
        suite: k.suite,
        parameters: k.parameters,
        epoch: k.epoch,
        key_id: object_id("key", k)?,
    })
}
pub fn signing_statement(duty: &Duty, record: &Record) -> Result<Vec<u8>, Error> {
    encode(&Statement {
        duty: duty.clone(),
        identity: record.identity,
        keys: record
            .components
            .iter()
            .map(|c| Keyref {
                suite: c.suite,
                parameters: c.parameters,
                epoch: c.epoch,
                key_id: c.key_id,
            })
            .collect(),
    })
}
pub fn validate_payload(duty: &Duty, payload: &[u8]) -> Result<(), Error> {
    let mut bytes = vec![duty.role];
    bytes.extend_from_slice(payload);
    if digest("payload", &bytes)? != duty.payload_hash {
        return Err(Error("payload-hash"));
    }
    if duty.role == 5 {
        let intent = decode::<Update>(payload)?;
        if !(1..=7).contains(&intent.operation) || intent.nonce != duty.position {
            return Err(Error("admin-payload"));
        }
        return Ok(());
    }
    if !(1..=4).contains(&duty.role) || duty.position > u32::MAX as u64 {
        return Err(Error("role-position"));
    }
    let candidate = [0x3f, 0xcd, 0x91, 0xb6];
    let notarize = [0xa8, 0x05, 0xf6, 0xcd];
    let finalize = [0x05, 0xe1, 0xa7, 0x40];
    let skip = [0x26, 0x1f, 0x6b, 0x2f];
    let (size, prefix, offset) = match duty.role {
        1 => (40, candidate, 4),
        2 => (44, notarize, 8),
        3 => (44, finalize, 8),
        _ => (8, skip, 4),
    };
    if payload.len() != size || payload[..4] != prefix {
        return Err(Error("payload-type"));
    }
    if offset == 8 && payload[4..8] != candidate {
        return Err(Error("payload-type"));
    }
    let mut slot = [0; 4];
    slot.copy_from_slice(&payload[offset..offset + 4]);
    if u64::from(u32::from_le_bytes(slot)) != duty.position {
        return Err(Error("payload-position"));
    }
    Ok(())
}
#[derive(Clone, Debug)]
struct Entry {
    member: Member,
    references: Vec<Keyref>,
    keys: Vec<AdmittedKey>,
}
#[derive(Clone, Debug)]
pub struct RegistrySnapshot {
    committee: Committee,
    policy: Policy,
    committee_id: Hash,
    policy_id: Hash,
    roster: BTreeMap<Hash, Entry>,
    total: u64,
}
#[derive(Clone, Debug)]
pub struct VerifiedCertificate {
    certificate_id: Hash,
    duty: Duty,
    signers: Vec<Hash>,
    weight: u64,
}
impl VerifiedCertificate {
    pub fn certificate_id(&self) -> &Hash {
        &self.certificate_id
    }
    pub fn duty(&self) -> &Duty {
        &self.duty
    }
    pub fn signers(&self) -> &[Hash] {
        &self.signers
    }
    pub fn weight(&self) -> u64 {
        self.weight
    }
}
impl RegistrySnapshot {
    /// Admission validates the roster; native state proofs establish its authority.
    pub fn compile(committee: &Committee, policy: &Policy) -> Result<Self, Error> {
        if policy.phase != 0 || policy.suites != [Suite { suite: 1, parameters: 1 }] {
            return Err(Error("unsupported-profile"));
        }
        if policy.interface_digest != INTERFACE_FINGERPRINT {
            return Err(Error("interface-digest"));
        }
        if policy.revision == 0
            || policy.max_envelope != 4096
            || policy.max_certificate != 524288
            || policy.effective_from > committee.anchor_mc
        {
            return Err(Error("c0-policy"));
        }
        let policy_id = object_id("policy", policy)?;
        let committee_id = object_id("committee", committee)?;
        if committee.policy != policy_id {
            return Err(Error("registry-policy"));
        }
        if committee.members.is_empty() || committee.members.len() > 400 {
            return Err(Error("registry-bound"));
        }
        let mut out = Self {
            committee: committee.clone(),
            policy: policy.clone(),
            committee_id,
            policy_id,
            roster: BTreeMap::new(),
            total: 0,
        };
        let mut previous = [0; 32];
        let mut stakes = BTreeSet::new();
        for m in &committee.members {
            if m.identity <= previous || m.stake_id == [0; 32] || !stakes.insert(m.stake_id) {
                return Err(Error("registry-identities"));
            }
            previous = m.identity;
            let total = out.total.checked_add(m.weight).ok_or(Error("weight"))?;
            if m.weight == 0 || total > MAX_WEIGHT {
                return Err(Error("weight"));
            }
            out.total = total;
            if m.keys.len() != 5 {
                return Err(Error("registry-keys"));
            }
            let mut entry = Entry { member: m.clone(), references: Vec::new(), keys: Vec::new() };
            for (i, k) in m.keys.iter().enumerate() {
                if usize::from(k.role) != i + 1
                    || k.suite != 1
                    || k.parameters != 1
                    || k.identity != m.identity
                    || k.epoch == 0
                    || k.valid_from > committee.anchor_mc
                    || committee.anchor_mc >= k.valid_until
                {
                    return Err(Error("key-validity"));
                }
                if k.capacity_domain != [0; 32] || k.capacity_limit != 0 {
                    return Err(Error("c0-capacity"));
                }
                entry.keys.push(AdmittedKey::admit(&k.public_key)?);
                entry.references.push(key_reference(k)?);
            }
            out.roster.insert(m.identity, entry);
        }
        Ok(out)
    }
    pub fn committee_id(&self) -> &Hash {
        &self.committee_id
    }
    pub fn policy_id(&self) -> &Hash {
        &self.policy_id
    }
    pub fn committee(&self) -> &Committee {
        &self.committee
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn total_weight(&self) -> u64 {
        self.total
    }
    fn verify_records(
        &self,
        duty: &Duty,
        payload: &[u8],
        rows: &[Record],
        expected: &Duty,
        quorum: bool,
    ) -> Result<u64, Error> {
        if duty != expected {
            return Err(Error("expected-context"));
        }
        if duty.committee != self.committee_id
            || duty.policy != self.policy_id
            || duty.workchain != self.committee.workchain
            || duty.shard != self.committee.shard
            || duty.anchor_mc != self.committee.anchor_mc
            || duty.catchain != self.committee.catchain
        {
            return Err(Error("context-binding"));
        }
        validate_payload(duty, payload)?;
        if rows.is_empty() || rows.len() > self.roster.len() {
            return Err(Error("signer-order"));
        }
        let mut weight = 0u64;
        let mut previous = [0; 32];
        let mut pending = Vec::new();
        for row in rows {
            if row.identity <= previous {
                return Err(Error("signer-order"));
            }
            previous = row.identity;
            let member = self.roster.get(&row.identity).ok_or(Error("unknown-signer"))?;
            if row.components.len() != 1 {
                return Err(Error("c0-components"));
            }
            let c = &row.components[0];
            let reference = Keyref {
                suite: c.suite,
                parameters: c.parameters,
                epoch: c.epoch,
                key_id: c.key_id,
            };
            if reference != member.references[usize::from(duty.role) - 1] {
                return Err(Error("key-binding"));
            }
            if c.signature.len() != 64 {
                return Err(Error("signature-size"));
            }
            let sum = weight.checked_add(member.member.weight).ok_or(Error("weight"))?;
            if sum > MAX_WEIGHT {
                return Err(Error("weight"));
            }
            weight = sum;
            pending.push((
                &member.keys[usize::from(duty.role) - 1],
                signing_statement(duty, row)?,
                &c.signature,
            ));
        }
        let signed_weight = weight.checked_mul(3).ok_or(Error("weight"))?;
        let required_weight = self.total.checked_mul(2).ok_or(Error("weight"))?;
        if quorum && signed_weight < required_weight {
            return Err(Error("quorum"));
        }
        for (key, statement, signature) in pending {
            if !key.verify(&statement, signature) {
                return Err(Error("signature"));
            }
        }
        Ok(weight)
    }
    pub fn verify_certificate(
        &self,
        cert: &Certificate,
        expected: &Duty,
    ) -> Result<VerifiedCertificate, Error> {
        let raw = encode(cert)?;
        if raw.len() > self.policy.max_certificate as usize {
            return Err(Error("certificate-budget"));
        }
        let weight =
            self.verify_records(&cert.duty, &cert.payload, &cert.records, expected, true)?;
        Ok(VerifiedCertificate {
            certificate_id: digest("certificate", &raw)?,
            duty: cert.duty.clone(),
            signers: cert.records.iter().map(|r| r.identity).collect(),
            weight,
        })
    }
    pub fn verify_envelope(&self, env: &Envelope, expected: &Duty) -> Result<u64, Error> {
        if encode(env)?.len() > self.policy.max_envelope as usize {
            return Err(Error("envelope-budget"));
        }
        self.verify_records(
            &env.duty,
            &env.payload,
            std::slice::from_ref(&env.record),
            expected,
            false,
        )
    }
}
