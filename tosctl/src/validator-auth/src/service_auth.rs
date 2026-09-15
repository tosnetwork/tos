use crate::{
    codec::{encode, Error, Hash},
    crypto::{object_id, AdmittedKey},
    types::*,
};
use std::collections::BTreeMap;
#[derive(Clone, Debug)]
pub struct ServiceKey {
    pub id: Hash,
    pub public_key: Vec<u8>,
}
struct Installed {
    policy: ServicePolicy,
    key: ServiceKey,
    admitted: AdmittedKey,
}
#[derive(Default)]
pub struct ServiceTrust {
    history: BTreeMap<Hash, Installed>,
    current: BTreeMap<Hash, Hash>,
}
impl ServiceTrust {
    // Called only from independently authenticated local configuration.
    pub fn install_trusted(
        &mut self,
        policy: &ServicePolicy,
        key: &ServiceKey,
    ) -> Result<(), Error> {
        if policy.issuer == [0; 32]
            || key.id == [0; 32]
            || policy.suites != vec![Suite { suite: 1, parameters: 1 }]
        {
            return Err(Error("service-policy"));
        }
        let id = object_id("service_policy", policy)?;
        if let Some(old) = self.history.get(&id) {
            if old.key.id != key.id || old.key.public_key != key.public_key {
                return Err(Error("service-key-replacement"));
            }
            return Ok(());
        }
        if let Some(previous) = self.current.get(&policy.issuer) {
            let old = self.history.get(previous).ok_or(Error("service-policy-history"))?;
            if policy.previous != *previous
                || old.policy.revision.checked_add(1) != Some(policy.revision)
            {
                return Err(Error("service-policy-history"));
            }
        } else if policy.revision != 1 || policy.previous != [0; 32] {
            return Err(Error("service-policy-history"));
        }
        let admitted = AdmittedKey::admit(&key.public_key)?;
        self.history.insert(id, Installed { policy: policy.clone(), key: key.clone(), admitted });
        self.current.insert(policy.issuer, id);
        Ok(())
    }
    fn verify_body(
        &self,
        issuer: &Hash,
        policy: &Hash,
        raw: &[u8],
        components: &[ServiceComponent],
    ) -> Result<(), Error> {
        let found = self.history.get(policy).ok_or(Error("service-issuer"))?;
        if found.policy.issuer != *issuer {
            return Err(Error("service-issuer"));
        }
        if components.len() != 1 {
            return Err(Error("service-components"));
        }
        let c = &components[0];
        if c.suite != 1 || c.parameters != 1 || c.key_id != found.key.id {
            return Err(Error("service-components"));
        }
        if !found.admitted.verify(raw, &c.signature) {
            return Err(Error("service-signature"));
        }
        Ok(())
    }
    pub fn verify_permit(&self, value: &Permit) -> Result<(), Error> {
        if self.current.get(&value.body.issuer) != Some(&value.body.service_policy) {
            return Err(Error("stale-permit-policy"));
        }
        self.verify_body(
            &value.body.issuer,
            &value.body.service_policy,
            &encode(&value.body)?,
            &value.components,
        )
    }
    pub fn verify_receipt(&self, value: &Receipt) -> Result<(), Error> {
        self.verify_body(
            &value.body.issuer,
            &value.body.service_policy,
            &encode(&value.body)?,
            &value.components,
        )
    }
}
pub fn validate_permit_context(
    body: &PermitBody,
    current: u32,
    fence: u64,
    live: bool,
) -> Result<(), Error> {
    if [
        body.issuer,
        body.service_policy,
        body.audience,
        body.genesis_root,
        body.genesis_file,
        body.registry_root,
        body.policy,
        body.committee,
        body.session,
        body.identity,
        body.subject,
    ]
    .contains(&[0; 32])
        || ![4, 5, 7].contains(&body.method)
    {
        return Err(Error("permit-shape"));
    }
    if body.anchor.seqno == u32::MAX
        || [body.anchor.root, body.anchor.file, body.anchor.state].contains(&[0; 32])
        || body.expires_mc == u32::MAX
        || body.expires_mc.checked_sub(body.anchor.seqno).is_none_or(|v| v > 128)
    {
        return Err(Error("permit-expiry"));
    }
    if current < body.anchor.seqno || current > body.expires_mc {
        return Err(Error("permit-current-coordinate"));
    }
    if fence == 0 || body.fence != fence {
        return Err(Error("fenced"));
    }
    if !live {
        return Err(Error("duty-not-permitted"));
    }
    Ok(())
}
pub fn verify_permit(
    value: &Permit,
    expected: &PermitBody,
    trust: &ServiceTrust,
    current: u32,
    fence: u64,
    live: bool,
) -> Result<(), Error> {
    if value.body != *expected {
        return Err(Error("permit-context"));
    }
    validate_permit_context(&value.body, current, fence, live)?;
    trust.verify_permit(value)
}
pub trait ReceiptWitness {
    fn contains(&self, sequence: u64, receipt_body: &Hash) -> Result<bool, Error>;
}
pub fn verify_receipt(
    value: &Receipt,
    expected: &ReceiptBody,
    trust: &ServiceTrust,
    witness: &impl ReceiptWitness,
) -> Result<(), Error> {
    if value.body != *expected {
        return Err(Error("receipt-binding"));
    }
    let body = &value.body;
    if body.journal_sequence == 0 || body.fence == 0 || !(1..=3).contains(&body.state) {
        return Err(Error("receipt-state"));
    }
    trust.verify_receipt(value)?;
    if !witness.contains(body.journal_sequence, &object_id("receipt_body", body)?)? {
        return Err(Error("receipt-frontier"));
    }
    Ok(())
}
pub fn validate_request_state(value: &RequestState, id: &Hash) -> Result<(), Error> {
    encode(value)?;
    if value.request_id != *id {
        return Err(Error("state-correlation"));
    }
    if value.state > 3 {
        return Err(Error("state-code"));
    }
    if value.state == 0 {
        if value.statement_id != [0; 32]
            || value.fence != 0
            || !value.result.is_empty()
            || !value.receipt.is_empty()
        {
            return Err(Error("absent-shape"));
        }
    } else {
        if value.statement_id == [0; 32] || value.fence == 0 {
            return Err(Error("known-state"));
        }
        if value.state == 2 {
            if value.result.len() != 1 || !value.receipt.is_empty() {
                return Err(Error("complete-shape"));
            }
            let result = &value.result[0];
            if result.request_id != *id
                || result.statement_id != value.statement_id
                || result.fence != value.fence
            {
                return Err(Error("state-result"));
            }
        } else {
            if !value.result.is_empty() || value.receipt.len() != 1 {
                return Err(Error("pending-shape"));
            }
            let body = &value.receipt[0].body;
            if body.state != value.state
                || body.request_id != *id
                || body.method != 5
                || body.subject != value.statement_id
                || body.fence != value.fence
                || body.result_hash != [0; 32]
            {
                return Err(Error("state-receipt-binding"));
            }
        }
    }
    Ok(())
}
pub fn observe_request_state(
    previous: Option<&RequestState>,
    next: &RequestState,
    id: &Hash,
) -> Result<(), Error> {
    validate_request_state(next, id)?;
    if let Some(old) = previous {
        validate_request_state(old, id)?;
        if (old.state == 2 || old.state == 3) && old != next {
            return Err(Error("terminal-state-regression"));
        }
        if old.state == 1 {
            if next.state == 0 {
                return Err(Error("reserved-state-regression"));
            }
            if old.statement_id != next.statement_id || old.fence != next.fence {
                return Err(Error("reserved-state-binding"));
            }
        }
    }
    Ok(())
}
