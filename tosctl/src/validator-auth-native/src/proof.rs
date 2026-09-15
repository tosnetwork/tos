use crate::{cells, native};
use chain_block::{
    Cell, Deserializable, HashmapE, MerkleProof, Serializable, ShardStateUnsplit, SliceData,
    UsageTree,
};
use tos_validator_auth::{
    api_semantics::registry_query_id,
    codec::{decode, encode, Error, Hash, Wire},
    crypto::{digest, object_id},
    transfer::ObjectReader,
    types::*,
};
/// The constructor is private: only proof verification can grant this result.
pub struct VerifiedNativeResponse {
    bytes: Vec<u8>,
    anchor: Anchor,
    method: u8,
}
impl VerifiedNativeResponse {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn anchor(&self) -> &Anchor {
        &self.anchor
    }
    pub fn method(&self) -> u8 {
        self.method
    }
}
fn key_slice(id: &[u8]) -> Result<SliceData, Error> {
    native(SliceData::load_bitstring(native(chain_block::BuilderData::with_raw(
        id.to_vec(),
        id.len() * 8,
    ))?))
}
fn wrapper(cell: Cell) -> Result<HashmapE, Error> {
    let mut slice = native(SliceData::load_cell(cell))?;
    if slice.cell_type() != chain_block::CellType::Ordinary || slice.remaining_bits() != 1 {
        return Err(Error("dictionary-shape"));
    }
    let present = native(slice.get_next_bit())?;
    if slice.remaining_references() != usize::from(present) {
        return Err(Error("dictionary-shape"));
    }
    let data = if present { Some(native(slice.checked_drain_reference())?) } else { None };
    Ok(HashmapE::with_hashmap(256, data))
}
fn leaf_ref(slice: SliceData) -> Result<Cell, Error> {
    if slice.remaining_bits() != 0 || slice.remaining_references() != 1 {
        return Err(Error("dictionary-shape"));
    }
    native(slice.reference(0))
}
fn lookup<T: Wire>(dict: &HashmapE, id: &Hash, domain: &str) -> Result<T, Error> {
    let leaf = native(dict.get(key_slice(id)?))?.ok_or(Error("history-unavailable"))?;
    let value = decode::<T>(&cells::unpack_bytes(leaf_ref(leaf)?, cells::MAX_OBJECT)?)?;
    if object_id(domain, &value)? != *id {
        return Err(Error("entry-hash"));
    }
    Ok(value)
}
fn read_hash(slice: &mut SliceData) -> Result<Hash, Error> {
    native(slice.get_next_bits(256))?.try_into().map_err(|_| Error("native-hash"))
}
fn query(
    root: Cell,
    anchor: &Anchor,
    network: i32,
    method: u8,
    request: &[u8],
    proof: Proofref,
) -> Result<(Vec<u8>, u8, Hash), Error> {
    if anchor.seqno == u32::MAX
        || anchor.root == [0; 32]
        || anchor.file == [0; 32]
        || anchor.state == [0; 32]
    {
        return Err(Error("anchor"));
    }
    if root.repr_hash().as_slice() != &anchor.state {
        return Err(Error("state-root"));
    }
    let state = native(ShardStateUnsplit::construct_from_full_cell(root))?;
    if state.global_id() != network
        || state.global_id() == 0
        || state.seq_no() != anchor.seqno
        || state.shard().workchain_id() != -1
        || state.shard().prefix_len() != 0
    {
        return Err(Error("state-context"));
    }
    // Native header admission includes the queue/account dictionary roots.
    // Their descendants remain pruned unless the requested proof needs them.
    native(state.read_out_msg_queue_info())?;
    native(state.read_accounts())?;
    let extra = native(chain_block::McStateExtra::construct_from_full_cell(
        state.custom_cell().ok_or(Error("native-config"))?,
    ))?;
    let config = &extra.config.config_params;
    let parameter = |index: u32| -> Result<Cell, Error> {
        leaf_ref(
            native(config.get(native(index.write_to_bitstring())?))?
                .ok_or(Error("native-config"))?,
        )
    };
    let mut cap = native(SliceData::load_cell(parameter(8)?))?;
    if cap.cell_type() != chain_block::CellType::Ordinary
        || cap.remaining_bits() != 104
        || cap.remaining_references() != 0
        || native(cap.get_next_byte())? != 0xc4
    {
        return Err(Error("config-capability"));
    }
    native(cap.get_next_u32())?;
    if native(cap.get_next_u64())? & 1024 == 0 {
        return Err(Error("config-capability"));
    }
    for index in [9, 10] {
        let required = HashmapE::with_hashmap(32, Some(parameter(index)?));
        let entry = native(required.get(native(46u32.write_to_bitstring())?))?
            .ok_or(Error("config-mandatory"))?;
        if entry.remaining_bits() != 0 || entry.remaining_references() != 0 {
            return Err(Error("config-mandatory"));
        }
    }
    let mut count = native(SliceData::load_cell(parameter(16)?))?;
    if count.cell_type() != chain_block::CellType::Ordinary
        || count.remaining_bits() != 48
        || count.remaining_references() != 0
    {
        return Err(Error("validator-count"));
    }
    let maximum = native(count.get_next_u16())?;
    let main = native(count.get_next_u16())?;
    let minimum = native(count.get_next_u16())?;
    if maximum > 400 || maximum < main || main < minimum || minimum < 1 {
        return Err(Error("validator-count"));
    }
    let mut p0 = native(SliceData::load_cell(parameter(46)?))?;
    if p0.cell_type() != chain_block::CellType::Ordinary
        || p0.remaining_bits() != 880
        || p0.remaining_references() != 4
        || native(p0.get_next_u32())? != 0x76617131
        || native(p0.get_next_u16())? != 1
    {
        return Err(Error("config46-shape"));
    }
    let chain_domain = read_hash(&mut p0)?;
    let fingerprint = read_hash(&mut p0)?;
    if chain_domain == [0; 32] || fingerprint != INTERFACE_FINGERPRINT {
        return Err(Error("interface-digest"));
    }
    native(p0.get_next_u64())?;
    let policy_id = read_hash(&mut p0)?;
    let identities = native(p0.checked_drain_reference())?;
    let keys = native(p0.checked_drain_reference())?;
    let policies = wrapper(native(p0.checked_drain_reference())?)?;
    let selected = lookup::<Policy>(&policies, &policy_id, "policy")?;
    if selected.phase != 0
        || selected.suites != vec![Suite { suite: 1, parameters: 1 }]
        || selected.interface_digest != fingerprint
        || selected.effective_from > anchor.seqno
        || selected.max_envelope != 4096
        || selected.max_certificate != 524288
    {
        return Err(Error("unsupported-profile"));
    }
    match method {
        8 => {
            let q = decode::<GetProfileRequest>(request)?;
            if q.anchor != *anchor {
                return Err(Error("request-anchor"));
            }
            let state = ProfileState {
                interface_digest: fingerprint,
                policy: policy_id,
                active: selected.suites.clone(),
            };
            let result = ProfileResult {
                anchor: anchor.clone(),
                interface_digest: fingerprint,
                policy: policy_id,
                installed: vec![Suite { suite: 1, parameters: 1 }],
                active: selected.suites,
                can_parse: 1,
                can_verify: 1,
                proof,
            };
            Ok((encode(&result)?, 6, object_id("profile_state", &state)?))
        }
        9 => {
            let q = decode::<GetPolicyRequest>(request)?;
            if q.anchor != *anchor {
                return Err(Error("request-anchor"));
            }
            let policy = lookup::<Policy>(&policies, &q.policy_id, "policy")?;
            Ok((encode(&PolicyResult { anchor: anchor.clone(), policy, proof })?, 2, q.policy_id))
        }
        11 => {
            let q = decode::<GetKeyRequest>(request)?;
            if q.anchor != *anchor {
                return Err(Error("request-anchor"));
            }
            let key = lookup::<Key>(&wrapper(keys)?, &q.key_id, "key")?;
            Ok((encode(&KeyResult { anchor: anchor.clone(), key, proof })?, 4, q.key_id))
        }
        10 => {
            let q = decode::<GetRegistryRequest>(request)?;
            if q.anchor != *anchor {
                return Err(Error("request-anchor"));
            }
            if !(1..=128).contains(&q.limit) {
                return Err(Error("page-limit"));
            }
            let query_id = registry_query_id(anchor, q.limit)?;
            let mut start = [0; 32];
            if let Some(c) = q.cursor.first() {
                if c.anchor != *anchor || c.query_id != query_id || c.last_identity == [0; 32] {
                    return Err(Error("cursor-binding"));
                }
                start = c.last_identity;
            }
            let dict = wrapper(identities)?;
            let mut current = start;
            let mut rows = Vec::new();
            let mut more = false;
            for n in 0..=q.limit {
                let next =
                    native(dict.find_leaf(key_slice(&current)?, true, false, false, &mut 0))?;
                let Some((key, leaf)) = next else {
                    break;
                };
                current = read_hash(&mut native(SliceData::load_bitstring(key))?)?;
                if current == [0; 32] {
                    return Err(Error("identity-entry"));
                }
                let cell = leaf_ref(leaf)?;
                if n == q.limit {
                    more = true;
                    break;
                }
                let value = decode::<Identity>(&cells::unpack_bytes(cell, cells::MAX_OBJECT)?)?;
                if value.identity != current {
                    return Err(Error("identity-key"));
                }
                rows.push(value);
            }
            let cursor = if more {
                vec![tos_validator_auth::types::Cursor {
                    anchor: anchor.clone(),
                    query_id,
                    last_identity: rows.last().ok_or(Error("page-shape"))?.identity,
                }]
            } else {
                vec![]
            };
            let mut bytes = query_id.to_vec();
            bytes.extend_from_slice(&start);
            bytes.push(u8::try_from(rows.len()).map_err(|_| Error("page-shape"))?);
            for row in &rows {
                bytes.extend_from_slice(&encode(row)?);
            }
            bytes.push(u8::try_from(cursor.len()).map_err(|_| Error("page-shape"))?);
            for row in &cursor {
                bytes.extend_from_slice(&encode(row)?);
            }
            let id = digest("registry-page", &bytes)?;
            Ok((
                encode(&RegistryResult {
                    anchor: anchor.clone(),
                    query_id,
                    identities: rows,
                    cursor,
                    proof,
                })?,
                3,
                id,
            ))
        }
        _ => Err(Error("unsupported-method")),
    }
}
fn response_proof(method: u8, raw: &[u8]) -> Result<Proofref, Error> {
    Ok(match method {
        8 => decode::<ProfileResult>(raw)?.proof,
        9 => decode::<PolicyResult>(raw)?.proof,
        10 => decode::<RegistryResult>(raw)?.proof,
        11 => decode::<KeyResult>(raw)?.proof,
        _ => return Err(Error("unsupported-method")),
    })
}
/// `anchor` comes from independently established finality/checkpoint trust,
/// never from the peer supplying the response. One reader bounds all attachments.
pub fn verify_native_response<F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>>(
    method: u8,
    request: &[u8],
    response: &[u8],
    anchor: &Anchor,
    network: i32,
    reader: &mut ObjectReader<F>,
) -> Result<VerifiedNativeResponse, Error> {
    if request.len() > 2_000_000 || response.len() > 2_000_000 {
        return Err(Error("api-binary-bound"));
    }
    let proof = response_proof(method, response)?;
    if proof.anchor != *anchor {
        return Err(Error("proof-anchor"));
    }
    let raw = reader.resolve(&proof.proof, 5)?;
    if digest("proof", &raw)? != proof.proof_hash {
        return Err(Error("proof-hash"));
    }
    let cell = cells::read_boc(&raw, true)?;
    let merkle = native(MerkleProof::construct_from_full_cell(cell.clone()))?;
    let virtualized = merkle.proof.virtualize(1);
    let used = UsageTree::with_root(virtualized.clone());
    let (expected, kind, id) =
        query(used.root_cell(), anchor, network, method, request, proof.clone())?;
    if proof.kind != kind || proof.object_id != id {
        return Err(Error("proof-object"));
    }
    let minimal = native(MerkleProof::create_by_usage_tree(&virtualized, &used))?;
    if native(minimal.serialize())?.repr_hash() != cell.repr_hash() {
        return Err(Error("proof-unrelated-values"));
    }
    if expected != response {
        return Err(Error("response-association"));
    }
    Ok(VerifiedNativeResponse { bytes: expected, anchor: anchor.clone(), method })
}

/// Supplied from independent finality/checkpoint trust, not a response field.
pub struct NativeStateVerifier {
    pub anchor: Anchor,
    pub network: i32,
}
impl tos_validator_auth::client::ResponseVerifier for NativeStateVerifier {
    type Output = VerifiedNativeResponse;
    type Prepared = ();
    fn prepare<F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>>(
        &self,
        method: u8,
        request: &[u8],
        reader: &mut ObjectReader<F>,
    ) -> Result<(), Error> {
        tos_validator_auth::api_semantics::validate_api_request(method, request, reader)
    }
    fn verify<F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>>(
        &self,
        _prepared: (),
        method: u8,
        _id: Hash,
        request: &[u8],
        response: &[u8],
        reader: &mut ObjectReader<F>,
    ) -> Result<Self::Output, Error> {
        verify_native_response(method, request, response, &self.anchor, self.network, reader)
    }
}
