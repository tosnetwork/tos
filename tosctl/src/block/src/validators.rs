/*
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{
    config_params::CatchainConfig,
    define_HashmapE,
    error::{BlockError, Result},
    fail,
    pq_bytes::{pack_pq_bytes, unpack_pq_bytes, PQ_BYTES_HARD_MAX},
    sha256_digest, sha512_digest,
    shard::{MASTERCHAIN_ID, SHARD_FULL},
    signature::{CryptoSignature, SigPubKey},
    types::Number16,
    BuilderData, ByteOrderRead, Cell, Crc32, Deserializable, IBitstring, KeyId, Serializable,
    SliceData, UInt256,
};
use std::{
    borrow::Cow,
    cmp::{min, Ordering},
    io::{Cursor, Write},
    sync::Arc,
};

/*
validator_info$_
  validator_list_hash_short:uint32
  catchain_seqno:uint32
  nx_cc_updated:Bool
= ValidatorInfo;
*/

/// Validator info struct
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ValidatorInfo {
    pub validator_list_hash_short: u32,
    pub catchain_seqno: u32,
    pub nx_cc_updated: bool,
}

impl ValidatorInfo {
    pub fn with_params(
        validator_list_hash_short: u32,
        catchain_seqno: u32,
        nx_cc_updated: bool,
    ) -> Self {
        ValidatorInfo { validator_list_hash_short, catchain_seqno, nx_cc_updated }
    }
}

impl Serializable for ValidatorInfo {
    fn write_to(&self, cell: &mut BuilderData) -> Result<()> {
        self.validator_list_hash_short.write_to(cell)?;
        self.catchain_seqno.write_to(cell)?;
        self.nx_cc_updated.write_to(cell)?;
        Ok(())
    }
}

impl Deserializable for ValidatorInfo {
    fn read_from(&mut self, cell: &mut SliceData) -> Result<()> {
        self.validator_list_hash_short.read_from(cell)?;
        self.catchain_seqno.read_from(cell)?;
        self.nx_cc_updated.read_from(cell)?;
        Ok(())
    }
}

/*
validator_base_info$_
  validator_list_hash_short:uint32
  catchain_seqno:uint32
= ValidatorBaseInfo;
*/

///
/// ValidatorBaseInfo
///
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ValidatorBaseInfo {
    pub validator_list_hash_short: u32,
    pub catchain_seqno: u32,
}

impl ValidatorBaseInfo {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_params(validator_list_hash_short: u32, catchain_seqno: u32) -> Self {
        ValidatorBaseInfo { validator_list_hash_short, catchain_seqno }
    }
}

impl Serializable for ValidatorBaseInfo {
    fn write_to(&self, cell: &mut BuilderData) -> Result<()> {
        self.validator_list_hash_short.write_to(cell)?;
        self.catchain_seqno.write_to(cell)?;
        Ok(())
    }
}

impl Deserializable for ValidatorBaseInfo {
    fn read_from(&mut self, cell: &mut SliceData) -> Result<()> {
        self.validator_list_hash_short.read_from(cell)?;
        self.catchain_seqno.read_from(cell)?;
        Ok(())
    }
}

/*
validator#53
    public_key:SigPubKey
    weight:uint64
= ValidatorDescr;
validator_addr#73
    public_key:SigPubKey
    weight:uint64
    adnl_addr:bits256
= ValidatorDescr;
validator_pq#b3
    validator_id:bits256
    algorithm_id:uint16
    key_id:bits256
    public_key:^Cell
    weight:uint64
    adnl_addr:bits256
= ValidatorDescr;

Tag 0x93 was a Rust-only reader/writer path that never existed in block.tlb and
that the C++ side rejects; it has been removed so both implementations accept
exactly the same constructors.
*/

/// The one consensus signature suite admitted at genesis. Mirrors `PQAlgorithmId` in
/// crypto/pq/pq-consensus.h.
pub const MLDSA44_ALGORITHM_ID: u16 = 1;
pub const MLDSA44_PUBLIC_KEY_BYTES: usize = 1312;

/// Frozen domain for the consensus key identity. Must stay byte-identical to
/// `key_id_domain` in crypto/pq/pq-consensus.h, since both derive the same identity.
const CONSENSUS_KEY_ID_DOMAIN: &[u8] = b"TOS-PQ-CONSENSUS-KEY-v1";

/// key_id = SHA-256(domain || u16_le(algorithm_id) || public_key), the counterpart of
/// `derive_key_id` on the C++ side.
pub fn derive_consensus_key_id(algorithm_id: u16, public_key: &[u8]) -> UInt256 {
    let mut preimage = Vec::with_capacity(CONSENSUS_KEY_ID_DOMAIN.len() + 2 + public_key.len());
    preimage.extend_from_slice(CONSENSUS_KEY_ID_DOMAIN);
    preimage.extend_from_slice(&algorithm_id.to_le_bytes());
    preimage.extend_from_slice(public_key);
    UInt256::from(sha256_digest(&preimage))
}

/// The protocol cap on the summed weight of a validator set. Mirrors
/// `kMaxTotalValidatorWeight` in tos/quorum.h: it keeps the quorum arithmetic, which
/// multiplies weights by three, from overflowing.
pub const MAX_TOTAL_VALIDATOR_WEIGHT: u64 = u64::MAX / 3;

/// Validate a whole list and return the weight it sums to.
///
/// Both building a set and reading one go through here, so a set that one path refuses
/// cannot be accepted by the other.
pub fn validate_validator_list(list: &[ValidatorDescr]) -> Result<u64> {
    let mut seen_validator_ids = std::collections::HashSet::new();
    let mut seen_key_ids = std::collections::HashSet::new();
    let mut seen_adnl_addrs = std::collections::HashSet::new();
    let mut total: u64 = 0;
    for descr in list {
        descr.validate_consensus()?;
        // One validator may appear once: a second entry would let a single member be
        // counted twice toward a quorum.
        if !seen_validator_ids.insert(descr.validator_id()?) {
            fail!("validator set repeats a validator identity")
        }
        // A consensus key belongs to one validator. This is a different fault from a
        // repeated member, and it also covers a repeated public key, since a key
        // identity is bound to the key that derives it.
        if !seen_key_ids.insert(descr.consensus_key_id()?) {
            fail!("validator set repeats a consensus key identity")
        }
        // An ADNL identity names one member's transport, and every peer-to-peer decision
        // above it resolves through it. Two members sharing one cannot both be addressed,
        // and a peer authenticated on that transport is speaking for whichever of them the
        // routing happened to pick -- a different member from the one a consensus signature
        // names. Only a present address is required to be unique: a classical descriptor may
        // carry none, while a post-quantum one is refused unless it has one.
        if let Some(adnl_addr) = descr.adnl_addr.as_ref() {
            if adnl_addr != &UInt256::default() && !seen_adnl_addrs.insert(adnl_addr.clone()) {
                fail!("validator set repeats an ADNL identity")
            }
        }
        total = match total.checked_add(descr.weight) {
            Some(v) => v,
            None => fail!("total weight of all validators in validator set exceeds u64"),
        };
        if total > MAX_TOTAL_VALIDATOR_WEIGHT {
            fail!(
                "total weight of all validators in validator set exceeds the protocol cap \
                 (UINT64_MAX/3), which the quorum arithmetic depends on"
            )
        }
    }
    Ok(total)
}

/// The post-quantum consensus key a validator currently holds.
///
/// This describes a key and nothing else. The validator that holds it is named by
/// `ValidatorDescr::validator_id`, deliberately outside this struct: replacing a
/// validator's key must never be able to replace the validator's identity along
/// with it, which is the whole reason the two are kept apart.
///
/// `key_id` must equal the frozen derivation over `algorithm_id` and `public_key`.
/// The suite key is 1312 bytes for ML-DSA-44, far past what fits inline, so on the
/// wire it travels through the canonical bounded-bytes cell encoding.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct PqConsensusKey {
    pub algorithm_id: u16,
    pub key_id: UInt256,
    pub public_key: Vec<u8>,
}

/// The consensus verification key a descriptor carries.
///
/// The classical and post-quantum forms are separate variants on purpose: code
/// holding one must not be able to reach for the other by accident, which is the
/// mistake that lets a classical key stand in for consensus authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidatorKey {
    Ed25519(SigPubKey),
    Pq(PqConsensusKey),
}

impl Default for ValidatorKey {
    fn default() -> Self {
        ValidatorKey::Ed25519(SigPubKey::default())
    }
}

///
/// ValidatorDescr
/// Before first election adnl_addr is None and it is calculated from the public key.
/// A post-quantum descriptor always carries an explicit adnl_addr instead, because
/// an ADNL identity is never derived from a consensus key.
///
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ValidatorDescr {
    pub weight: u64,
    /// Stable membership identity, carried on the wire only by a post-quantum
    /// descriptor. A classical one has none to carry, so its identity is derived from
    /// its key instead. Private because the raw field is meaningless for a classical
    /// descriptor: ask `validator_id()`, which answers correctly for both.
    validator_id: UInt256,
    pub key: ValidatorKey,
    /// before first election this filed is None
    pub adnl_addr: Option<UInt256>,

    // Total weight of the previous validators in the list.
    // The field is not serialized.
    pub prev_weight_sum: u64,
}

#[allow(clippy::derived_hash_with_manual_eq)]
impl std::hash::Hash for ValidatorDescr {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match &self.key {
            ValidatorKey::Ed25519(pk) => pk.as_slice().hash(state),
            ValidatorKey::Pq(k) => {
                self.validator_id.hash(state);
                k.key_id.hash(state);
            }
        }
        if let Some(aa) = &self.adnl_addr {
            aa.hash(state)
        }
    }
}

impl ValidatorDescr {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_params(public_key: SigPubKey, weight: u64, adnl_addr: Option<UInt256>) -> Self {
        ValidatorDescr {
            validator_id: UInt256::default(),
            key: ValidatorKey::Ed25519(public_key),
            weight,
            adnl_addr,
            prev_weight_sum: 0,
        }
    }

    pub fn with_key(
        validator_id: UInt256,
        key: ValidatorKey,
        weight: u64,
        adnl_addr: Option<UInt256>,
    ) -> Self {
        ValidatorDescr { validator_id, key, weight, adnl_addr, prev_weight_sum: 0 }
    }

    pub fn with_pq_params(
        validator_id: UInt256,
        key: PqConsensusKey,
        weight: u64,
        adnl_addr: UInt256,
    ) -> Self {
        ValidatorDescr {
            validator_id,
            key: ValidatorKey::Pq(key),
            weight,
            adnl_addr: Some(adnl_addr),
            prev_weight_sum: 0,
        }
    }

    /// The classical key. Fails on a post-quantum descriptor rather than
    /// inventing one, so a caller that has not been converted cannot quietly
    /// treat PQ key material as an Ed25519 key.
    pub fn public_key(&self) -> Result<&SigPubKey> {
        match &self.key {
            ValidatorKey::Ed25519(pk) => Ok(pk),
            ValidatorKey::Pq(_) => {
                fail!("descriptor carries a post-quantum key, not an Ed25519 one")
            }
        }
    }

    /// Stable membership identity. For a classical descriptor this is the identity
    /// derived from its Ed25519 key; for a post-quantum one it is carried explicitly
    /// and does not change when the consensus key rotates.
    pub fn validator_id(&self) -> Result<UInt256> {
        match &self.key {
            ValidatorKey::Ed25519(pk) => Ok(pk.pub_key().id().data().into()),
            ValidatorKey::Pq(_) => Ok(self.validator_id.clone()),
        }
    }

    /// Identity of the consensus key currently held. This is what moves on rotation.
    pub fn consensus_key_id(&self) -> Result<UInt256> {
        match &self.key {
            ValidatorKey::Ed25519(pk) => Ok(pk.pub_key().id().data().into()),
            ValidatorKey::Pq(k) => Ok(k.key_id.clone()),
        }
    }

    /// Everything a descriptor must satisfy before it can take part in consensus.
    ///
    /// The node applies the same rules when it decodes a validator set, and a set that
    /// one implementation accepts while the other refuses is a split waiting to happen,
    /// so these are checked here rather than left to whichever caller remembers.
    pub fn validate_consensus(&self) -> Result<()> {
        // A member with no stake cannot be part of a quorum.
        if self.weight == 0 {
            fail!("validator descriptor has zero weight")
        }
        match &self.key {
            ValidatorKey::Ed25519(_) => Ok(()),
            ValidatorKey::Pq(key) => {
                if key.algorithm_id != MLDSA44_ALGORITHM_ID {
                    fail!("validator descriptor names an unadmitted consensus algorithm")
                }
                if key.public_key.len() != MLDSA44_PUBLIC_KEY_BYTES {
                    fail!("post-quantum consensus key has the wrong length")
                }
                // The declared key identity must be the one this key derives, otherwise a
                // descriptor could claim an identity its key does not back.
                if derive_consensus_key_id(key.algorithm_id, &key.public_key) != key.key_id {
                    fail!("declared key identity is not the one the public key derives")
                }
                if self.validator_id.is_zero() {
                    fail!("post-quantum descriptor has a zero validator identity")
                }
                // An ADNL identity is never derived from a consensus key, so it has to be
                // carried explicitly.
                match self.adnl_addr.as_ref() {
                    Some(addr) if !addr.is_zero() => Ok(()),
                    _ => fail!("post-quantum descriptor has no explicit ADNL identity"),
                }
            }
        }
    }

    pub fn pq_key(&self) -> Option<&PqConsensusKey> {
        match &self.key {
            ValidatorKey::Pq(k) => Some(k),
            ValidatorKey::Ed25519(_) => None,
        }
    }

    pub fn compute_node_id_short(&self) -> Result<UInt256> {
        Ok(self.public_key()?.pub_key().id().data().into())
    }

    pub fn verify_signature(&self, data: &[u8], signature: &CryptoSignature) -> bool {
        match self.public_key() {
            Ok(pk) => pk.verify_signature(data, signature),
            Err(_) => false,
        }
    }

    /// returns adnl_addr or calc it from the public key
    pub fn adnl_addr(&self) -> Result<Arc<KeyId>> {
        match &self.adnl_addr {
            Some(addr) => Ok(KeyId::from_data(*addr.as_array())),
            None => Ok(self.public_key()?.pub_key().id().clone()),
        }
    }
}

const VALIDATOR_DESC_TAG: u8 = 0x53;
const VALIDATOR_DESC_ADDR_TAG: u8 = 0x73;
pub const VALIDATOR_DESC_PQ_TAG: u8 = 0xb3;

impl Serializable for ValidatorDescr {
    fn write_to(&self, cell: &mut BuilderData) -> Result<()> {
        match &self.key {
            ValidatorKey::Ed25519(public_key) => {
                let tag = if self.adnl_addr.is_some() {
                    VALIDATOR_DESC_ADDR_TAG
                } else {
                    VALIDATOR_DESC_TAG
                };
                cell.append_u8(tag)?;
                public_key.write_to(cell)?;
                self.weight.write_to(cell)?;
                if let Some(adnl_addr) = self.adnl_addr.as_ref() {
                    adnl_addr.write_to(cell)?;
                }
            }
            ValidatorKey::Pq(key) => {
                let adnl_addr = match self.adnl_addr.as_ref() {
                    Some(addr) => addr,
                    None => fail!("a post-quantum descriptor requires an explicit adnl address"),
                };
                cell.append_u8(VALIDATOR_DESC_PQ_TAG)?;
                self.validator_id.write_to(cell)?;
                cell.append_bits(key.algorithm_id as usize, 16)?;
                key.key_id.write_to(cell)?;
                cell.checked_append_reference(pack_pq_bytes(&key.public_key, PQ_BYTES_HARD_MAX)?)?;
                self.weight.write_to(cell)?;
                adnl_addr.write_to(cell)?;
            }
        }
        Ok(())
    }
}

impl Deserializable for ValidatorDescr {
    fn construct_from(slice: &mut SliceData) -> Result<Self> {
        let tag = slice.get_next_byte()?;
        let (key, weight, adnl_addr);
        let mut validator_id = UInt256::default();
        match tag {
            VALIDATOR_DESC_TAG => {
                key = ValidatorKey::Ed25519(Deserializable::construct_from(slice)?);
                weight = Deserializable::construct_from(slice)?;
                adnl_addr = None;
            }
            VALIDATOR_DESC_ADDR_TAG => {
                key = ValidatorKey::Ed25519(Deserializable::construct_from(slice)?);
                weight = Deserializable::construct_from(slice)?;
                adnl_addr = Some(Deserializable::construct_from(slice)?);
            }
            VALIDATOR_DESC_PQ_TAG => {
                validator_id = Deserializable::construct_from(slice)?;
                let algorithm_id = slice.get_next_int(16)? as u16;
                let key_id = Deserializable::construct_from(slice)?;
                let public_key =
                    unpack_pq_bytes(&slice.checked_drain_reference()?, PQ_BYTES_HARD_MAX)?;
                key = ValidatorKey::Pq(PqConsensusKey { algorithm_id, key_id, public_key });
                weight = Deserializable::construct_from(slice)?;
                adnl_addr = Some(Deserializable::construct_from(slice)?);
            }
            tag => fail!(Self::invalid_tag(tag as u32)),
        }
        Ok(Self { validator_id, key, weight, adnl_addr, prev_weight_sum: 0 })
    }
}

/*
validators#11
    utime_since:uint32
    utime_until:uint32
    total:(## 16)
    main:(## 16)
    { main <= total }
    { main >= 1 }
    list:(Hashmap 16 ValidatorDescr)
= ValidatorSet;

validators_ext#12
    utime_since:uint32
    utime_until:uint32
    total:(## 16)
    main:(## 16)
    { main <= total }
    { main >= 1 }
    total_weight:uint64
    list:(HashmapE 16 ValidatorDescr)
= ValidatorSet;
*/

define_HashmapE! {ValidatorDescriptions, 16, ValidatorDescr}

///
/// ValidatorSet
///
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct ValidatorSet {
    utime_since: u32,
    utime_until: u32,
    total: Number16,
    main: Number16,
    total_weight: u64,
    cc_seqno: u32,             // is never used
    list: Vec<ValidatorDescr>, //ValidatorDescriptions,
}

#[derive(Eq, PartialEq, Debug)]
struct IncludedValidatorWeight {
    pub prev_weight_sum: u64,
    pub weight: u64,
}

impl PartialOrd for IncludedValidatorWeight {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IncludedValidatorWeight {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.prev_weight_sum.cmp(&other.prev_weight_sum) {
            Ordering::Equal => self.weight.cmp(&other.weight),
            other => other,
        }
    }
}

impl ValidatorSet {
    pub fn new(
        utime_since: u32,
        utime_until: u32,
        main: u16,
        mut list: Vec<ValidatorDescr>,
    ) -> Result<Self> {
        if list.is_empty() {
            fail!(BlockError::InvalidArg("`list` can't be empty".to_string()))
        }
        // The same rules the node applies when it decodes a set, so a set that can be
        // built here is one it would also accept, and vice versa.
        let total_weight = validate_validator_list(&list)?;
        let mut running = 0u64;
        for descr in &mut list {
            descr.prev_weight_sum = running;
            running += descr.weight;
        }
        Ok(ValidatorSet {
            utime_since,
            utime_until,
            total: Number16::from(list.len() as u16),
            main: Number16::from(main),
            total_weight,
            cc_seqno: 0,
            list,
        })
    }

    pub fn with_cc_seqno(
        utime_since: u32,
        utime_until: u32,
        main: u16,
        cc_seqno: u32,
        list: Vec<ValidatorDescr>,
    ) -> Result<Self> {
        Ok(Self { cc_seqno, ..Self::new(utime_since, utime_until, main, list)? })
    }

    pub fn with_values_version_2(
        utime_since: u32,
        utime_until: u32,
        main: u16,
        total_weight: u64,
        list: Vec<ValidatorDescr>,
    ) -> Result<Self> {
        Ok(Self { total_weight, ..Self::new(utime_since, utime_until, main, list)? })
    }

    pub fn utime_since(&self) -> u32 {
        self.utime_since
    }

    pub fn utime_until(&self) -> u32 {
        self.utime_until
    }

    pub fn total(&self) -> u16 {
        self.total.as_u16()
    }

    pub fn main(&self) -> u16 {
        self.main.as_u16()
    }

    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    pub fn list(&self) -> &[ValidatorDescr] {
        &self.list
    }

    pub fn validator_by_pub_key(&self, pub_key: &[u8; 32]) -> Option<&ValidatorDescr> {
        self.list.iter().find(|item| item.public_key().is_ok_and(|pk| pk.as_slice() == pub_key))
    }

    pub fn catchain_seqno(&self) -> u32 {
        self.cc_seqno
    }

    pub fn set_catchain_seqno(&mut self, cc_seqno: u32) {
        self.cc_seqno = cc_seqno;
    }

    pub fn cc_seqno(&self) -> u32 {
        self.cc_seqno
    }

    pub fn set_cc_seqno(&mut self, cc_seqno: u32) {
        self.cc_seqno = cc_seqno;
    }

    pub fn at_weight(&self, weight_pos: u64) -> &ValidatorDescr {
        debug_assert!(weight_pos < self.total_weight);
        debug_assert!(!self.list.is_empty());
        for i in 0..self.list.len() {
            if self.list[i].prev_weight_sum > weight_pos {
                debug_assert!(i != 0);
                return &self.list[i - 1];
            }
        }
        self.list.last().unwrap()
    }

    pub fn calc_subset(
        &self,
        cc_config: &CatchainConfig,
        shard_pfx: u64,
        workchain_id: i32,
        cc_seqno: u32,
    ) -> Result<(Vec<ValidatorDescr>, u32)> {
        let is_master = (shard_pfx == SHARD_FULL) && (workchain_id == MASTERCHAIN_ID);

        let subset = if is_master {
            let count = min(self.total.as_usize(), self.main.as_usize());
            if !cc_config.shuffle_mc_validators {
                self.list[0..count].to_vec()
            } else {
                // shuffle mc validators from the head of the list
                let mut prng = ValidatorSetPRNG::new(shard_pfx, workchain_id, cc_seqno);
                let mut indexes = vec![0; count];
                for i in 0..count {
                    let j = prng.next_ranged(i as u64 + 1) as usize; // number 0 .. i
                    debug_assert!(j <= i);
                    indexes[i] = indexes[j];
                    indexes[j] = i;
                }
                let mut subset = Vec::with_capacity(count);
                for index in indexes.iter().take(count) {
                    subset.push(self.list()[*index].clone());
                }
                subset
            }
        } else {
            let mut prng = ValidatorSetPRNG::new(shard_pfx, workchain_id, cc_seqno);
            let full_list = if cc_config.isolate_mc_validators {
                if self.total <= self.main && !(self.main == 0 && self.total == 0) {
                    fail!("Count of validators is too small to make sharde's subset while `isolate_mc_validators` flag is set (total={}, main={})", self.total, self.main)
                }
                let list = self.list[self.main.as_usize()..].to_vec();
                Cow::Owned(Self::new(self.utime_since, self.utime_until, self.main.as_u16(), list)?)
            } else {
                Cow::Borrowed(self)
            };
            let count = min(full_list.total(), cc_config.shard_validators_num as u16) as usize;
            let mut subset = Vec::with_capacity(count);
            let mut weights = Vec::<IncludedValidatorWeight>::with_capacity(count);
            let mut weight_remainder = full_list.total_weight();

            for _ in 0..count {
                debug_assert!(weight_remainder > 0);
                // 1. take pseudo random weight less (or equal) than weight_remainder
                let mut p = prng.next_ranged(weight_remainder);

                // 2. find p which
                //      >= start p value
                //      >= prev_weight_sum of some number of first validators
                for vw in weights.iter() {
                    if p < vw.prev_weight_sum {
                        break;
                    }
                    p += vw.weight;
                }

                // 3. take validator with less weight greater than p
                let next_validator = full_list.at_weight(p);

                subset.push(ValidatorDescr::with_key(
                    next_validator.validator_id.clone(),
                    next_validator.key.clone(),
                    1, // NB: shardchain validator lists have all weights = 1
                    next_validator.adnl_addr.clone(),
                ));
                debug_assert!(weight_remainder >= next_validator.weight);
                weight_remainder -= next_validator.weight;

                // 4. put validator's weight into sorted list of previous weights
                let new_weight = IncludedValidatorWeight {
                    prev_weight_sum: next_validator.prev_weight_sum,
                    weight: next_validator.weight,
                };
                let mut idx = 0;
                while idx < weights.len() {
                    if weights[idx] > new_weight {
                        break;
                    }
                    idx += 1;
                }
                debug_assert!(idx == 0 || weights[idx - 1] < new_weight);
                weights.insert(idx, new_weight);
            }
            subset
        };

        let hash_short = Self::calc_subset_hash_short(subset.as_slice(), cc_seqno)?;

        Ok((subset, hash_short))
    }

    /// Frozen magic for the version 2 validator-set commitment preimage. Deliberately
    /// not the inherited value, so a preimage from either version can never be mistaken
    /// for the other: SHA-256("TOS-VALIDATOR-SET-v2")[0..4) = 0x79ae62d2.
    /// Must stay equal to `validator_set_hash_magic_v2` in crypto/block/block.h.
    pub const HASH_SHORT_MAGIC_V2: u32 = 0x79AE62D2;

    /// Version 2 of the validator-set commitment, the exact counterpart of
    /// `compute_validator_set_hash` in crypto/block/block.cpp.
    ///
    /// It commits to both identities rather than to a raw key: the stable membership
    /// identity, and the identity of the key currently held. Rotating a key changes the
    /// commitment while the validator keeps its place in the set. The public key is not
    /// repeated, because the key identity is already a hash over the algorithm and key.
    /// The exact bytes the commitment is taken over, the counterpart of
    /// `validator_set_hash_preimage` in crypto/block/block.cpp. Built separately from
    /// the hash so the two languages can be compared byte for byte, not just by result.
    pub fn hash_preimage(subset: &[ValidatorDescr], cc_seqno: u32) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(12 + subset.len() * 104);
        out.extend_from_slice(&Self::HASH_SHORT_MAGIC_V2.to_le_bytes());
        out.extend_from_slice(&cc_seqno.to_le_bytes());
        out.extend_from_slice(&(subset.len() as u32).to_le_bytes());
        for vd in subset.iter() {
            out.extend_from_slice(vd.validator_id()?.as_slice());
            out.extend_from_slice(vd.consensus_key_id()?.as_slice());
            out.extend_from_slice(&vd.weight.to_le_bytes());
            match vd.adnl_addr.as_ref() {
                Some(addr) => out.extend_from_slice(addr.as_slice()),
                None => out.extend_from_slice(UInt256::default().as_slice()),
            }
        }
        Ok(out)
    }

    pub fn calc_subset_hash_short(subset: &[ValidatorDescr], cc_seqno: u32) -> Result<u32> {
        let mut hasher = Crc32::new();
        hasher.update(Self::hash_preimage(subset, cc_seqno)?);
        Ok(hasher.finalize())
    }
}

const VALIDATOR_SET_TAG: u8 = 0x11;
const VALIDATOR_SET_EX_TAG: u8 = 0x12;

impl Serializable for ValidatorSet {
    fn write_to(&self, cell: &mut BuilderData) -> Result<()> {
        cell.append_u8(VALIDATOR_SET_EX_TAG)?;
        self.utime_since.write_to(cell)?;
        self.utime_until.write_to(cell)?;
        self.total.write_to(cell)?;
        self.main.write_to(cell)?;

        let mut validators = ValidatorDescriptions::default();
        for (i, v) in self.list.iter().enumerate() {
            validators.set(&(i as u16), v)?;
        }
        self.total_weight.write_to(cell)?;
        validators.write_to(cell)?;
        Ok(())
    }
}

impl Deserializable for ValidatorSet {
    fn read_from(&mut self, cell: &mut SliceData) -> Result<()> {
        let tag = cell.get_next_byte()?;
        if !matches!(tag, VALIDATOR_SET_TAG | VALIDATOR_SET_EX_TAG) {
            fail!(Self::invalid_tag(tag as u32))
        }
        self.utime_since.read_from(cell)?;
        self.utime_until.read_from(cell)?;
        self.total.read_from(cell)?;
        self.main.read_from(cell)?;
        let mut validators = ValidatorDescriptions::default();
        if tag == VALIDATOR_SET_TAG {
            validators.read_hashmap_root(cell)?; // Hashmap
        } else {
            self.total_weight = u64::construct_from(cell)?;
            validators.read_from(cell)?; // HashmapE
        }
        self.list.clear();
        for i in 0..self.total.as_u16() {
            let val = validators.get(&i)?.ok_or_else(|| {
                BlockError::InvalidData(format!(
                    "Validator's hash map doesn't \
                    contain validator with index {}",
                    i
                ))
            })?;
            self.list.push(val);
        }
        // A decoded set is untrusted input, so it goes through the same validation as one
        // built in process rather than the bare accumulation this used to do.
        let total_weight = validate_validator_list(&self.list)?;
        let mut running = 0u64;
        for val in self.list.iter_mut() {
            val.prev_weight_sum = running;
            running += val.weight;
        }
        if self.list.is_empty() {
            fail!(BlockError::InvalidData("list can't be empty".to_string()));
        }
        if tag == VALIDATOR_SET_TAG {
            self.total_weight = self.list.iter().map(|vd| vd.weight).sum();
        } else if self.total_weight != total_weight {
            fail!(BlockError::InvalidData(
                "Calculated total_weight is not equal to the read one while read ValidatorSet"
                    .to_string()
            ))
        }

        if self.main > self.total {
            fail!(BlockError::InvalidData("main > total while read ValidatorSet".to_string()))
        }
        if self.main < Number16::new(1)? {
            fail!(BlockError::InvalidData("main < 1 while read ValidatorSet".to_string()))
        }
        Ok(())
    }
}

pub struct ValidatorSetPRNG {
    context: [u8; 48],
    bag: [u64; 7],
    cursor: usize,
}

impl ValidatorSetPRNG {
    pub fn new(shard_pfx: u64, workchain_id: i32, cc_seqno: u32) -> Self {
        let seed = [0; 32];
        Self::with_seed(shard_pfx, workchain_id, cc_seqno, &seed)
    }

    pub fn with_seed(shard_pfx: u64, workchain_id: i32, cc_seqno: u32, seed: &[u8; 32]) -> Self {
        // Big endian
        // byte seed[32]
        // u64 shard;
        // i32 workchain;
        // u32 cc_seqno;
        let mut context = [0_u8; 48];
        let mut cur = Cursor::new(&mut context[..]);
        cur.write_all(seed).unwrap();
        cur.write_all(&shard_pfx.to_be_bytes()).unwrap();
        cur.write_all(&workchain_id.to_be_bytes()).unwrap();
        cur.write_all(&cc_seqno.to_be_bytes()).unwrap();

        ValidatorSetPRNG { context, bag: [0_u64; 7], cursor: 7 }
    }

    fn reset(&mut self) -> u64 {
        // calc hash
        let mut hash = Cursor::new(sha512_digest(self.context));

        // increment seed
        for i in (0..32).rev() {
            self.context[i] += 1;
            if self.context[i] != 0 {
                break;
            }
        }

        // read results
        let first_u64 = hash.read_be_u64().unwrap();
        for i in 0..7 {
            self.bag[i] = hash.read_be_u64().unwrap();
        }

        self.cursor = 0;
        first_u64
    }

    pub fn next_u64(&mut self) -> u64 {
        if self.cursor < self.bag.len() {
            let next = self.bag[self.cursor];
            self.cursor += 1;
            next
        } else {
            self.reset()
        }
    }

    pub fn next_ranged(&mut self, range: u64) -> u64 {
        let val = self.next_u64();
        ((range as u128 * val as u128) >> 64) as u64
    }
}

#[cfg(test)]
#[path = "tests/test_validators.rs"]
mod tests;
