/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! The ML-DSA-44 authentication route of the Agent Account
//! (`crypto/smartcont/auth-extension.md`, `doc/mldsa44-auth-module.md`).
//!
//! An immutable module (`crypto/smartcont/mldsa44-auth-module.fc`) holds one
//! ML-DSA-44 public key and the network it serves. A funded relayer sends it
//! `submit`; the module verifies the signature over the whole AUTH request and
//! forwards the envelope to the account, which checks the sender, network,
//! epoch, nonce and expiry before running the payload. The payload of kind 0 is
//! the same unsigned controller-action body an Ed25519 controller would sign.
use anyhow::{Context, anyhow, bail, ensure};
use chain_block::{
    BuilderData, Cell, CellType, Deserializable, IBitstring, MsgAddressInt, Serializable,
    SliceData, StateInit, base64_decode, read_single_root_boc,
};

use crate::ContractProvider;
use crate::native_registry::{
    NATIVE_REGISTRY_PUBLIC_KEY_BYTES, NATIVE_REGISTRY_SIGNATURE_BYTES, sign_ml_dsa_44,
    verify_ml_dsa_44,
};

/// The FunC ML-DSA-44 authentication module. Regenerated and checked by
/// `scripts/update-auth-contract-code.py` together with the Agent Account.
pub const MLDSA44_AUTH_MODULE_CODE_B64: &str = "te6cckECCAEAAVEAART/APSkE/S88sgLAQIBIAIDAgFIBAUACvIw8sdsAebQAdDXCwNxsJJfA+Ag10nBIJJfA+Ag1wsfghBNTEQ0vZJfA+DTHzHTPzHU1NHtRNDSH9TR+DVSILry5wkj0NMfAYIQQVVUSLry5xPU9ATRIG6RMI4Q0CDXSYMIugHXSsAAsPLnEOIg0NIfBLry5wkC+kAhBgAToSc72omhpD+powH+INdJgQELuiHXSsAAsPLnESDXCwLABPLnEfpE+Cj6RFAzulITvRKw8ucRMNM/MdM/MdMfIfgjvPgjgQ4QoBO7ErDy5w3TBwHBA/LnE9Qx0QKCMFRPUy1BVVRIyMs/zMn5AMjL/8mCmFRPUy1BVVRILU1MLURTQS00NC12McjLpwcAWslaFPkxAPLnEANwA6EStgly+wJxcIAYyMsFUATPFiP6AhPLaRLLAMzJgED7AK+nxMs=";

/// `submit#4d4c4434 query_id:uint64 envelope:^Cell signature:^Cell`.
pub const MLDSA44_AUTH_SUBMIT_OPCODE: u32 = 0x4d4c_4434;
/// `auth#41555448 request:^Cell cosignature:(Maybe ^Cell)`.
pub const AUTH_ENVELOPE_OPCODE: u32 = 0x4155_5448;
/// Owner-only `stage_auth#41475008 query_id global_id expected_auth_epoch module`.
pub const AGENT_STAGE_AUTH_OPCODE: u32 = 0x4147_5008;
/// ASCII "TOS-AUTH": the tag of the request commitment every root signs.
pub const AUTH_REQUEST_TAG: u64 = 0x544f_532d_4155_5448;
/// The exact Pure ML-DSA-44 context of the module's signatures.
pub const MLDSA44_AUTH_CONTEXT: &[u8] = b"TOS-AUTH-ML-DSA-44-v1";
/// Request kind that executes an unsigned controller-action payload.
pub const AUTH_KIND_EXECUTE: u8 = 0;
/// The module refuses a request valid for longer than this.
pub const MLDSA44_AUTH_MAX_TTL_SECS: u32 = 3_600;
/// `get_auth_state` modes.
pub const AUTH_MODE_LEGACY: u8 = 0;
pub const AUTH_MODE_STAGED: u8 = 1;
pub const AUTH_MODE_MODULE_ONLY: u8 = 2;
pub const AUTH_MODE_HYBRID: u8 = 3;

const CHAIN_CHUNK_BYTES: usize = 127;

/// `bytes` as the canonical byte chain the module stores and PQCHECKSIG reads:
/// full 127-byte cells, one continuation each, a non-empty last cell, no
/// length prefix.
pub fn byte_chain(bytes: &[u8]) -> anyhow::Result<Cell> {
    ensure!(!bytes.is_empty(), "a byte chain carries at least one byte");
    let mut next: Option<Cell> = None;
    for chunk in bytes.chunks(CHAIN_CHUNK_BYTES).rev() {
        let mut cell = BuilderData::new();
        let bits = chunk.len().checked_mul(8).ok_or_else(|| anyhow!("chain chunk overflow"))?;
        cell.append_raw(chunk, bits)?;
        if let Some(link) = next {
            cell.checked_append_reference(link)?;
        }
        next = Some(cell.into_cell()?);
    }
    next.ok_or_else(|| anyhow!("a byte chain carries at least one byte"))
}

/// The bytes of a canonical byte chain of exactly `expected` bytes; anything
/// [`byte_chain`] would not write is refused.
pub fn read_byte_chain(chain: &Cell, expected: usize) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(expected);
    let mut cursor = chain.clone();
    loop {
        ensure!(cursor.cell_type() == CellType::Ordinary, "byte chain cell is not ordinary");
        let mut cell = SliceData::load_cell(cursor.clone())?;
        let bits = cell.remaining_bits();
        ensure!(bits % 8 == 0, "byte chain cell is not byte-aligned");
        let length = bits / 8;
        let total = bytes.len().checked_add(length).ok_or_else(|| anyhow!("chain overflow"))?;
        ensure!(length > 0 && total <= expected, "byte chain is not {expected} bytes");
        bytes.extend_from_slice(&cell.get_next_bytes(length)?);
        match cell.remaining_references() {
            0 => break,
            1 => {
                ensure!(length == CHAIN_CHUNK_BYTES, "byte chain is not canonical");
                cursor = cell.checked_drain_reference()?;
            }
            _ => bail!("byte chain cell has more than one continuation"),
        }
    }
    ensure!(bytes.len() == expected, "byte chain is not {expected} bytes");
    Ok(bytes)
}

/// A module address the account's `auth_module_hash` accepts: standard,
/// non-anycast, in the account's workchain, not the account itself.
pub fn check_module_address(module: &MsgAddressInt, account: &MsgAddressInt) -> anyhow::Result<()> {
    ensure!(
        matches!(module, MsgAddressInt::AddrStd(std) if std.anycast.is_none()),
        "an authentication module is a standard non-anycast address"
    );
    ensure!(
        module.workchain_id() == account.workchain_id(),
        "an authentication module must be in the account's workchain"
    );
    ensure!(module != account, "an account cannot be its own authentication module");
    Ok(())
}

/// The ML-DSA-44 authentication module: immutable, ownerless, relayer-funded.
pub struct Mldsa44AuthModule;

/// What `get_mldsa44_config` reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mldsa44AuthConfig {
    pub global_id: i32,
    pub public_key: Vec<u8>,
}

impl Mldsa44AuthModule {
    pub fn code() -> anyhow::Result<Cell> {
        read_single_root_boc(base64_decode(MLDSA44_AUTH_MODULE_CODE_B64)?)
    }

    /// `global_id:int32 public_key:^Cell` with the key as a canonical chain.
    pub fn build_data(global_id: i32, public_key: &[u8]) -> anyhow::Result<Cell> {
        ensure!(
            public_key.len() == NATIVE_REGISTRY_PUBLIC_KEY_BYTES,
            "an ML-DSA-44 public key is {NATIVE_REGISTRY_PUBLIC_KEY_BYTES} bytes, not {}",
            public_key.len()
        );
        let mut data = BuilderData::new();
        data.append_i32(global_id)?;
        data.checked_append_reference(byte_chain(public_key)?)?;
        data.into_cell()
    }

    pub fn build_state_init(global_id: i32, public_key: &[u8]) -> anyhow::Result<StateInit> {
        Ok(StateInit::with_code_and_data(Self::code()?, Self::build_data(global_id, public_key)?))
    }

    pub fn calculate_address(
        workchain: i32,
        global_id: i32,
        public_key: &[u8],
    ) -> anyhow::Result<MsgAddressInt> {
        let state = Self::build_state_init(global_id, public_key)?.write_to_new_cell()?;
        MsgAddressInt::with_params(workchain, state.into_cell()?.hash(0))
    }

    pub async fn get_config(
        provider: &dyn ContractProvider,
        module: &MsgAddressInt,
    ) -> anyhow::Result<Mldsa44AuthConfig> {
        let stack = provider.get_method(module.to_string(), "get_mldsa44_config", vec![]).await?;
        Self::decode_config(&stack)
    }

    pub fn decode_config(
        stack: &common::tvm_stack_parser::TvmStackParser,
    ) -> anyhow::Result<Mldsa44AuthConfig> {
        let global_id = i32::try_from(stack.i64(0)?).context("module network exceeds int32")?;
        let public_key = read_byte_chain(&stack.cell(1)?, NATIVE_REGISTRY_PUBLIC_KEY_BYTES)?;
        Ok(Mldsa44AuthConfig { global_id, public_key })
    }
}

/// The Agent Account's authentication state (`get_auth_state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentAuthState {
    pub mode: u8,
    pub epoch: u64,
    pub nonce: u64,
    pub module_hash: [u8; 32],
}

impl AgentAuthState {
    pub async fn get(
        provider: &dyn ContractProvider,
        account: &MsgAddressInt,
    ) -> anyhow::Result<Self> {
        let stack = provider.get_method(account.to_string(), "get_auth_state", vec![]).await?;
        Self::decode(&stack)
    }

    pub fn decode(stack: &common::tvm_stack_parser::TvmStackParser) -> anyhow::Result<Self> {
        let mode = u8::try_from(stack.u64(0)?).context("auth mode exceeds uint8")?;
        ensure!(mode <= AUTH_MODE_HYBRID, "unknown Agent Account auth mode {mode}");
        let module_hash: [u8; 32] = stack
            .number_bytes(3, 32)?
            .try_into()
            .map_err(|_| anyhow!("auth module hash is not 256 bits"))?;
        Ok(Self { mode, epoch: stack.u64(1)?, nonce: stack.u64(2)?, module_hash })
    }

    /// The address the state names in `workchain`, or `None` without a module.
    pub fn module_address(&self, workchain: i32) -> anyhow::Result<Option<MsgAddressInt>> {
        if self.mode == AUTH_MODE_LEGACY {
            return Ok(None);
        }
        Ok(Some(MsgAddressInt::with_params(workchain, SliceData::from(self.module_hash))?))
    }
}

/// The owner message that stages `module` while the account is still in
/// legacy or staged mode. The contract then advances `controller_epoch` and
/// `seqno`, starts a new auth epoch and resets the auth nonce.
pub fn build_stage_auth_message(
    query_id: u64,
    global_id: i32,
    expected_auth_epoch: u64,
    module: &MsgAddressInt,
) -> anyhow::Result<Cell> {
    let mut body = BuilderData::new();
    body.append_u32(AGENT_STAGE_AUTH_OPCODE)?
        .append_u64(query_id)?
        .append_i32(global_id)?
        .append_u64(expected_auth_epoch)?;
    module.write_to(&mut body)?;
    body.into_cell()
}

/// `request$_ global_id:int32 account:MsgAddressInt epoch:uint64 nonce:uint64
/// valid_until:uint32 kind:uint8 payload:^Cell`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthRequest {
    pub global_id: i32,
    pub account: MsgAddressInt,
    pub epoch: u64,
    pub nonce: u64,
    pub valid_until: u32,
    pub kind: u8,
    pub payload: Cell,
}

impl AuthRequest {
    pub fn to_cell(&self) -> anyhow::Result<Cell> {
        ensure!(self.kind == AUTH_KIND_EXECUTE, "only execute requests (kind 0) are supported");
        let mut request = BuilderData::new();
        request.append_i32(self.global_id)?;
        self.account.write_to(&mut request)?;
        request.append_u64(self.epoch)?.append_u64(self.nonce)?.append_u32(self.valid_until)?;
        request.append_u8(self.kind)?;
        request.checked_append_reference(self.payload.clone())?;
        request.into_cell()
    }

    /// Reads a request, refusing trailing data and every kind but execute.
    pub fn parse(cell: &Cell) -> anyhow::Result<Self> {
        let mut s = SliceData::load_cell(cell.clone())?;
        let global_id = s.get_next_i32()?;
        let account = MsgAddressInt::construct_from(&mut s)?;
        let epoch = s.get_next_u64()?;
        let nonce = s.get_next_u64()?;
        let valid_until = s.get_next_u32()?;
        let kind = s.get_next_byte()?;
        let payload = s.checked_drain_reference()?;
        ensure!(
            s.remaining_bits() == 0 && s.remaining_references() == 0,
            "AUTH request has trailing data"
        );
        ensure!(kind == AUTH_KIND_EXECUTE, "AUTH request kind {kind} is not execute");
        Ok(Self { global_id, account, epoch, nonce, valid_until, kind, payload })
    }
}

/// The 32 bytes every authentication root signs: the hash of
/// `uint64("TOS-AUTH") ^request`.
pub fn auth_request_commitment(request: &Cell) -> anyhow::Result<[u8; 32]> {
    let mut commitment = BuilderData::new();
    commitment.append_u64(AUTH_REQUEST_TAG)?;
    commitment.checked_append_reference(request.clone())?;
    Ok(*commitment.into_cell()?.repr_hash().as_array())
}

/// The AUTH envelope with an explicitly absent cosignature (Maybe bit 0):
/// hybrid mode is not driven by this route.
pub fn build_auth_envelope(request: &Cell) -> anyhow::Result<Cell> {
    let mut envelope = BuilderData::new();
    envelope.append_u32(AUTH_ENVELOPE_OPCODE)?;
    envelope.checked_append_reference(request.clone())?;
    envelope.append_bit_zero()?;
    envelope.into_cell()
}

/// Pure ML-DSA-44 over the request commitment under [`MLDSA44_AUTH_CONTEXT`].
pub fn sign_auth_request(seed: &[u8; 32], request: &Cell) -> anyhow::Result<Vec<u8>> {
    let commitment = auth_request_commitment(request)?;
    let signed = sign_ml_dsa_44(seed, &commitment, MLDSA44_AUTH_CONTEXT)?;
    verify_ml_dsa_44(&signed.public_key, &signed.signature, &commitment, MLDSA44_AUTH_CONTEXT)
        .context("the fresh AUTH signature does not verify")?;
    Ok(signed.signature)
}

/// Verifies an AUTH signature exactly as the module will.
pub fn verify_auth_request(
    public_key: &[u8],
    signature: &[u8],
    request: &Cell,
) -> anyhow::Result<()> {
    verify_ml_dsa_44(
        public_key,
        signature,
        &auth_request_commitment(request)?,
        MLDSA44_AUTH_CONTEXT,
    )
}

/// The relayer's body for the module.
pub fn build_mldsa44_submit(
    query_id: u64,
    envelope: &Cell,
    signature: &[u8],
) -> anyhow::Result<Cell> {
    ensure!(
        signature.len() == NATIVE_REGISTRY_SIGNATURE_BYTES,
        "an ML-DSA-44 signature is {NATIVE_REGISTRY_SIGNATURE_BYTES} bytes, not {}",
        signature.len()
    );
    let mut body = BuilderData::new();
    body.append_u32(MLDSA44_AUTH_SUBMIT_OPCODE)?.append_u64(query_id)?;
    body.checked_append_reference(envelope.clone())?;
    body.checked_append_reference(byte_chain(signature)?)?;
    body.into_cell()
}

/// A submission read back in full: every layer canonical, no trailing data,
/// no cosignature, an execute request.
#[derive(Clone, Debug)]
pub struct ParsedMldsa44Submission {
    pub query_id: u64,
    pub envelope: Cell,
    pub request: AuthRequest,
    pub signature: Vec<u8>,
}

pub fn parse_mldsa44_submit(body: &Cell) -> anyhow::Result<ParsedMldsa44Submission> {
    let mut s = SliceData::load_cell(body.clone())?;
    ensure!(s.get_next_u32()? == MLDSA44_AUTH_SUBMIT_OPCODE, "not an ML-DSA-44 submission");
    let query_id = s.get_next_u64()?;
    let envelope = s.checked_drain_reference()?;
    let signature_chain = s.checked_drain_reference()?;
    ensure!(
        s.remaining_bits() == 0 && s.remaining_references() == 0,
        "ML-DSA-44 submission has trailing data"
    );
    let signature = read_byte_chain(&signature_chain, NATIVE_REGISTRY_SIGNATURE_BYTES)?;
    let mut e = SliceData::load_cell(envelope.clone())?;
    ensure!(e.get_next_u32()? == AUTH_ENVELOPE_OPCODE, "not an AUTH envelope");
    let request_cell = e.checked_drain_reference()?;
    ensure!(!e.get_next_bit()?, "this route carries no cosignature");
    ensure!(
        e.remaining_bits() == 0 && e.remaining_references() == 0,
        "AUTH envelope has trailing data"
    );
    let request = AuthRequest::parse(&request_cell)?;
    Ok(ParsedMldsa44Submission { query_id, envelope, request, signature })
}

/// Client-side bounds the module and the account will both apply.
pub fn check_auth_window(
    valid_until: u32,
    chain_now: u32,
    default_task_timeout_secs: u64,
) -> anyhow::Result<()> {
    ensure!(valid_until > chain_now, "valid_until must be after the current chain time");
    let ttl = u64::from(valid_until - chain_now);
    ensure!(
        ttl <= u64::from(MLDSA44_AUTH_MAX_TTL_SECS),
        "valid_until is more than {MLDSA44_AUTH_MAX_TTL_SECS} seconds after the chain time"
    );
    ensure!(
        ttl <= default_task_timeout_secs,
        "valid_until exceeds the Agent Account default_task_timeout"
    );
    Ok(())
}

/// The module address `module` must equal the account's staged root.
pub fn require_staged_module(
    state: &AgentAuthState,
    account: &MsgAddressInt,
    module: &MsgAddressInt,
) -> anyhow::Result<()> {
    check_module_address(module, account)?;
    ensure!(
        state.mode == AUTH_MODE_STAGED || state.mode == AUTH_MODE_MODULE_ONLY,
        "the Agent Account auth mode {} does not accept a module-only request",
        state.mode
    );
    let expected = state.module_address(account.workchain_id())?;
    ensure!(
        expected.as_ref() == Some(module),
        "the Agent Account's authentication module is not this controller's ML-DSA-44 module"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_registry::native_public_key_from_seed;

    fn account() -> MsgAddressInt {
        MsgAddressInt::with_standart(None, 0, [0x31; 32].into()).unwrap()
    }

    fn payload() -> Cell {
        let mut b = BuilderData::new();
        b.append_u32(0x4147_5004).unwrap();
        b.into_cell().unwrap()
    }

    fn request() -> AuthRequest {
        AuthRequest {
            global_id: 42,
            account: account(),
            epoch: 1,
            nonce: 0,
            valid_until: 1_000,
            kind: AUTH_KIND_EXECUTE,
            payload: payload(),
        }
    }

    #[test]
    fn byte_chains_split_at_127_bytes_and_refuse_other_shapes() {
        let key = native_public_key_from_seed(&[7; 32]);
        let chain = byte_chain(&key).unwrap();
        // 1,312 = 10 * 127 + 42: eleven cells.
        let mut cells = 1;
        let mut cursor = chain.clone();
        while cursor.references_count() == 1 {
            assert_eq!(cursor.bit_length(), 127 * 8);
            cursor = cursor.reference(0).unwrap();
            cells += 1;
        }
        assert_eq!(cells, 11);
        assert_eq!(cursor.bit_length(), 42 * 8);
        assert_eq!(read_byte_chain(&chain, 1312).unwrap(), key);
        assert!(read_byte_chain(&chain, 1311).is_err());
        assert!(byte_chain(&[]).is_err());
        // A short non-final cell is not canonical.
        let mut head = BuilderData::new();
        head.append_raw(&key[..126], 126 * 8).unwrap();
        head.checked_append_reference(byte_chain(&key[126..]).unwrap()).unwrap();
        assert!(read_byte_chain(&head.into_cell().unwrap(), 1312).is_err());
    }

    #[test]
    fn request_layout_is_exact_and_round_trips() {
        let r = request();
        let cell = r.to_cell().unwrap();
        let mut expected = BuilderData::new();
        expected.append_i32(42).unwrap();
        account().write_to(&mut expected).unwrap();
        expected.append_u64(1).unwrap().append_u64(0).unwrap().append_u32(1_000).unwrap();
        expected.append_u8(0).unwrap();
        expected.checked_append_reference(payload()).unwrap();
        assert_eq!(cell, expected.into_cell().unwrap());
        assert_eq!(AuthRequest::parse(&cell).unwrap(), r);
        let other_kind = AuthRequest { kind: 1, ..request() };
        assert!(other_kind.to_cell().is_err());
    }

    #[test]
    fn the_commitment_tags_the_request_reference() {
        let cell = request().to_cell().unwrap();
        let mut tagged = BuilderData::new();
        tagged.append_raw(b"TOS-AUTH", 64).unwrap();
        tagged.checked_append_reference(cell.clone()).unwrap();
        assert_eq!(
            auth_request_commitment(&cell).unwrap(),
            *tagged.into_cell().unwrap().repr_hash().as_array()
        );
    }

    #[test]
    fn a_signature_verifies_only_under_its_own_context_and_request() {
        let seed = [9; 32];
        let key = native_public_key_from_seed(&seed);
        let cell = request().to_cell().unwrap();
        let signature = sign_auth_request(&seed, &cell).unwrap();
        verify_auth_request(&key, &signature, &cell).unwrap();
        let other = AuthRequest { nonce: 1, ..request() }.to_cell().unwrap();
        assert!(verify_auth_request(&key, &signature, &other).is_err());
        let commitment = auth_request_commitment(&cell).unwrap();
        for context in crate::native_registry::CONTROLLER_SIGNATURE_CONTEXTS {
            if context != MLDSA44_AUTH_CONTEXT {
                assert!(verify_ml_dsa_44(&key, &signature, &commitment, context).is_err());
            }
        }
    }

    #[test]
    fn a_submission_round_trips_and_refuses_altered_layers() {
        let seed = [9; 32];
        let cell = request().to_cell().unwrap();
        let envelope = build_auth_envelope(&cell).unwrap();
        let signature = sign_auth_request(&seed, &cell).unwrap();
        let body = build_mldsa44_submit(5, &envelope, &signature).unwrap();
        let parsed = parse_mldsa44_submit(&body).unwrap();
        assert_eq!(parsed.query_id, 5);
        assert_eq!(parsed.envelope, envelope);
        assert_eq!(parsed.request, request());
        assert_eq!(parsed.signature, signature);
        assert!(build_mldsa44_submit(5, &envelope, &signature[1..]).is_err());

        let mut with_cosignature = BuilderData::new();
        with_cosignature.append_u32(AUTH_ENVELOPE_OPCODE).unwrap();
        with_cosignature.checked_append_reference(cell.clone()).unwrap();
        with_cosignature.append_bit_one().unwrap();
        with_cosignature.checked_append_reference(Cell::default()).unwrap();
        let cosigned = with_cosignature.into_cell().unwrap();
        assert!(
            parse_mldsa44_submit(&build_mldsa44_submit(5, &cosigned, &signature).unwrap()).is_err()
        );

        let mut trailing = BuilderData::from_cell(&body).unwrap();
        trailing.append_bit_zero().unwrap();
        assert!(parse_mldsa44_submit(&trailing.into_cell().unwrap()).is_err());
    }

    #[test]
    fn module_data_and_address_follow_the_key_and_network() {
        let key = native_public_key_from_seed(&[3; 32]);
        let data = Mldsa44AuthModule::build_data(42, &key).unwrap();
        let mut s = SliceData::load_cell(data.clone()).unwrap();
        assert_eq!(s.get_next_i32().unwrap(), 42);
        assert_eq!(read_byte_chain(&s.checked_drain_reference().unwrap(), 1312).unwrap(), key);
        assert!(Mldsa44AuthModule::build_data(42, &key[1..]).is_err());
        let here = Mldsa44AuthModule::calculate_address(0, 42, &key).unwrap();
        assert_ne!(here, Mldsa44AuthModule::calculate_address(0, 43, &key).unwrap());
        let other_key = native_public_key_from_seed(&[4; 32]);
        assert_ne!(here, Mldsa44AuthModule::calculate_address(0, 42, &other_key).unwrap());
    }

    #[test]
    fn the_window_and_the_staged_module_are_checked_before_signing() {
        assert!(check_auth_window(1_100, 1_000, 3_600).is_ok());
        assert!(check_auth_window(1_000, 1_000, 3_600).is_err());
        assert!(check_auth_window(4_601, 1_000, 86_400).is_err());
        assert!(check_auth_window(1_301, 1_000, 300).is_err());

        let module = MsgAddressInt::with_standart(None, 0, [0x77; 32].into()).unwrap();
        let staged =
            AgentAuthState { mode: AUTH_MODE_STAGED, epoch: 1, nonce: 0, module_hash: [0x77; 32] };
        require_staged_module(&staged, &account(), &module).unwrap();
        let elsewhere = AgentAuthState { module_hash: [0x78; 32], ..staged };
        assert!(require_staged_module(&elsewhere, &account(), &module).is_err());
        for mode in [AUTH_MODE_LEGACY, AUTH_MODE_HYBRID] {
            assert!(
                require_staged_module(&AgentAuthState { mode, ..staged }, &account(), &module)
                    .is_err()
            );
        }
        let masterchain = MsgAddressInt::with_standart(None, -1, [0x77; 32].into()).unwrap();
        assert!(require_staged_module(&staged, &account(), &masterchain).is_err());
        assert!(check_module_address(&account(), &account()).is_err());
    }

    #[test]
    fn stage_auth_layout_is_exact() {
        let module = MsgAddressInt::with_standart(None, 0, [0x77; 32].into()).unwrap();
        let body = build_stage_auth_message(9, 42, 3, &module).unwrap();
        let mut s = SliceData::load_cell(body).unwrap();
        assert_eq!(s.get_next_u32().unwrap(), AGENT_STAGE_AUTH_OPCODE);
        assert_eq!(s.get_next_u64().unwrap(), 9);
        assert_eq!(s.get_next_i32().unwrap(), 42);
        assert_eq!(s.get_next_u64().unwrap(), 3);
        assert_eq!(MsgAddressInt::construct_from(&mut s).unwrap(), module);
        assert_eq!(s.remaining_bits(), 0);
    }
}
