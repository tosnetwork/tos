/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
/*
 * `JvmWalletContract` — wc=3 single-owner Ed25519 wallet, mirror of the
 * `java/lang/Wallet` reference (jvm/avata/rt/java/lang/Wallet.java).
 *
 * This is a *contract-level* helper: given a `Signer` (typically a
 * `VaultSigner` over an Ed25519 keypair), a deployer account-id, a salt,
 * and the compiled wallet class bytes, it computes the wc=3 contract
 * address and can build `init` / `execute` call descriptors plus the
 * Ed25519 signature over a single-transfer payload.
 *
 * The wc=3 address is derived deterministically by:
 *   class_hash         = sha256(class_bytes)
 *   manifest_root_hash = manifest_cell.hash       (3-entry Wallet manifest)
 *   address_commit     = sha256(deployer || salt || init_args.hash)
 *   address            = sha256("TOS-JVM-CONTRACT-v2"
 *                                || deployer || address_commit
 *                                || class_hash || manifest_root_hash)
 *
 * This module does NOT talk to a validator. The CLI layer
 * (`commands/src/commands/nodectl/jvm_wallet_cmd.rs`) is responsible for
 * pairing this with `ClientJsonRpc::jvm_deploy_contract`,
 * `jvm_call_contract`, `send_boc`, etc.
 */
use crate::jvm_codec::{
    compute_jvm_address_commit, compute_jvm_class_hash,
    compute_jvm_manifest_root_hash, derive_jvm_contract_address,
    encode_action_create_account, encode_jvm_args,
    encode_jvm_call_descriptor, encode_jvm_deploy_descriptor,
    encode_jvm_method_manifest, encode_jvm_state_init_cell,
    JvmArgs, JvmCallDescriptor, JvmDeployDescriptor,
    JvmMethodManifestEntry, JvmTypedArg,
};
use anyhow::{Context, Result};
use chain_block::{keccak256_digest, BuilderData, Cell, IBitstring};
use common::signer::Signer;

/// Canonical `java/lang/Wallet` class name (matches Wallet.java's
/// package + class). The deploy descriptor commits to this string and
/// the address derivation binds the manifest cell hash that contains it.
pub const JVM_WALLET_CLASS_NAME: &str = "java/lang/Wallet";

/// ABI signatures of the three `@ContractEntry` methods on Wallet.java.
/// `method_id = keccak256(signature)[0..4]` per the C++ resolver in
/// `jvm/core/dispatch-engine.cpp`.
pub const ABI_SIG_INIT: &str = "init(bytes32)";
pub const ABI_SIG_EXECUTE: &str = "execute(uint256,bytes,bytes)";
pub const ABI_SIG_GET_NONCE: &str = "getNonce()";

/// JVM type specs for the manifest. These must match what the Avata
/// compiler emits for `Wallet.init` / `Wallet.execute` / `Wallet.getNonce`.
pub const JVM_SPEC_INIT: &str = "(Ljava/lang/Bytes32;)V";
pub const JVM_SPEC_EXECUTE: &str =
    "(Ljava/lang/Uint256;Ljava/lang/Bytes;Ljava/lang/Bytes;)V";
pub const JVM_SPEC_GET_NONCE: &str = "()V";

/// Method-name strings as they appear in the manifest.
pub const JVM_METHOD_NAME_INIT: &str = "init";
pub const JVM_METHOD_NAME_EXECUTE: &str = "execute";
pub const JVM_METHOD_NAME_GET_NONCE: &str = "getNonce";

/// Compute the 4-byte ABI method id from a Solidity-style signature
/// (keccak256 over the signature bytes, first four bytes big-endian).
pub fn method_id_of(signature: &str) -> u32 {
    let h = keccak256_digest(signature.as_bytes());
    u32::from_be_bytes([h[0], h[1], h[2], h[3]])
}

/// Build the canonical 3-entry Wallet manifest. The order is
/// (init, execute, getNonce); the entry order is part of the manifest
/// cell layout and therefore part of the deployed contract's address
/// binding — pin it deliberately so two callers always land on the
/// same address for the same (deployer, salt, class_bytes).
pub fn build_wallet_manifest_entries() -> Vec<JvmMethodManifestEntry> {
    vec![
        JvmMethodManifestEntry::new(
            method_id_of(ABI_SIG_INIT),
            JVM_WALLET_CLASS_NAME,
            JVM_METHOD_NAME_INIT,
            JVM_SPEC_INIT,
        ),
        JvmMethodManifestEntry::new(
            method_id_of(ABI_SIG_EXECUTE),
            JVM_WALLET_CLASS_NAME,
            JVM_METHOD_NAME_EXECUTE,
            JVM_SPEC_EXECUTE,
        ),
        JvmMethodManifestEntry::new(
            method_id_of(ABI_SIG_GET_NONCE),
            JVM_WALLET_CLASS_NAME,
            JVM_METHOD_NAME_GET_NONCE,
            JVM_SPEC_GET_NONCE,
        ),
    ]
}

/// Compute the Wallet manifest cell (re-usable across callers that need
/// to bind a contract's manifest hash without instantiating the full
/// `JvmWalletContract`).
pub fn build_wallet_manifest_cell() -> Result<Cell> {
    let entries = build_wallet_manifest_entries();
    encode_jvm_method_manifest(&entries)
        .context("encode wallet method manifest failed")
}

/// Compute the digest Wallet.java's `execute(...)` entry verifies
/// against the supplied signature: `keccak256(self_addr || nonce ||
/// payload)`.  Exposed as a free function so off-chain tooling and the
/// parity-vector test can compute the digest with an arbitrary address
/// (the method on `JvmWalletContract` requires a fully-instantiated
/// signer, which is overkill for the digest itself).
///
/// Layout MUST match `java.lang.Wallet.digest`:
///   selfBytes(32) || nonceBytes(32 BE) || payloadBytes(raw).
pub fn compute_wallet_execute_digest(
    self_addr: &[u8; 32],
    nonce: U256,
    payload: &[u8],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 32 + payload.len());
    buf.extend_from_slice(self_addr);
    buf.extend_from_slice(nonce.as_bytes());
    buf.extend_from_slice(payload);
    keccak256_digest(&buf)
}

/// A 256-bit unsigned integer carried over the wire as 32 big-endian
/// bytes. We use a `[u8; 32]` newtype instead of dragging in a heavier
/// `primitive_types::U256` so the workspace's existing dependency graph
/// is untouched; the Wallet contract only ever sees the byte form.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct U256([u8; 32]);

impl U256 {
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Build a U256 from a `u64`, big-endian padded.
    pub fn from_u64(v: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&v.to_be_bytes());
        Self(bytes)
    }
}

pub struct JvmWalletContract {
    signer: Box<dyn Signer>,
    deployer: [u8; 32],
    salt: [u8; 32],
    class_bytes: Vec<u8>,
    class_hash: [u8; 32],
    manifest_cell: Cell,
    manifest_root_hash: [u8; 32],
    owner_pubkey: [u8; 32],
    address: [u8; 32],
}

impl JvmWalletContract {
    /// Build a wallet helper from its cryptographic + deploy inputs.
    ///
    /// `class_bytes` is the JVM .class blob the host stores at deploy
    /// time. `salt` disambiguates two wallets with the same owner key
    /// and same class (e.g. several wallets for a single user). When in
    /// doubt, derive `salt` from a non-secret per-wallet name with
    /// sha256: that's what the CLI layer does.
    pub async fn new(
        signer: Box<dyn Signer>,
        deployer: [u8; 32],
        salt: [u8; 32],
        class_bytes: Vec<u8>,
    ) -> Result<Self> {
        let owner_pubkey_vec = signer.public_key().await?;
        if owner_pubkey_vec.len() != 32 {
            anyhow::bail!(
                "JvmWalletContract: signer public_key must be 32 bytes, got {}",
                owner_pubkey_vec.len()
            );
        }
        let mut owner_pubkey = [0u8; 32];
        owner_pubkey.copy_from_slice(&owner_pubkey_vec);

        let class_hash = compute_jvm_class_hash(&class_bytes);
        let manifest_cell = build_wallet_manifest_cell()?;
        let manifest_root_hash = compute_jvm_manifest_root_hash(Some(&manifest_cell));

        // address_commit binds (deployer, salt, init_args.hash); init_args
        // is the JvmArgs cell for `init(ownerPubKey:Bytes32)`.
        let init_args = encode_jvm_args(&JvmArgs::new(vec![
            JvmTypedArg::bytes32(owner_pubkey),
        ]))
        .context("encode wallet init args failed")?;
        let address_commit =
            compute_jvm_address_commit(&deployer, &salt, &init_args);
        let address = derive_jvm_contract_address(
            &deployer,
            &address_commit,
            &class_hash,
            &manifest_root_hash,
        );

        Ok(Self {
            signer,
            deployer,
            salt,
            class_bytes,
            class_hash,
            manifest_cell,
            manifest_root_hash,
            owner_pubkey,
            address,
        })
    }

    /// 32-byte wc=3 account-id of this wallet.
    pub fn calculate_address(&self) -> [u8; 32] {
        self.address
    }

    pub fn deployer(&self) -> &[u8; 32] {
        &self.deployer
    }

    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }

    pub fn class_hash(&self) -> &[u8; 32] {
        &self.class_hash
    }

    pub fn manifest_root_hash(&self) -> &[u8; 32] {
        &self.manifest_root_hash
    }

    pub fn manifest_cell(&self) -> &Cell {
        &self.manifest_cell
    }

    pub fn owner_pubkey(&self) -> &[u8; 32] {
        &self.owner_pubkey
    }

    /// Encode the call descriptor for the one-time `init(Bytes32)` call
    /// that installs the owner public key into wallet storage.
    pub fn encode_init_call(&self) -> Result<Cell> {
        let args = JvmArgs::new(vec![JvmTypedArg::bytes32(self.owner_pubkey)]);
        let descriptor =
            JvmCallDescriptor::new(method_id_of(ABI_SIG_INIT), args);
        encode_jvm_call_descriptor(&descriptor)
            .context("encode wallet init call descriptor failed")
    }

    /// Encode a call descriptor for `execute(Uint256 nonce, Bytes payload,
    /// Bytes signature)`. The signature is the Ed25519 signature over
    /// `keccak256(self_addr || nonce || payload)` — see `sign_execute`.
    pub fn encode_execute_call(
        &self,
        nonce: U256,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<Cell> {
        if signature.len() != 64 {
            anyhow::bail!(
                "JvmWalletContract: expected 64-byte Ed25519 signature, got {}",
                signature.len()
            );
        }
        let args = JvmArgs::new(vec![
            JvmTypedArg::uint256(nonce.into_bytes()),
            JvmTypedArg::raw_bytes(payload.to_vec()),
            JvmTypedArg::raw_bytes(signature.to_vec()),
        ]);
        let descriptor =
            JvmCallDescriptor::new(method_id_of(ABI_SIG_EXECUTE), args);
        encode_jvm_call_descriptor(&descriptor)
            .context("encode wallet execute call descriptor failed")
    }

    /// Compute the digest the Wallet.java `execute(...)` entry checks
    /// against: `keccak256(self_addr || nonce || payload)`.
    pub fn execute_digest(&self, nonce: U256, payload: &[u8]) -> [u8; 32] {
        compute_wallet_execute_digest(&self.address, nonce, payload)
    }

    /// Sign the `execute(...)` digest with the wallet's Ed25519 owner
    /// key. Returns a 64-byte signature.
    pub async fn sign_execute(
        &self,
        nonce: U256,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let digest = self.execute_digest(nonce, payload);
        let sig = self.signer.sign(&digest).await?;
        if sig.len() != 64 {
            anyhow::bail!(
                "JvmWalletContract: signer returned {}-byte signature, expected 64",
                sig.len()
            );
        }
        Ok(sig)
    }

    /// Build the consensus-side deploy descriptor (`JVMD` magic).
    ///
    /// The deployer obtains this cell and wraps it in `StateInit` ->
    /// `action_create_account`. The validator decodes the descriptor
    /// server-side and materializes the wc=3 account at
    /// `self.calculate_address()`.
    pub fn encode_deploy_descriptor(&self) -> Result<Cell> {
        let init_args = encode_jvm_args(&JvmArgs::new(vec![
            JvmTypedArg::bytes32(self.owner_pubkey),
        ]))
        .context("encode wallet init args failed")?;
        let descriptor = JvmDeployDescriptor {
            deployer: self.deployer,
            salt: self.salt,
            class_hash: self.class_hash,
            class_name: JVM_WALLET_CLASS_NAME.to_string(),
            class_bytes: self.class_bytes.clone(),
            init_args,
        };
        encode_jvm_deploy_descriptor(&descriptor)
            .context("encode wallet deploy descriptor failed")
    }

    /// Build a complete `action_create_account` OutAction cell ready to
    /// be packed into the deployer wallet's OutActions list.
    ///
    /// `state_init_state_cell` is the JVAC (JvmContractAccountState)
    /// cell the host returns from `jvm_deployContract` — caller should
    /// decode it from the RPC response's `deployDescriptorBoc` and pass
    /// it here.
    ///
    /// The validator gate at `transaction.cpp:2807` requires the sender
    /// to declare `admits_engine_create_account_actions`; at v2 launch
    /// only wc=3 contracts (other JVM accounts) have that capability.
    /// A wc=0 TVM wallet cannot call this directly — for the very first
    /// wc=3 wallet seed via the `jvm-zerostate-from-alloc` Fift word
    /// (Phase F genesis seeding) instead.
    pub fn build_create_account_action(
        &self,
        mode: u8,
        state_init_state_cell: Cell,
        value_tomis: u128,
        init_body: Option<Cell>,
    ) -> Result<Cell> {
        let state_init = encode_jvm_state_init_cell(state_init_state_cell)
            .context("encode wallet state_init failed")?;
        encode_action_create_account(
            mode,
            &self.address,
            state_init,
            value_tomis,
            init_body,
        )
        .context("encode action_create_account failed")
    }
}

/// Build the Wallet.java `execute(...)` payload for a single transfer.
///
/// Wire layout (matches `Wallet.java::dispatch`):
///   count:uint8 || dest_workchain:int32 || dest_addr:bytes32
///                || value:uint256(32B BE) || body_len:uint16 || body:bytes
///
/// For a single transfer count = 1. `value_tomis` is encoded as a 256-bit
/// big-endian integer (Wallet.java widens it to Uint256). `body` is the
/// raw internal-message body the destination receives.
pub fn build_wallet_single_transfer_payload(
    dest_workchain: i32,
    dest_addr: &[u8; 32],
    value_tomis: u128,
    body: &[u8],
) -> Result<Vec<u8>> {
    if body.len() > u16::MAX as usize {
        anyhow::bail!(
            "wallet payload body length {} exceeds u16::MAX",
            body.len()
        );
    }
    let mut buf = Vec::with_capacity(1 + 4 + 32 + 32 + 2 + body.len());
    buf.push(1u8); // count
    buf.extend_from_slice(&dest_workchain.to_be_bytes());
    buf.extend_from_slice(dest_addr);
    let mut value_bytes = [0u8; 32];
    value_bytes[16..].copy_from_slice(&value_tomis.to_be_bytes());
    buf.extend_from_slice(&value_bytes);
    buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
    buf.extend_from_slice(body);
    Ok(buf)
}

/// Build a TVM-style "comment" body cell (`uint32(0) || utf8 text`).
/// Convenience helper for the CLI; matches the `WalletSendCmd`
/// comment encoding used on wc=0.
pub fn build_wallet_comment_body(text: &str) -> Result<Cell> {
    let mut cb = BuilderData::new();
    cb.append_u32(0)
        .context("wallet comment magic append failed")?;
    cb.append_raw(text.as_bytes(), text.len() * 8)
        .context("wallet comment text append failed")?;
    cb.into_cell().context("wallet comment finalize failed")
}
