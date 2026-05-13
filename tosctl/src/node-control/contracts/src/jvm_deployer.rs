/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
/*
 * `JvmDeployerContract` — wc=3 focused deploy-router, mirror of the
 * `java/lang/Deployer` reference (jvm/avata/rt/java/lang/Deployer.java).
 *
 * Same shape as `JvmWalletContract` but the signed payload triggers
 * `System.createAccount` instead of `System.sendMessage`.  Used by
 * `tosctl jw deploy --via <deployer-name>` to spawn a fresh wc=3
 * account from off-chain — the host's `action_create_account` gate
 * requires a same-workchain sender, so the Deployer is the only path
 * to deploy further wc=3 contracts after genesis.
 *
 * Storage / manifest layout intentionally distinct from
 * `JvmWalletContract`: slot names use the `Deployer.<name>` prefix
 * (matches the Java class), and the manifest carries
 * `(init, deploy, getNonce)` instead of `(init, execute, getNonce)`.
 * The address binds the manifest cell hash, so a Deployer and a
 * Wallet built from the same (deployer, salt, class_bytes) NEVER
 * collide.
 */
use crate::jvm_codec::{
    compute_jvm_address_commit, compute_jvm_class_hash,
    compute_jvm_manifest_root_hash, derive_jvm_contract_address,
    encode_jvm_args, encode_jvm_call_descriptor,
    encode_jvm_method_manifest, JvmArgs, JvmCallDescriptor,
    JvmMethodManifestEntry, JvmTypedArg,
};
use crate::jvm_wallet::U256;
use anyhow::{Context, Result};
use chain_block::{keccak256_digest, Cell};
use common::signer::Signer;

/// Canonical `java/lang/Deployer` class name.  Pinned consensus-stable;
/// don't paraphrase.
pub const JVM_DEPLOYER_CLASS_NAME: &str = "java/lang/Deployer";

/// ABI signatures for the three `@ContractEntry` methods on
/// Deployer.java.  `init` and `getNonce` reuse the same selectors as
/// Wallet because they take the same args (Bytes32 ownerPubKey / void
/// respectively); only `deploy` is unique.
pub const ABI_SIG_DEPLOYER_INIT: &str = "init(bytes32)";
pub const ABI_SIG_DEPLOYER_DEPLOY: &str =
    "deploy(uint256,bytes32,bytes,uint256,bytes,bytes)";
pub const ABI_SIG_DEPLOYER_GET_NONCE: &str = "getNonce()";

/// JVM type specs — must match what the Avata javac emits for
/// `Deployer.init` / `Deployer.deploy` / `Deployer.getNonce`.
pub const JVM_SPEC_DEPLOYER_INIT: &str = "(Ljava/lang/Bytes32;)V";
pub const JVM_SPEC_DEPLOYER_DEPLOY: &str =
    "(Ljava/lang/Uint256;Ljava/lang/Bytes32;Ljava/lang/Bytes;\
     Ljava/lang/Uint256;Ljava/lang/Bytes;Ljava/lang/Bytes;)V";
pub const JVM_SPEC_DEPLOYER_GET_NONCE: &str = "()V";

pub const JVM_METHOD_NAME_DEPLOYER_INIT: &str = "init";
pub const JVM_METHOD_NAME_DEPLOYER_DEPLOY: &str = "deploy";
pub const JVM_METHOD_NAME_DEPLOYER_GET_NONCE: &str = "getNonce";

/// 4-byte ABI method id (keccak256(signature)[0..4]).
pub fn deployer_method_id_of(signature: &str) -> u32 {
    let h = keccak256_digest(signature.as_bytes());
    u32::from_be_bytes([h[0], h[1], h[2], h[3]])
}

/// Build the canonical 3-entry Deployer manifest.  Entry order
/// (init, deploy, getNonce) is consensus-stable because it influences
/// the manifest cell's hash which is then bound into the Deployer's
/// wc=3 address.  Don't permute.
pub fn build_deployer_manifest_entries() -> Vec<JvmMethodManifestEntry> {
    vec![
        JvmMethodManifestEntry::new(
            deployer_method_id_of(ABI_SIG_DEPLOYER_INIT),
            JVM_DEPLOYER_CLASS_NAME,
            JVM_METHOD_NAME_DEPLOYER_INIT,
            JVM_SPEC_DEPLOYER_INIT,
        ),
        JvmMethodManifestEntry::new(
            deployer_method_id_of(ABI_SIG_DEPLOYER_DEPLOY),
            JVM_DEPLOYER_CLASS_NAME,
            JVM_METHOD_NAME_DEPLOYER_DEPLOY,
            JVM_SPEC_DEPLOYER_DEPLOY,
        ),
        JvmMethodManifestEntry::new(
            deployer_method_id_of(ABI_SIG_DEPLOYER_GET_NONCE),
            JVM_DEPLOYER_CLASS_NAME,
            JVM_METHOD_NAME_DEPLOYER_GET_NONCE,
            JVM_SPEC_DEPLOYER_GET_NONCE,
        ),
    ]
}

/// Compute the Deployer manifest cell.
pub fn build_deployer_manifest_cell() -> Result<Cell> {
    let entries = build_deployer_manifest_entries();
    encode_jvm_method_manifest(&entries)
        .context("encode deployer method manifest failed")
}

/// Compute the digest Deployer.java's `deploy(...)` entry verifies
/// against the supplied signature: `keccak256(self_addr || nonce ||
/// destAccountId || keccak256(stateInit) || value || keccak256(body))`.
/// Exposed as a free function so off-chain tooling and the parity-
/// vector test can compute the digest with an arbitrary address.
///
/// Layout MUST match `java.lang.Deployer.deployDigest`:
///   selfBytes(32) || nonce(32) || destAccountId(32) ||
///   keccak256(stateInit)(32) || value(32) || keccak256(body)(32).
pub fn compute_deployer_deploy_digest(
    self_addr: &[u8; 32],
    nonce: U256,
    dest_account_id: &[u8; 32],
    state_init: &[u8],
    value: U256,
    body: &[u8],
) -> [u8; 32] {
    let state_init_hash = keccak256_digest(state_init);
    let body_hash = keccak256_digest(body);

    let mut buf = Vec::with_capacity(32 * 6);
    buf.extend_from_slice(self_addr);
    buf.extend_from_slice(nonce.as_bytes());
    buf.extend_from_slice(dest_account_id);
    buf.extend_from_slice(&state_init_hash);
    buf.extend_from_slice(value.as_bytes());
    buf.extend_from_slice(&body_hash);
    keccak256_digest(&buf)
}

/// wc=3 deploy-router contract abstraction.
pub struct JvmDeployerContract {
    signer: Box<dyn Signer>,
    deployer: [u8; 32],
    salt: [u8; 32],
    class_hash: [u8; 32],
    #[allow(dead_code)]
    manifest_cell: Cell,
    manifest_root_hash: [u8; 32],
    owner_pubkey: [u8; 32],
    address: [u8; 32],
}

impl JvmDeployerContract {
    pub async fn new(
        signer: Box<dyn Signer>,
        deployer: [u8; 32],
        salt: [u8; 32],
        class_bytes: Vec<u8>,
    ) -> Result<Self> {
        let owner_pubkey_vec = signer.public_key().await?;
        if owner_pubkey_vec.len() != 32 {
            anyhow::bail!(
                "JvmDeployerContract: signer public_key must be 32 bytes, got {}",
                owner_pubkey_vec.len()
            );
        }
        let mut owner_pubkey = [0u8; 32];
        owner_pubkey.copy_from_slice(&owner_pubkey_vec);

        let class_hash = compute_jvm_class_hash(&class_bytes);
        let manifest_cell = build_deployer_manifest_cell()?;
        let manifest_root_hash =
            compute_jvm_manifest_root_hash(Some(&manifest_cell));

        let init_args = encode_jvm_args(&JvmArgs::new(vec![
            JvmTypedArg::bytes32(owner_pubkey),
        ]))
        .context("encode deployer init args failed")?;
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
            class_hash,
            manifest_cell,
            manifest_root_hash,
            owner_pubkey,
            address,
        })
    }

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

    pub fn owner_pubkey(&self) -> &[u8; 32] {
        &self.owner_pubkey
    }

    /// Encode the one-time `init(Bytes32)` call descriptor.
    pub fn encode_init_call(&self) -> Result<Cell> {
        let args = JvmArgs::new(vec![JvmTypedArg::bytes32(self.owner_pubkey)]);
        let descriptor = JvmCallDescriptor::new(
            deployer_method_id_of(ABI_SIG_DEPLOYER_INIT),
            args,
        );
        encode_jvm_call_descriptor(&descriptor)
            .context("encode deployer init call descriptor failed")
    }

    /// Compute the digest Deployer.deploy(...) checks:
    /// keccak256(self_addr || nonce || destAccountId
    ///           || keccak256(stateInit) || value || keccak256(body)).
    pub fn deploy_digest(
        &self,
        nonce: U256,
        dest_account_id: &[u8; 32],
        state_init: &[u8],
        value: U256,
        body: &[u8],
    ) -> [u8; 32] {
        compute_deployer_deploy_digest(
            &self.address,
            nonce,
            dest_account_id,
            state_init,
            value,
            body,
        )
    }

    /// Sign the deploy digest with the Deployer owner's Ed25519 key.
    pub async fn sign_deploy(
        &self,
        nonce: U256,
        dest_account_id: &[u8; 32],
        state_init: &[u8],
        value: U256,
        body: &[u8],
    ) -> Result<Vec<u8>> {
        let digest =
            self.deploy_digest(nonce, dest_account_id, state_init, value, body);
        let sig = self.signer.sign(&digest).await?;
        if sig.len() != 64 {
            anyhow::bail!(
                "JvmDeployerContract: signer returned {}-byte signature, expected 64",
                sig.len()
            );
        }
        Ok(sig)
    }

    /// Encode the `deploy(Uint256 nonce, Bytes32 destAccountId, Bytes
    /// stateInit, Uint256 value, Bytes body, Bytes signature)` call
    /// descriptor.  Signature MUST come from `sign_deploy` above.
    pub fn encode_deploy_call(
        &self,
        nonce: U256,
        dest_account_id: &[u8; 32],
        state_init: &[u8],
        value: U256,
        body: &[u8],
        signature: &[u8],
    ) -> Result<Cell> {
        if signature.len() != 64 {
            anyhow::bail!(
                "JvmDeployerContract: expected 64-byte Ed25519 signature, got {}",
                signature.len()
            );
        }
        let args = JvmArgs::new(vec![
            JvmTypedArg::uint256(nonce.into_bytes()),
            JvmTypedArg::bytes32(*dest_account_id),
            JvmTypedArg::raw_bytes(state_init.to_vec()),
            JvmTypedArg::uint256(value.into_bytes()),
            JvmTypedArg::raw_bytes(body.to_vec()),
            JvmTypedArg::raw_bytes(signature.to_vec()),
        ]);
        let descriptor = JvmCallDescriptor::new(
            deployer_method_id_of(ABI_SIG_DEPLOYER_DEPLOY),
            args,
        );
        encode_jvm_call_descriptor(&descriptor)
            .context("encode deployer deploy call descriptor failed")
    }
}
