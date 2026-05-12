/*
 * Offline determinism + signature-verification tests for
 * `contracts::jvm_wallet::JvmWalletContract`.
 *
 * The point of this test file is to lock the wallet's offline surface:
 *   * The wc=3 address derived by `calculate_address()` is stable
 *     across two builds of the same wallet.
 *   * The Ed25519 signature produced by `sign_execute()` validates
 *     against the wallet's public key for the exact digest
 *     `keccak256(self_addr || nonce || payload)` Wallet.java checks.
 *   * `encode_init_call()` and `encode_execute_call()` produce
 *     byte-identical cells (matching `repr_hash`) on re-run for
 *     identical inputs.
 *
 * Live-validator tests are out of scope here — those belong in an
 * integration harness that can boot a wc=3 node.
 */
use anyhow::Result;
use chain_block::{ed25519_create_private_key, ed25519_verify, keccak256_digest};
use common::signer::Signer;
use contracts::jvm_wallet::{
    build_wallet_single_transfer_payload, JvmWalletContract, U256,
};

/// Deterministic Ed25519 signer over a fixed 32-byte seed. Mirrors
/// `VaultSigner` enough for the `Signer` trait the wallet expects.
struct FixedEd25519Signer {
    seed: [u8; 32],
    public_key: Vec<u8>,
}

impl FixedEd25519Signer {
    fn new(seed: [u8; 32]) -> Self {
        let pk_arr = ed25519_create_private_key(&seed)
            .expect("create private key from seed")
            .verifying_key();
        Self { seed, public_key: pk_arr.to_vec() }
    }
}

#[async_trait::async_trait]
impl Signer for FixedEd25519Signer {
    async fn public_key(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.public_key.clone())
    }
    async fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        let key = ed25519_create_private_key(&self.seed)
            .map_err(|e| anyhow::anyhow!("create private key: {e:?}"))?;
        Ok(key.sign(message).to_vec())
    }
}

fn fixture_seed() -> [u8; 32] {
    // Match the jvm_codec tests' `sample_owner_pubkey` style — every
    // byte is its own index. Any fixed 32-byte sequence works; what
    // matters is determinism.
    let mut v = [0u8; 32];
    for (i, b) in v.iter_mut().enumerate() {
        *b = i as u8;
    }
    v
}

fn fixture_salt() -> [u8; 32] {
    // Different shape from the seed so the two test inputs don't
    // accidentally collide.
    let mut v = [0u8; 32];
    for (i, b) in v.iter_mut().enumerate() {
        *b = (i ^ 0x5a) as u8;
    }
    v
}

fn fixture_class_bytes() -> Vec<u8> {
    b"fake-wallet-class-bytes-for-offline-test".to_vec()
}

async fn build_wallet() -> Result<JvmWalletContract> {
    let signer = FixedEd25519Signer::new(fixture_seed());
    JvmWalletContract::new(
        Box::new(signer),
        [0u8; 32],         // deployer
        fixture_salt(),    // salt
        fixture_class_bytes(),
    )
    .await
}

#[tokio::test]
async fn calculate_address_is_deterministic_across_two_builds() {
    let a = build_wallet().await.expect("build wallet a");
    let b = build_wallet().await.expect("build wallet b");
    assert_eq!(
        a.calculate_address(),
        b.calculate_address(),
        "wc=3 address must be stable across two wallet builds with identical inputs"
    );
}

#[tokio::test]
async fn sign_execute_produces_valid_ed25519_signature() {
    let wallet = build_wallet().await.expect("build wallet");
    let nonce = U256::from_u64(42);
    let payload = build_wallet_single_transfer_payload(
        0,                // dest workchain
        &[0xabu8; 32],    // dest addr
        1_234_567u128,    // value tomis
        b"hello-wallet",  // body bytes
    )
    .expect("build payload");

    let signature = wallet
        .sign_execute(nonce, &payload)
        .await
        .expect("sign execute");
    assert_eq!(signature.len(), 64);

    // Recompute the digest the Wallet.java side checks and verify the
    // signature explicitly against the public key.
    let mut buf = Vec::new();
    buf.extend_from_slice(&wallet.calculate_address());
    buf.extend_from_slice(nonce.as_bytes());
    buf.extend_from_slice(&payload);
    let digest = keccak256_digest(&buf);

    let public_key = wallet.owner_pubkey().to_vec();
    ed25519_verify(&public_key, &digest, &signature)
        .expect("Ed25519 signature must verify against owner pubkey");
}

#[tokio::test]
async fn encode_init_call_is_deterministic() {
    let wallet = build_wallet().await.expect("build wallet");
    let a = wallet.encode_init_call().expect("init a");
    let b = wallet.encode_init_call().expect("init b");
    assert_eq!(
        a.repr_hash(),
        b.repr_hash(),
        "encode_init_call must be byte-stable"
    );
}

#[tokio::test]
async fn encode_execute_call_is_deterministic() {
    let wallet = build_wallet().await.expect("build wallet");
    let nonce = U256::from_u64(1);
    let payload = build_wallet_single_transfer_payload(
        0,
        &[0u8; 32],
        100,
        &[],
    )
    .expect("build payload");
    let sig = wallet.sign_execute(nonce, &payload).await.expect("sign");

    let a = wallet.encode_execute_call(nonce, &payload, &sig).expect("execute a");
    let b = wallet.encode_execute_call(nonce, &payload, &sig).expect("execute b");
    assert_eq!(
        a.repr_hash(),
        b.repr_hash(),
        "encode_execute_call must be byte-stable"
    );
}

#[tokio::test]
async fn salt_change_changes_address() {
    let signer_a = FixedEd25519Signer::new(fixture_seed());
    let signer_b = FixedEd25519Signer::new(fixture_seed());
    let wallet_a = JvmWalletContract::new(
        Box::new(signer_a),
        [0u8; 32],
        fixture_salt(),
        fixture_class_bytes(),
    )
    .await
    .expect("wallet a");

    let mut alt_salt = fixture_salt();
    alt_salt[0] ^= 0xff;

    let wallet_b = JvmWalletContract::new(
        Box::new(signer_b),
        [0u8; 32],
        alt_salt,
        fixture_class_bytes(),
    )
    .await
    .expect("wallet b");

    assert_ne!(
        wallet_a.calculate_address(),
        wallet_b.calculate_address(),
        "different salts must derive different wc=3 addresses"
    );
}
