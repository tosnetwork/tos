/*
 * Offline determinism + signature-verification tests for
 * `contracts::jvm_deployer::JvmDeployerContract`.
 *
 * Same shape as `jvm_wallet_offline.rs`: address determinism, salt
 * sensitivity, init/deploy descriptor byte stability, Ed25519
 * signature validity against the canonical deploy digest the
 * Deployer.java contract checks on-chain.
 */
use anyhow::Result;
use chain_block::{ed25519_create_private_key, ed25519_verify, keccak256_digest};
use common::signer::Signer;
use contracts::jvm_deployer::JvmDeployerContract;
use contracts::jvm_wallet::U256;

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
    // Distinct from the wallet fixture so any cross-contamination
    // between wallet and deployer tests becomes immediately visible.
    let mut v = [0u8; 32];
    for (i, b) in v.iter_mut().enumerate() {
        *b = (0x80 + i) as u8;
    }
    v
}

fn fixture_salt() -> [u8; 32] {
    let mut v = [0u8; 32];
    for (i, b) in v.iter_mut().enumerate() {
        *b = (i ^ 0xa5) as u8;
    }
    v
}

fn fixture_class_bytes() -> Vec<u8> {
    b"fake-deployer-class-bytes-for-offline-test".to_vec()
}

async fn build_deployer() -> Result<JvmDeployerContract> {
    let signer = FixedEd25519Signer::new(fixture_seed());
    JvmDeployerContract::new(
        Box::new(signer),
        [0u8; 32],
        fixture_salt(),
        fixture_class_bytes(),
    )
    .await
}

#[tokio::test]
async fn deployer_address_is_deterministic_across_two_builds() {
    let a = build_deployer().await.expect("build deployer a");
    let b = build_deployer().await.expect("build deployer b");
    assert_eq!(
        a.calculate_address(),
        b.calculate_address(),
        "Deployer wc=3 address must be stable across two builds with identical inputs"
    );
}

#[tokio::test]
async fn deployer_salt_change_changes_address() {
    let signer_a = FixedEd25519Signer::new(fixture_seed());
    let signer_b = FixedEd25519Signer::new(fixture_seed());

    let a = JvmDeployerContract::new(
        Box::new(signer_a),
        [0u8; 32],
        fixture_salt(),
        fixture_class_bytes(),
    )
    .await
    .expect("deployer a");

    let mut alt = fixture_salt();
    alt[0] ^= 0xff;

    let b = JvmDeployerContract::new(
        Box::new(signer_b),
        [0u8; 32],
        alt,
        fixture_class_bytes(),
    )
    .await
    .expect("deployer b");

    assert_ne!(a.calculate_address(), b.calculate_address());
}

#[tokio::test]
async fn encode_init_call_is_deterministic() {
    let d = build_deployer().await.expect("build deployer");
    let a = d.encode_init_call().expect("init a");
    let b = d.encode_init_call().expect("init b");
    assert_eq!(a.repr_hash(), b.repr_hash());
}

#[tokio::test]
async fn sign_deploy_produces_valid_ed25519_signature() {
    let d = build_deployer().await.expect("build deployer");
    let nonce = U256::from_u64(7);
    let dest = [0x42u8; 32];
    let state_init = b"fake-state-init-boc";
    let value = U256::from_u64(1_000_000_000);
    let body = b"deploy-body";

    let sig = d
        .sign_deploy(nonce, &dest, state_init, value, body)
        .await
        .expect("sign deploy");
    assert_eq!(sig.len(), 64);

    // Recompute the digest the Deployer.java side checks and verify
    // explicitly:
    //   keccak256(self_addr || nonce || dest || keccak256(stateInit)
    //             || value || keccak256(body))
    let state_init_hash = keccak256_digest(state_init);
    let body_hash = keccak256_digest(body);
    let mut buf = Vec::new();
    buf.extend_from_slice(&d.calculate_address());
    buf.extend_from_slice(nonce.as_bytes());
    buf.extend_from_slice(&dest);
    buf.extend_from_slice(&state_init_hash);
    buf.extend_from_slice(value.as_bytes());
    buf.extend_from_slice(&body_hash);
    let digest = keccak256_digest(&buf);

    let public_key = d.owner_pubkey().to_vec();
    ed25519_verify(&public_key, &digest, &sig)
        .expect("Ed25519 signature must verify against deployer owner pubkey");
}

#[tokio::test]
async fn encode_deploy_call_is_deterministic() {
    let d = build_deployer().await.expect("build deployer");
    let nonce = U256::from_u64(11);
    let dest = [0x01u8; 32];
    let state_init = b"another-state-init-blob";
    let value = U256::from_u64(50_000);
    let body: Vec<u8> = Vec::new();
    let sig = d
        .sign_deploy(nonce, &dest, state_init, value, &body)
        .await
        .expect("sign deploy");

    let a = d
        .encode_deploy_call(nonce, &dest, state_init, value, &body, &sig)
        .expect("encode a");
    let b = d
        .encode_deploy_call(nonce, &dest, state_init, value, &body, &sig)
        .expect("encode b");
    assert_eq!(a.repr_hash(), b.repr_hash());
}

#[tokio::test]
async fn deployer_address_distinct_from_wallet_with_same_inputs() {
    use contracts::jvm_wallet::JvmWalletContract;

    let signer_w = FixedEd25519Signer::new(fixture_seed());
    let signer_d = FixedEd25519Signer::new(fixture_seed());

    let wallet = JvmWalletContract::new(
        Box::new(signer_w),
        [0u8; 32],
        fixture_salt(),
        fixture_class_bytes(),
    )
    .await
    .expect("wallet");

    let deployer = JvmDeployerContract::new(
        Box::new(signer_d),
        [0u8; 32],
        fixture_salt(),
        fixture_class_bytes(),
    )
    .await
    .expect("deployer");

    // The manifest cells differ (3-entry execute vs 3-entry deploy),
    // so manifest_root_hash differs, so the derived address differs
    // even when (deployer, salt, class_bytes) match.
    assert_ne!(
        wallet.calculate_address(),
        deployer.calculate_address(),
        "Wallet and Deployer derived from the same (deployer, salt, class_bytes) \
         MUST produce different wc=3 addresses (manifest binding into address)"
    );
}
