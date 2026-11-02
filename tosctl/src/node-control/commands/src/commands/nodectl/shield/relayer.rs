/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Which relayer a relayed spend goes through, and what must be true of it.
//!
//! A relayer profile carries the release pins the relayer published and the
//! public StateInit of its Bond. Nothing in the file is taken on its word:
//! the Bond's identity is recomputed from the StateInit and checked against
//! every pin, the pins are checked against the pool this instance is on as
//! the proof verifier shows it, the release's genesis identity is checked
//! against the proof anchor -- which must be the genesis block itself for
//! that to mean anything -- and the Bond's eligibility is read through the
//! verifier at the same authenticated checkpoint as the pool.
//!
//! A relayed spend also keeps the wallet off the network except through Tor:
//! every chain read it makes goes to a loopback address. The lite-server
//! the verifier queries and the RPC endpoints the sync uses are checked
//! before anything else happens.

use anyhow::Context;
use br1_client::release::Release;
use chain_block::MsgAddressInt;
use common::app_config::{AppConfig, ProofVerifierConfig};
use contracts::proven_getters::{ProvenGetterProvider, ReadPolicy};
use contracts::relayer_bond::{BondInit, BondState, RelayerBond};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use super::chain::{ANCHOR_KIND_ZEROSTATE, Head};
use super::profile::{Network, Profile};

pub const RELAYER_PROFILE_SCHEMA: &str = "tos.shield.relayer-profile.v1";

/// The largest relayer profile this tool reads: the pins and one Bond
/// StateInit, which carries an ML-DSA-44 public key and an endpoint.
const MAX_RELAYER_PROFILE_BYTES: u64 = 64 * 1024;

/// The largest lite-server configuration the loopback rule reads.
const MAX_LITESERVER_CONFIG_BYTES: u64 = 1024 * 1024;

/// A relayer, as its operator published it: the release scope every quote
/// and request carries, and the Bond that scope names.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RelayerProfile {
    pub schema: String,
    pub release: Release,
    /// The Bond's public StateInit as a base64 BOC, from which its identity
    /// is recomputed.
    pub bond_init_b64: String,
}

impl RelayerProfile {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let meta = std::fs::metadata(path)
            .with_context(|| format!("read relayer profile {}", path.display()))?;
        anyhow::ensure!(meta.is_file(), "relayer profile {} is not a regular file", path.display());
        anyhow::ensure!(
            meta.len() <= MAX_RELAYER_PROFILE_BYTES,
            "relayer profile {} is too large",
            path.display()
        );
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read relayer profile {}", path.display()))?;
        let profile: Self = serde_json::from_str(&text)
            .with_context(|| format!("parse relayer profile {}", path.display()))?;
        profile.validate()?;
        Ok(profile)
    }

    /// Everything the file alone can prove: the schema, well-formed pins on
    /// a network this client knows, and a Bond StateInit that is canonical,
    /// matches every pin and declares an onion endpoint. Returns the Bond's
    /// identity.
    pub fn validate(&self) -> anyhow::Result<BondInit> {
        anyhow::ensure!(
            self.schema == RELAYER_PROFILE_SCHEMA,
            "relayer profile schema {:?} is not {RELAYER_PROFILE_SCHEMA}",
            self.schema
        );
        self.release.validate().context("the relayer release pins")?;
        Network::of(self.release.global_id)?;
        let init = br1_client::bond::identity(&self.release, &self.bond_init_b64)
            .context("the Bond StateInit against the release pins")?;
        br1_client::onion::OnionEndpoint::parse(&init.endpoint)
            .context("the Bond's declared endpoint")?;
        Ok(init)
    }

    pub fn bond_address(&self) -> anyhow::Result<MsgAddressInt> {
        self.release.bond.parse::<MsgAddressInt>().context("the release's Bond address")
    }

    pub fn scope(&self) -> anyhow::Result<String> {
        self.release.scope().context("the release scope")
    }

    /// Binds the release to the pool this instance is on, as a verified head
    /// shows it. The release names a network, a pool, the pool's code and
    /// frozen configuration, and the genesis identity of the chain; each is
    /// compared with the authenticated head, and the genesis identity with
    /// the proof anchor, which has to be the genesis block itself.
    pub fn bind(&self, profile: &Profile, head: &Head) -> anyhow::Result<()> {
        anyhow::ensure!(
            head.verified,
            "a relayed spend is built only on a head the proof verifier authenticated"
        );
        anyhow::ensure!(
            self.release.global_id == profile.global_id && head.global_id == profile.global_id,
            "the relayer release is for global id {} but this instance is on {} (the chain \
             reports {})",
            self.release.global_id,
            profile.global_id,
            head.global_id
        );
        let release_pool: MsgAddressInt =
            self.release.pool.parse().context("the release's pool address")?;
        anyhow::ensure!(
            release_pool == profile.address()?,
            "the relayer release names pool {} but this instance is on {}",
            self.release.pool,
            profile.pool_address
        );
        anyhow::ensure!(
            self.release.pool_code_hash == hex::encode(head.code_hash),
            "the relayer release pins pool code {} but the pool runs {}",
            self.release.pool_code_hash,
            hex::encode(head.code_hash)
        );
        anyhow::ensure!(
            self.release.pool_config_hash == hex::encode(head.pool_config_hash),
            "the relayer release pins pool configuration {} but the pool's is {}",
            self.release.pool_config_hash,
            hex::encode(head.pool_config_hash)
        );
        anyhow::ensure!(
            head.anchor_kind.as_deref() == Some(ANCHOR_KIND_ZEROSTATE),
            "the proof anchor is {}; the relayer release names the chain by its genesis \
             identity, which only an anchor on the genesis block itself authenticates. \
             Re-anchor the proof verifier on the independently obtained zerostate",
            head.anchor_kind.as_deref().map_or_else(
                || "an RPC endpoint's word".to_owned(),
                |kind| format!("a {kind} anchor")
            )
        );
        anyhow::ensure!(
            self.release.genesis_root == hex::encode(head.chain.root_hash)
                && self.release.genesis_file == hex::encode(head.chain.file_hash),
            "the relayer release names genesis {} / {} but the proof anchor is {} / {}",
            self.release.genesis_root,
            self.release.genesis_file,
            hex::encode(head.chain.root_hash),
            hex::encode(head.chain.file_hash)
        );
        Ok(())
    }
}

/// The Bond as the chain shows it at one authenticated checkpoint.
#[derive(Clone, Debug)]
pub struct BondReading {
    pub state: BondState,
    pub balance: u128,
}

impl BondReading {
    pub fn eligible(&self) -> bool {
        self.state.eligible(self.balance)
    }

    /// Refuses a Bond that is not active and backed to its minimum.
    pub fn require_eligible(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.eligible(),
            "the relayer's Bond is {} with {} TOS backing against a minimum of {} TOS; a \
             relayed spend goes only through an active, fully backed Bond",
            self.state.status(),
            super::tos(self.state.backed(self.balance)),
            super::tos(self.state.init.minimum)
        );
        Ok(())
    }
}

/// A Bond read: at the head's checkpoint, or at another one because the
/// masterchain moved between the two reads, in which case both are re-read.
pub enum BondRead {
    AtCheckpoint(Box<BondReading>),
    OtherCheckpoint,
}

/// Reads the Bond through the proof verifier at the checkpoint `head` was
/// read at. The account must carry the Bond code, decode as a Bond, and be
/// the very Bond the profile describes; the pool and the Bond are then two
/// facts about one authenticated block, not two blocks.
pub async fn read_bond(
    verifier: &ProofVerifierConfig,
    head: &Head,
    profile: &RelayerProfile,
    init: &BondInit,
) -> anyhow::Result<BondRead> {
    let proven_head = head.proven().context("the head was not read through the proof verifier")?;
    let address = profile.bond_address()?;
    let provider = ProvenGetterProvider::new(verifier)?;
    let proven = provider
        .read_account(&address, &ReadPolicy::Live)
        .await
        .context("authenticated Bond read")?;
    if proven_head.require_same_checkpoint(&proven).is_err() {
        return Ok(BondRead::OtherCheckpoint);
    }
    let account = proven.account();
    anyhow::ensure!(account.get_addr() == Some(&address), "the proven account is not the Bond");
    let code_hash = account.get_code_hash().context("the Bond account has no code")?;
    anyhow::ensure!(
        code_hash == RelayerBond::code()?.repr_hash(),
        "the account at {address} does not run the Bond code this client knows"
    );
    let data = account.get_data().context("the Bond account has no data")?;
    let state = RelayerBond::decode(&address, &data).context("the Bond's state cell")?;
    anyhow::ensure!(
        state.init == *init,
        "the Bond on chain was initialised with other terms than the profile's StateInit"
    );
    let balance = account.get_balance().context("the Bond account has no balance")?.coins.as_u128();
    Ok(BondRead::AtCheckpoint(Box::new(BondReading { state, balance })))
}

/// Every chain read a relayed spend makes stays on this host: the
/// lite-server the proof verifier queries and the RPC endpoints the sync
/// uses are loopback addresses, written numerically. A name would be
/// resolved, and a resolver is a network observer. Offline proof material
/// makes no connection and passes.
pub fn require_loopback_reads(config: &AppConfig) -> anyhow::Result<()> {
    let verifier = config.proof_verifier.as_ref().context(
        "proof_verifier is not configured; a relayed spend is built only on heads the local proof \
         verifier authenticated",
    )?;
    if let Some(path) = &verifier.liteserver_config {
        let meta = std::fs::metadata(path)
            .with_context(|| format!("read the lite-server configuration {}", path.display()))?;
        anyhow::ensure!(
            meta.is_file() && meta.len() <= MAX_LITESERVER_CONFIG_BYTES,
            "the lite-server configuration {} is not a regular file of bounded size",
            path.display()
        );
        let text = std::fs::read(path)
            .with_context(|| format!("read the lite-server configuration {}", path.display()))?;
        require_loopback_liteservers(&text)
            .with_context(|| format!("the lite-server configuration {}", path.display()))?;
    }
    let endpoints = config.chain_rpc.resolved_endpoints();
    anyhow::ensure!(!endpoints.is_empty(), "no RPC endpoint is configured");
    for (url, _) in endpoints {
        require_loopback_url(&url).with_context(|| format!("the RPC endpoint {url:?}"))?;
    }
    Ok(())
}

/// Every lite-server in a global configuration listens on 127.0.0.0/8.
fn require_loopback_liteservers(text: &[u8]) -> anyhow::Result<()> {
    let value: serde_json::Value = serde_json::from_slice(text).context("parse")?;
    let servers = value
        .get("liteservers")
        .and_then(serde_json::Value::as_array)
        .context("no `liteservers` list")?;
    anyhow::ensure!(!servers.is_empty(), "an empty `liteservers` list");
    for server in servers {
        let ip = server
            .get("ip")
            .and_then(serde_json::Value::as_i64)
            .context("a lite-server without a numeric `ip`")?;
        let ip = i32::try_from(ip).context("a lite-server `ip` outside 32 bits")?;
        let address = Ipv4Addr::from(ip.to_be_bytes());
        anyhow::ensure!(
            address.is_loopback(),
            "lite-server {address} is not a loopback address; a relayed spend reads the chain \
             through a local node only"
        );
    }
    Ok(())
}

/// A URL whose host is `127.0.0.1`, another 127.0.0.0/8 address or `[::1]`,
/// written as such. `localhost` is a name and is refused.
pub fn require_loopback_url(url: &str) -> anyhow::Result<()> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .context("not an http(s) URL")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    anyhow::ensure!(!authority.contains('@'), "a URL with user information");
    anyhow::ensure!(!authority.is_empty(), "a URL without a host");
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, after) = bracketed.split_once(']').context("an unterminated IPv6 literal")?;
        anyhow::ensure!(
            after.is_empty() || after.strip_prefix(':').is_some_and(is_port),
            "a malformed port"
        );
        let address: Ipv6Addr = host.parse().context("not an IPv6 literal")?;
        anyhow::ensure!(address.is_loopback(), "{address} is not the loopback address");
        return Ok(());
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => {
                anyhow::ensure!(is_port(port), "a malformed port");
                host
            }
            None => authority,
        }
    };
    let address: Ipv4Addr = host.parse().with_context(|| {
        format!("host {host:?} is not a numeric loopback address (a name would be resolved)")
    })?;
    anyhow::ensure!(address.is_loopback(), "{address} is not a loopback address");
    Ok(())
}

fn is_port(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 5
        && text.bytes().all(|b| b.is_ascii_digit())
        && text.parse::<u32>().is_ok_and(|port| (1..=65535).contains(&port))
}

#[cfg(test)]
mod tests {
    use super::super::profile::PROFILE_SCHEMA;
    use super::super::store::ChainIdentity;
    use super::*;
    use base64::Engine;
    use chain_block::Serializable;
    use fips204::ml_dsa_44;
    use fips204::traits::{KeyGen, SerDes};

    const ENDPOINT: &str = "http://pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";

    /// A Bond and the release that pins it, on the local network, naming a
    /// pool and a genesis of the test's choosing.
    fn fixture() -> (RelayerProfile, BondInit) {
        let (public, _) = ml_dsa_44::KG::keygen_from_seed(&[37; 32]);
        let init = BondInit {
            global_id: 3,
            salt: [1; 32],
            owner: format!("0:{}", "11".repeat(32)).parse().expect("address"),
            worker: format!("0:{}", "22".repeat(32)).parse().expect("address"),
            worker_key: public.into_bytes().to_vec(),
            genesis_root: [4; 32],
            genesis_file: [5; 32],
            native_agent: [0; 32],
            minimum: 10_000_000_000,
            reserve: 1_000_000_000,
            exit_delay: 90000,
            endpoint: ENDPOINT.into(),
        };
        let release = Release {
            global_id: 3,
            genesis_root: hex::encode(init.genesis_root),
            genesis_file: hex::encode(init.genesis_file),
            bond: RelayerBond::address(&init).expect("address").to_string(),
            bond_code_hash: RelayerBond::code().expect("code").repr_hash().to_hex_string(),
            policy_hash: RelayerBond::policy(&init).expect("policy").repr_hash().to_hex_string(),
            worker_key_hash: br1_client::wire::hash(&init.worker_key),
            pool: format!("0:{}", "77".repeat(32)),
            pool_code_hash: "88".repeat(32),
            pool_config_hash: "99".repeat(32),
        };
        let bytes = chain_block::write_boc(
            &RelayerBond::state_init(&init).expect("state init").serialize().expect("cell"),
        )
        .expect("boc");
        let profile = RelayerProfile {
            schema: RELAYER_PROFILE_SCHEMA.into(),
            release,
            bond_init_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
        };
        (profile, init)
    }

    fn pool_profile() -> Profile {
        Profile {
            schema: PROFILE_SCHEMA.into(),
            global_id: 3,
            pool_address: format!("0:{}", "77".repeat(32)),
            pool_code_hash: "88".repeat(32),
        }
    }

    fn matching_head() -> Head {
        let mut head = super::super::chain::tests::head_for_tests();
        head.verified = true;
        head.global_id = 3;
        head.code_hash = [0x88; 32];
        head.pool_config_hash = [0x99; 32];
        head.anchor_kind = Some(ANCHOR_KIND_ZEROSTATE.into());
        head.chain = ChainIdentity {
            source: super::super::chain::PROOF_ANCHOR.into(),
            root_hash: [4; 32],
            file_hash: [5; 32],
        };
        head
    }

    #[test]
    fn a_profile_validates_to_the_bond_it_describes_and_refuses_every_altered_pin() {
        let (profile, init) = fixture();
        assert_eq!(profile.validate().expect("valid"), init);
        assert_eq!(profile.bond_address().expect("address").to_string(), profile.release.bond);

        let mut other_schema = profile.clone();
        other_schema.schema = "tos.shield.relayer-profile.v0".into();
        assert!(other_schema.validate().is_err());
        let mut other_network = profile.clone();
        other_network.release.global_id = 9;
        assert!(other_network.validate().is_err(), "a network this client does not know");
        let mut other_worker = profile.clone();
        other_worker.release.worker_key_hash = "66".repeat(32);
        assert!(other_worker.validate().is_err(), "the StateInit's worker is not the pinned one");
        let mut truncated = profile.clone();
        truncated.bond_init_b64.truncate(truncated.bond_init_b64.len() - 4);
        assert!(truncated.validate().is_err());
    }

    #[test]
    fn a_profile_file_is_bounded_and_regular() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (profile, _) = fixture();
        let path = dir.path().join("relayer.json");
        std::fs::write(&path, serde_json::to_vec(&profile).expect("json")).expect("write");
        assert_eq!(RelayerProfile::load(&path).expect("load"), profile);
        assert!(RelayerProfile::load(dir.path()).is_err(), "a directory");
        let big = dir.path().join("big.json");
        std::fs::write(&big, vec![b' '; 64 * 1024 + 1]).expect("write");
        assert!(RelayerProfile::load(&big).is_err(), "too large");
        assert!(RelayerProfile::load(&dir.path().join("missing.json")).is_err());
    }

    #[test]
    fn binding_needs_the_verified_head_the_pins_describe_on_a_zerostate_anchor() {
        let (profile, _) = fixture();
        let pool = pool_profile();
        profile.bind(&pool, &matching_head()).expect("the head the release describes");

        let mut unverified = matching_head();
        unverified.verified = false;
        assert!(profile.bind(&pool, &unverified).is_err());

        let mut other_pool = pool.clone();
        other_pool.pool_address = format!("0:{}", "76".repeat(32));
        assert!(profile.bind(&other_pool, &matching_head()).is_err(), "another pool");

        let mut other_code = matching_head();
        other_code.code_hash = [0x87; 32];
        assert!(profile.bind(&pool, &other_code).is_err(), "other pool code");

        let mut other_config = matching_head();
        other_config.pool_config_hash = [0x98; 32];
        assert!(profile.bind(&pool, &other_config).is_err(), "other pool configuration");

        let mut key_block = matching_head();
        key_block.anchor_kind = Some("key_block".into());
        let error = profile.bind(&pool, &key_block).expect_err("a key block anchor").to_string();
        assert!(error.contains("key_block anchor"), "{error}");

        let mut other_genesis = matching_head();
        other_genesis.chain.file_hash = [6; 32];
        assert!(profile.bind(&pool, &other_genesis).is_err(), "another chain");

        let mut other_network = matching_head();
        other_network.global_id = 2;
        assert!(profile.bind(&pool, &other_network).is_err(), "the chain reports another network");
    }

    #[test]
    fn eligibility_is_active_and_backed_to_the_minimum() {
        let (_, init) = fixture();
        let state = |phase: u8, principal: u128| BondState {
            init: init.clone(),
            phase,
            principal,
            activated: 1,
            exit_requested: 0,
            exit_after: 0,
            metadata_hash: [0; 32],
            evidence_hash: [0; 32],
            config: chain_block::Cell::default(),
        };
        let backed = BondReading { state: state(1, 10_000_000_000), balance: 11_000_000_000 };
        backed.require_eligible().expect("active, principal at the minimum, reserve kept");
        let short = BondReading { state: state(1, 10_000_000_000), balance: 10_999_999_999 };
        assert!(short.require_eligible().is_err(), "the balance does not cover the reserve");
        let unfunded = BondReading { state: state(0, 0), balance: 11_000_000_000 };
        assert!(unfunded.require_eligible().is_err());
        let exiting = BondReading { state: state(2, 10_000_000_000), balance: 11_000_000_000 };
        let error = exiting.require_eligible().expect_err("exiting").to_string();
        assert!(error.contains("exiting"), "{error}");
    }

    #[test]
    fn only_numeric_loopback_urls_pass() {
        for ok in [
            "http://127.0.0.1:18545",
            "http://127.0.0.1",
            "http://127.1.2.3:80/rpc",
            "https://127.0.0.1:443/v2?x=1",
            "http://[::1]:18545",
            "http://[::1]/",
        ] {
            require_loopback_url(ok).unwrap_or_else(|error| panic!("{ok}: {error}"));
        }
        for bad in [
            "http://localhost:18545",
            "http://LOCALHOST",
            "http://127.0.0.1.nip.io",
            "http://10.0.0.1:18545",
            "http://[::ffff:127.0.0.1]:1",
            "http://[fe80::1]",
            "http://user@127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:65536",
            "http://127.0.0.1:",
            "ws://127.0.0.1",
            "http://",
            "127.0.0.1:18545",
            "http://[::1",
            "http://[::1]x",
        ] {
            assert!(require_loopback_url(bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn lite_servers_must_all_be_loopback() {
        let loopback = i32::from_be_bytes([127, 0, 0, 1]);
        let public = i32::from_be_bytes([5, 9, 10, 15]);
        let config = |ips: &[i32]| {
            serde_json::json!({
                "liteservers": ips
                    .iter()
                    .map(|ip| serde_json::json!({"ip": ip, "port": 4924, "id": {}}))
                    .collect::<Vec<_>>()
            })
            .to_string()
        };
        require_loopback_liteservers(config(&[loopback]).as_bytes()).expect("loopback");
        require_loopback_liteservers(
            config(&[loopback, i32::from_be_bytes([127, 5, 5, 5])]).as_bytes(),
        )
        .expect("the whole 127/8");
        assert!(require_loopback_liteservers(config(&[loopback, public]).as_bytes()).is_err());
        assert!(require_loopback_liteservers(config(&[]).as_bytes()).is_err(), "no servers");
        assert!(require_loopback_liteservers(b"{}").is_err(), "no list");
        assert!(
            require_loopback_liteservers(br#"{"liteservers":[{"ip":"127.0.0.1"}]}"#).is_err(),
            "a textual ip is not the format"
        );
    }
}
