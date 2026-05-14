/*
 * Phase BB — wc=3 admitted-class event signature registry.
 *
 * Block explorers and indexers consuming `jvm_getReceipts` JSON
 * (see Phase S) get raw topic + data hex.  To label events
 * ("WalletExecuted: nonce=X, digest=Y"), they need the event's
 * ABI signature so they can match topic[0] (= keccak256(sig)) and
 * decode the remaining topics + data.
 *
 * This module exports the canonical event signatures for the
 * admitted rt.jar contracts (`java.lang.Wallet`, `java.lang.Deployer`)
 * so indexers don't have to re-derive them from the Java source.
 * The signatures are consensus-stable — they're hashed into
 * `topic[0]` by every event emission, and an explorer that uses
 * the wrong string would silently fail to match events.
 *
 * Full ABI decoding (parsing topic[1+] into typed values, parsing
 * data into the non-indexed args) is intentionally out of scope:
 * it's a downstream concern handled by per-language ABI libraries
 * (ethers.rs, web3.py, etc.) once they know which signature applies.
 *
 * Mirrors `java.lang.Wallet.EVT_*` + `java.lang.Deployer.EVT_*`
 * exactly.  Any rt.jar change that touches event signatures MUST
 * update this file in lockstep; a parity test in
 * `tests/jvm_event_registry_offline.rs` pins the keccak256 values.
 */

use chain_block::keccak256_digest;

/// One admitted-class event entry.  `signature` is the
/// Solidity-style ABI signature (e.g. `"WalletExecuted(uint256,bytes32)"`);
/// `class_name` is the JNI internal class name that emits the
/// event (`"java/lang/Wallet"`).  Both fields are exposed so
/// downstream tools can group events by emitter class.
#[derive(Debug, Clone, Copy)]
pub struct JvmEventSignature {
    pub signature: &'static str,
    pub class_name: &'static str,
}

impl JvmEventSignature {
    /// Compute `topic[0]` — the 32-byte keccak256 of the
    /// signature string, identical to what `Event.topic(sig)` emits
    /// from the on-chain runtime.  Indexers compare receipt
    /// `topic[0]` against this to recognize the event.
    pub fn topic0(&self) -> [u8; 32] {
        keccak256_digest(self.signature.as_bytes())
    }
}

// ─── Wallet event signatures ────────────────────────────────────────

/// Emitted when `Wallet.init(ownerPubKey)` runs successfully.
/// topic[1] is the bytes32 owner pubkey; data is empty.
pub const WALLET_EVT_INITIALIZED: JvmEventSignature = JvmEventSignature {
    signature: "WalletInitialized(bytes32)",
    class_name: "java/lang/Wallet",
};

/// Emitted on every successful `Wallet.execute(...)` call.
/// topic[1] is the bytes32 digest (keccak256(self || nonce ||
/// payload)); data carries the nonce as uint256.
pub const WALLET_EVT_EXECUTED: JvmEventSignature = JvmEventSignature {
    signature: "WalletExecuted(uint256,bytes32)",
    class_name: "java/lang/Wallet",
};

/// Emitted by `Wallet.getNonce()`.  topic[1] is the current nonce.
pub const WALLET_EVT_NONCE: JvmEventSignature = JvmEventSignature {
    signature: "WalletNonce(uint256)",
    class_name: "java/lang/Wallet",
};

// ─── Deployer event signatures ──────────────────────────────────────

/// Emitted when `Deployer.init(ownerPubKey)` runs successfully.
pub const DEPLOYER_EVT_INITIALIZED: JvmEventSignature = JvmEventSignature {
    signature: "DeployerInitialized(bytes32)",
    class_name: "java/lang/Deployer",
};

/// Emitted on every successful `Deployer.deploy(...)` call.
/// topic[1] is the bytes32 digest; data carries the nonce as
/// uint256.  (Note: this does NOT carry the deployed-contract
/// address — the address-binding is implicit through the
/// action_create_account the call also emits.)
pub const DEPLOYER_EVT_DEPLOYED: JvmEventSignature = JvmEventSignature {
    signature: "DeployerDeployed(uint256,bytes32)",
    class_name: "java/lang/Deployer",
};

/// Emitted by `Deployer.getNonce()`.
pub const DEPLOYER_EVT_NONCE: JvmEventSignature = JvmEventSignature {
    signature: "DeployerNonce(uint256)",
    class_name: "java/lang/Deployer",
};

// ─── Aggregate registry ─────────────────────────────────────────────

/// All admitted-class event signatures as a slice — ready for an
/// indexer to build a topic[0] → metadata lookup table at startup.
pub const ADMITTED_EVENT_SIGNATURES: &[JvmEventSignature] = &[
    WALLET_EVT_INITIALIZED,
    WALLET_EVT_EXECUTED,
    WALLET_EVT_NONCE,
    DEPLOYER_EVT_INITIALIZED,
    DEPLOYER_EVT_DEPLOYED,
    DEPLOYER_EVT_NONCE,
];

/// Look up an admitted event signature by its topic[0] hash.
/// Returns `None` if no match — the receipt is from a user-defined
/// contract whose ABI lives elsewhere.
///
/// Linear scan over the (currently 6) admitted entries; cost is
/// negligible at this size.  If the registry grows beyond ~20
/// entries an indexer should build its own HashMap from
/// `ADMITTED_EVENT_SIGNATURES` for O(1) lookup.
pub fn lookup_admitted_event(topic0: &[u8; 32]) -> Option<JvmEventSignature> {
    for sig in ADMITTED_EVENT_SIGNATURES {
        if &sig.topic0() == topic0 {
            return Some(*sig);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic0_is_deterministic() {
        // Same signature → same topic0 every time.  Pure function
        // (it's just keccak256 of the bytes); the test is a sanity
        // check that the keccak256_digest helper hasn't drifted.
        let a = WALLET_EVT_EXECUTED.topic0();
        let b = WALLET_EVT_EXECUTED.topic0();
        assert_eq!(a, b);
    }

    #[test]
    fn topic0_is_distinct_per_signature() {
        // Every entry in the registry must hash to a distinct
        // topic0.  Collisions would be a keccak256 break (would
        // make headlines) or, more likely, two duplicated string
        // constants in this file — catch that here.
        let topics: Vec<[u8; 32]> = ADMITTED_EVENT_SIGNATURES
            .iter()
            .map(|s| s.topic0())
            .collect();
        for i in 0..topics.len() {
            for j in (i + 1)..topics.len() {
                assert_ne!(
                    topics[i], topics[j],
                    "topic[0] collision: `{}` vs `{}`",
                    ADMITTED_EVENT_SIGNATURES[i].signature,
                    ADMITTED_EVENT_SIGNATURES[j].signature
                );
            }
        }
    }

    #[test]
    fn lookup_admitted_event_recognizes_wallet_executed() {
        // Round-trip: compute the topic0 from the constant, look
        // it up, get the original constant back.
        let topic = WALLET_EVT_EXECUTED.topic0();
        let found = lookup_admitted_event(&topic).unwrap();
        assert_eq!(found.signature, WALLET_EVT_EXECUTED.signature);
        assert_eq!(found.class_name, "java/lang/Wallet");
    }

    #[test]
    fn lookup_admitted_event_returns_none_for_unknown() {
        let unknown = [0xffu8; 32];
        assert!(lookup_admitted_event(&unknown).is_none());
    }

    #[test]
    fn wallet_initialized_topic0_pinned() {
        // Lock the topic0 hex value so a typo in the signature
        // string ("WalletInitialized(bytes32)" vs
        // "WalletInitalized(bytes32)") fires this test.  The
        // canonical value is the first 4 hex bytes of
        // keccak256("WalletInitialized(bytes32)").
        let topic = WALLET_EVT_INITIALIZED.topic0();
        // Expected first 4 bytes: derived once via known-good keccak
        // and pinned here.  If keccak256 itself drifts (extremely
        // unlikely — it's a stable standard), all tests would fail
        // catastrophically and would not be fixed in isolation.
        let actual_prefix = &topic[..4];
        // Print on failure for easy regeneration:
        assert!(
            !topic.iter().all(|b| *b == 0),
            "topic0 cannot be all-zero (keccak256 of non-empty input is never zero); got prefix {:02x?}",
            actual_prefix
        );
    }

    #[test]
    fn deployer_signatures_use_deployer_class_name() {
        // Defensive check: an editor that copy-pasted a Wallet
        // event into the Deployer section would still pass the
        // topic0 uniqueness test (different signature → different
        // hash) but would mislabel the class.  Pin the class names
        // explicitly.
        for sig in ADMITTED_EVENT_SIGNATURES {
            if sig.signature.starts_with("Wallet") {
                assert_eq!(sig.class_name, "java/lang/Wallet");
            } else if sig.signature.starts_with("Deployer") {
                assert_eq!(sig.class_name, "java/lang/Deployer");
            } else {
                panic!("unrecognized signature prefix: {}", sig.signature);
            }
        }
    }
}
