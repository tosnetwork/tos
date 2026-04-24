//! `tosctl uno mine` — CPU multi-threaded Poseidon2 PoW search loop.
//!
//! Phase 2 implementation of the MineUno mining client. Searches for a
//! 32-byte nonce satisfying the difficulty target, then constructs and
//! submits a MineUno transaction to the wc=2 collator.
//!
//! # PoW construction
//!
//! ```text
//! h = Poseidon2("uno-mine-v1" ‖ epoch(u32,LE) ‖ nonce(32B) ‖ output_cm(32B))
//! win iff  h < target  (lexicographic big-endian byte comparison)
//! ```
//!
//! # Thread model
//!
//! Uses a Rayon parallel iterator over a lazy nonce counter. Each worker
//! independently picks a random 32-byte starting nonce and increments
//! sequentially in its stripe. The first winning worker sets an `AtomicBool`
//! stop flag and returns the `MineResult`.
//!
//! # Plonky3 prover
//!
//! The call to the STARK prover is a clearly-marked stub (see
//! [`prove_mine_uno_stub`]). Phase 3 will replace it with a real call to
//! `uno_plonky3_ffi::prove_mine_uno`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::mine_constants::{
    era_from_epoch, mine_reward_for_era, MINE_HASH_TAG, MINE_SUPPLY_NANO,
};
use crate::mine_uno::{MineUnoAddress, MineUnoPublicInputs, MineUnoWitness};
use crate::poseidon2;
use crate::rpc_client::RpcClient;
use crate::transfer::compute_note_commitment;
use crate::transfer::NoteCommitmentInputs;
use crate::sizes::DIGEST;

// ---------------------------------------------------------------------------
// MineConfig — parameters for one search round
// ---------------------------------------------------------------------------

/// All parameters needed for one proof-of-work search round.
pub struct MineConfig {
    /// Recipient's Uno address (1259-byte material).
    pub recipient: MineUnoAddress,
    /// Current mining epoch (= cumulative successful solves).
    pub epoch: u32,
    /// 32-byte difficulty target (big-endian). Win iff `h < target` (lex BE).
    pub target: [u8; 32],
    /// Pre-computed mint value from `mine_reward_for_era(era_from_epoch(epoch))`.
    pub mint_value: u64,
    /// `mine_remaining` from chain state BEFORE this solve.
    pub remaining_pre: u64,
}

// ---------------------------------------------------------------------------
// MineResult — what a winning worker returns
// ---------------------------------------------------------------------------

/// Result of a successful nonce search.
pub struct MineResult {
    /// 32-byte winning nonce.
    pub nonce: [u8; DIGEST],
    /// Output note commitment computed from recipient + value + rseed.
    pub output_cm: [u8; DIGEST],
    /// 32-byte randomness seed used to derive `rcm` → `output_cm`.
    pub rseed: [u8; DIGEST],
}

// ---------------------------------------------------------------------------
// Poseidon2 PoW hash
// ---------------------------------------------------------------------------

/// Compute the PoW hash per the spec:
///
/// ```text
/// h = Poseidon2("uno-mine-v1" ‖ epoch(u32,LE padded to 8 B) ‖ nonce(32B) ‖ output_cm(32B))
/// ```
///
/// Input packing: epoch is placed in one Goldilocks element (u64 LE, value
/// = epoch as u32); nonce and output_cm are each split into 4 elements
/// (8-byte LE limbs, wrapped-load). Total: 1 + 4 + 4 = 9 field elements.
/// The sponge branches to the iterated path (len=9 > 8).
pub fn compute_mine_pow_hash(epoch: u32, nonce: &[u8; 32], output_cm: &[u8; 32]) -> [u8; DIGEST] {
    let mut fes: Vec<Goldilocks> = Vec::with_capacity(9);

    // epoch → 1 fe (u64, canonical)
    fes.push(Goldilocks::from_u64(epoch as u64));

    // nonce → 4 fes (8-byte LE chunks, wrapped-load)
    fes.extend(poseidon2::bytes_to_fes_wrapped(nonce));

    // output_cm → 4 fes (same)
    fes.extend(poseidon2::bytes_to_fes_wrapped(output_cm));

    debug_assert_eq!(fes.len(), 9);
    poseidon2::hash_tagged(MINE_HASH_TAG, &fes)
}

/// Returns `true` if `hash < target` under big-endian byte comparison.
/// Both slices must be 32 bytes.
pub fn hash_below_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    hash < target
}

// ---------------------------------------------------------------------------
// Note commitment for mining output
// ---------------------------------------------------------------------------

/// Compute `output_cm` for a MineUno output note.
///
/// ```text
/// rcm       = Poseidon2("uno-rcm-v1", rseed)
/// output_cm = Poseidon2("uno-cm-v1",
///               d ‖ pk_d ‖ ivk_commitment ‖ value_nano ‖ rcm)
/// ```
pub fn compute_mine_output_cm(
    recipient: &MineUnoAddress,
    value_nano: u64,
    rseed: &[u8; DIGEST],
) -> [u8; DIGEST] {
    let rcm = crate::transfer::compute_rcm(rseed);
    let input = NoteCommitmentInputs {
        d: &recipient.diversifier,
        pk_d_bytes: &recipient.pk_d_compressed,
        ivk_commitment: &recipient.ivk_commitment,
        value: value_nano,
        rcm: &rcm,
    };
    compute_note_commitment(&input)
}

// ---------------------------------------------------------------------------
// Nonce search loop
// ---------------------------------------------------------------------------

/// Search for a winning nonce using `n_threads` Rayon workers.
///
/// Each worker:
/// 1. Samples a fresh 32-byte `rseed` from OS randomness.
/// 2. Computes `output_cm = Poseidon2("uno-cm-v1", ...)` from recipient
///    fields + `value_nano` + `rseed`.
/// 3. Iterates nonces starting from a random base, incrementing in
///    little-endian carry order:
///    `h = Poseidon2("uno-mine-v1" ‖ epoch ‖ nonce ‖ output_cm)`.
/// 4. On `h < target`: sets the stop flag and returns `MineResult`.
///
/// `stop`: external cancellation — set it to `true` to abort (e.g. if
/// another miner on the network already found this epoch's solution).
///
/// Returns `None` if stopped externally before any worker wins.
pub fn search_nonce(
    cfg: &MineConfig,
    n_threads: usize,
    stop: Arc<AtomicBool>,
) -> Option<MineResult> {
    // Global attempt counter (for diagnostic eprintln).
    let total_attempts = Arc::new(AtomicU64::new(0));

    // Build the thread pool explicitly so we respect n_threads exactly.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(n_threads)
        .build()
        .expect("rayon pool build");

    // Each worker lives in its own rayon task; the first to finish sends
    // via a Mutex<Option<MineResult>>.
    let result: Arc<std::sync::Mutex<Option<MineResult>>> =
        Arc::new(std::sync::Mutex::new(None));

    pool.scope(|scope| {
        for _worker_id in 0..n_threads {
            let stop = Arc::clone(&stop);
            let result = Arc::clone(&result);
            let total_attempts = Arc::clone(&total_attempts);

            // Clone the parts of cfg we need (all cheap slices / u32 / u64).
            let epoch = cfg.epoch;
            let target = cfg.target;
            let mint_value = cfg.mint_value;
            let recipient_diversifier = cfg.recipient.diversifier;
            let recipient_pk_d = cfg.recipient.pk_d_compressed;
            let recipient_ivk_commitment = cfg.recipient.ivk_commitment;

            scope.spawn(move |_| {
                // Each worker gets its own rseed and computes its own output_cm.
                let mut rseed = [0u8; DIGEST];
                OsRng.fill_bytes(&mut rseed);

                let rcm = crate::transfer::compute_rcm(&rseed);
                let output_cm = {
                    let input = NoteCommitmentInputs {
                        d: &recipient_diversifier,
                        pk_d_bytes: &recipient_pk_d,
                        ivk_commitment: &recipient_ivk_commitment,
                        value: mint_value,
                        rcm: &rcm,
                    };
                    compute_note_commitment(&input)
                };

                // Random starting nonce, incremented sequentially.
                let mut nonce = [0u8; DIGEST];
                OsRng.fill_bytes(&mut nonce);

                const BATCH: u64 = 1024;
                loop {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }

                    for _ in 0..BATCH {
                        let h = compute_mine_pow_hash(epoch, &nonce, &output_cm);
                        if hash_below_target(&h, &target) {
                            // We won — stash result and signal stop.
                            stop.store(true, Ordering::Relaxed);
                            let mut guard = result.lock().unwrap();
                            if guard.is_none() {
                                *guard = Some(MineResult {
                                    nonce,
                                    output_cm,
                                    rseed,
                                });
                            }
                            return;
                        }
                        // Increment nonce (little-endian carry).
                        increment_nonce(&mut nonce);
                    }
                    total_attempts.fetch_add(BATCH, Ordering::Relaxed);
                }
            });
        }
    });

    Arc::try_unwrap(result)
        .ok()
        .and_then(|m| m.into_inner().ok())
        .flatten()
}

/// Increment a 32-byte nonce as a little-endian 256-bit integer.
fn increment_nonce(nonce: &mut [u8; 32]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Chain-state polling
// ---------------------------------------------------------------------------

/// Fetch `(mine_epoch, mine_target, mine_remaining)` from the wc=2 chain.
///
/// Calls `uno_getMineState` via the existing RPC client. If the node does
/// not support this method yet, returns a clearly-labeled stub for testing.
///
/// The stub hardcodes an easy (all-0xFF) target so the test search loop
/// converges immediately.
pub async fn fetch_mine_state(rpc: &RpcClient) -> Result<(u32, [u8; 32], u64)> {
    // TODO(Phase 3): implement `uno_getMineState` on the wc=2 node side.
    // The RPC should return: { "epoch": u32, "target": "hex", "remaining": u64 }
    // For now, attempt the call and fall back to stub values on any error.
    match rpc.call("uno_getMineState", serde_json::json!([])).await {
        Ok(v) => {
            let epoch = v
                .get("epoch")
                .and_then(|x| x.as_u64())
                .ok_or_else(|| anyhow!("uno_getMineState: missing 'epoch'"))?
                as u32;

            let target_hex = v
                .get("target")
                .and_then(|x| x.as_str())
                .ok_or_else(|| anyhow!("uno_getMineState: missing 'target'"))?;
            let target_bytes =
                hex::decode(target_hex.trim_start_matches("0x"))
                    .context("uno_getMineState: target not valid hex")?;
            if target_bytes.len() != 32 {
                return Err(anyhow!(
                    "uno_getMineState: target must be 32 bytes, got {}",
                    target_bytes.len()
                ));
            }
            let mut target = [0u8; 32];
            target.copy_from_slice(&target_bytes);

            let remaining = v
                .get("remaining")
                .and_then(|x| x.as_u64())
                .ok_or_else(|| anyhow!("uno_getMineState: missing 'remaining'"))?;

            Ok((epoch, target, remaining))
        }
        Err(e) => {
            eprintln!(
                "[mine] uno_getMineState not available ({}); using stub state for testing",
                e
            );
            // Stub: epoch 0, trivially-easy target (0xFF…FF = max u256 →
            // every hash wins), remaining = full supply.
            let mut easy_target = [0u8; 32];
            easy_target.fill(0xFF);
            Ok((0u32, easy_target, MINE_SUPPLY_NANO))
        }
    }
}

// ---------------------------------------------------------------------------
// Plonky3 prover (Phase 3 — real AIR call)
// ---------------------------------------------------------------------------

/// Run the real Plonky3 STARK prover for a `MineUnoWitness` + matching
/// `MineUnoPublicInputs` (the latter supplies `remaining_pre` /
/// `remaining_post`, which are PI-only conservation fields).
///
/// Returns the postcard-encoded `Proof<MvpConfig>` bytes on success. The
/// full `[u32_le proof_len][proof][pi]` owned buffer that
/// `uno_mine_uno_prove` emits via the C ABI is unpacked here — callers
/// get just the proof half back; the PI can always be rederived from
/// the witness (or from the passed-in `public_inputs` struct) so we do
/// not round-trip it.
///
/// Construction sequence:
///   1. Convert `MineUnoWitness` (wallet-native) → the FFI-side
///      `uno_plonky3_ffi::mine_uno_witness::MineUnoWitness`.
///   2. Call the direct Rust API `uno_plonky3_ffi::prover::prove_mine_uno`
///      (we're in the same cargo workspace; no need to bounce through
///      the C ABI).
///   3. Return the proof bytes.
/// Returns the proof blob in the daemon's canonical wire format:
/// `[u32 LE proof_len][proof][96 B PI]`. This matches what
/// `uno_mine_uno_prove` / `uno_mine_uno_verify` use on the C-ABI, and what
/// `decode_mine_uno_bytes` on the C++ side expects to find in the zk_proof
/// chunk-tree ref of the tx BoC.
pub fn prove_mine_uno_stub(
    witness: &MineUnoWitness,
    public_inputs: &MineUnoPublicInputs,
) -> Result<Vec<u8>> {
    use uno_plonky3_ffi::mine_uno_witness::MineUnoWitness as FfiWitness;
    use uno_plonky3_ffi::prover::prove_mine_uno;

    // Startup ABI version guard — catches a shipped-binary / linked-lib
    // skew early. MineUno FFI landed at ABI v4.
    let abi = uno_plonky3_ffi::uno_plonky3_abi_version();
    if abi < 4 {
        return Err(anyhow!(
            "uno_plonky3_ffi ABI version {} < 4 (MineUno prover requires v4+)",
            abi
        ));
    }

    // Pad the 11-byte diversifier into the canonical 32-byte form
    // (bytes [11..32] MUST be zero — enforced by the FFI decoder).
    let mut d = [0u8; 32];
    d[..11].copy_from_slice(&witness.recipient.diversifier);

    let ffi_witness = FfiWitness {
        epoch:           witness.epoch,
        nonce:           witness.nonce,
        d,
        pk_d:            witness.recipient.pk_d_compressed,
        ivk_commitment:  witness.recipient.ivk_commitment,
        value_nano:      witness.value_nano,
        rseed:           witness.rseed,
        remaining_pre:   public_inputs.remaining_pre,
        remaining_post:  public_inputs.remaining_post,
    };
    let witness_bytes = ffi_witness.encode();

    eprintln!(
        "[mine] generating STARK proof (epoch={}, value={}, remaining_pre={}) …",
        public_inputs.epoch, public_inputs.value_nano, public_inputs.remaining_pre
    );
    let t0 = std::time::Instant::now();
    let (proof_bytes, pi_bytes) = prove_mine_uno(&witness_bytes)
        .map_err(|s| anyhow!("uno_plonky3_ffi::prove_mine_uno failed: {:?}", s))?;
    let elapsed_ms = t0.elapsed().as_millis();

    // Pack into the daemon's canonical wire format:
    //   [u32 LE proof_len][proof bytes][96 B public inputs]
    // This is the exact layout `uno_mine_uno_prove` emits on the C ABI and
    // what `decode_mine_uno_bytes` expects inside the zk_proof chunk-tree
    // ref of the MineUno BoC.
    if pi_bytes.len() != 96 {
        return Err(anyhow!(
            "prove_mine_uno returned PI of {} bytes, expected 96",
            pi_bytes.len()
        ));
    }
    let proof_len_u32: u32 = proof_bytes.len().try_into().map_err(|_| {
        anyhow!("prove_mine_uno: proof length {} exceeds u32", proof_bytes.len())
    })?;
    let mut blob = Vec::with_capacity(4 + proof_bytes.len() + 96);
    blob.extend_from_slice(&proof_len_u32.to_le_bytes());
    blob.extend_from_slice(&proof_bytes);
    blob.extend_from_slice(&pi_bytes);

    eprintln!(
        "[mine] STARK proof generated in {} ms (proof={} B, pi=96 B, blob={} B)",
        elapsed_ms,
        proof_bytes.len(),
        blob.len(),
    );

    Ok(blob)
}

// ---------------------------------------------------------------------------
// Recipient address JSON format (matches `tosctl uno address` output)
// ---------------------------------------------------------------------------

/// JSON format produced by `tosctl uno address` for the `--recipient` file.
/// We accept a subset of fields — only those needed by the mining witness.
#[derive(Debug, Deserialize, Serialize)]
pub struct RecipientJson {
    /// Diversifier as hex string (22 chars = 11 bytes).
    pub diversifier: String,
    /// Compressed Ristretto `pk_d` as hex (64 chars = 32 bytes).
    pub pk_d: String,
    /// `ivk_commitment` as hex (64 chars = 32 bytes).
    pub ivk_commitment: String,
    /// ML-KEM-768 public key as hex (2368 chars = 1184 bytes).
    pub pk_mlkem_hex: String,
}

impl RecipientJson {
    /// Parse from a JSON file at the given path.
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading recipient JSON from {}", path.display()))?;
        serde_json::from_str(&text).context("parsing recipient JSON")
    }

    /// Convert to `MineUnoAddress` (validates field lengths).
    pub fn to_mine_address(&self) -> Result<MineUnoAddress> {
        let div_bytes =
            hex::decode(&self.diversifier).context("decoding diversifier hex")?;
        if div_bytes.len() != 11 {
            return Err(anyhow!(
                "diversifier must be 11 bytes (22 hex chars), got {}",
                div_bytes.len()
            ));
        }
        let mut diversifier = [0u8; 11];
        diversifier.copy_from_slice(&div_bytes);

        let pk_d_bytes = hex::decode(&self.pk_d).context("decoding pk_d hex")?;
        if pk_d_bytes.len() != 32 {
            return Err(anyhow!("pk_d must be 32 bytes (64 hex chars)"));
        }
        let mut pk_d_compressed = [0u8; 32];
        pk_d_compressed.copy_from_slice(&pk_d_bytes);

        let ivk_cm_bytes =
            hex::decode(&self.ivk_commitment).context("decoding ivk_commitment hex")?;
        if ivk_cm_bytes.len() != 32 {
            return Err(anyhow!("ivk_commitment must be 32 bytes (64 hex chars)"));
        }
        let mut ivk_commitment = [0u8; 32];
        ivk_commitment.copy_from_slice(&ivk_cm_bytes);

        let pk_mlkem =
            hex::decode(&self.pk_mlkem_hex).context("decoding pk_mlkem_hex hex")?;
        if pk_mlkem.len() != 1184 {
            return Err(anyhow!(
                "pk_mlkem_hex must be 1184 bytes (2368 hex chars), got {}",
                pk_mlkem.len()
            ));
        }

        Ok(MineUnoAddress {
            diversifier,
            pk_d_compressed,
            ivk_commitment,
            pk_mlkem,
        })
    }
}

// ---------------------------------------------------------------------------
// Top-level mine execution (called from main.rs)
// ---------------------------------------------------------------------------

/// Arguments for `tosctl uno mine`.
#[derive(Debug, Clone)]
pub struct MineArgs {
    /// Path to the recipient address JSON file (output of `tosctl uno address`).
    pub recipient_path: std::path::PathBuf,
    /// RPC URL of the wc=2 node.
    pub node_url: String,
    /// Number of search threads. `None` = `std::thread::available_parallelism`.
    pub threads: Option<usize>,
    /// Maximum wall-clock seconds to run. `None` = infinite.
    pub max_time_secs: Option<u64>,
}

/// Summary returned to the CLI on success (or stub mode).
#[derive(Debug, Serialize)]
pub struct MineSummary {
    pub epoch: u32,
    pub era: u32,
    pub value_nano: u64,
    pub nonce_hex: String,
    pub output_cm_hex: String,
    pub proof_status: String,
}

/// Execute the full mine pipeline:
/// 1. Load recipient.
/// 2. Poll chain state (or use stub).
/// 3. Search nonce.
/// 4. Build witness + PI.
/// 5. Call prover stub.
/// 6. Print result.
pub async fn execute(args: &MineArgs) -> Result<MineSummary> {
    // 1. Load recipient address.
    let recipient_json = RecipientJson::from_file(&args.recipient_path)?;
    let recipient = recipient_json.to_mine_address()?;

    // 2. Poll chain state.
    let rpc = RpcClient::new(&args.node_url)?;
    let (epoch, target, remaining_pre) = fetch_mine_state(&rpc).await?;

    // 3. Compute era / mint value.
    let era = era_from_epoch(epoch);
    let mint_value = mine_reward_for_era(era);
    if mint_value == 0 {
        return Err(anyhow!(
            "mining epoch {epoch} (era {era}): reward is 0 — mining cap reached"
        ));
    }
    if remaining_pre < mint_value {
        return Err(anyhow!(
            "remaining supply {remaining_pre} < mint value {mint_value} — cap exceeded"
        ));
    }

    eprintln!(
        "[mine] epoch={} era={} reward={} nano-UNO  target={}…",
        epoch,
        era,
        mint_value,
        hex::encode(&target[..4])
    );

    // 4. Resolve thread count.
    let n_threads = args.threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });
    eprintln!("[mine] searching with {} threads", n_threads);

    // 5. Build search config + stop flag.
    let cfg = MineConfig {
        recipient: recipient.clone(),
        epoch,
        target,
        mint_value,
        remaining_pre,
    };

    let stop = Arc::new(AtomicBool::new(false));

    // Optional timer thread to enforce --max-time.
    if let Some(secs) = args.max_time_secs {
        let stop_t = Arc::clone(&stop);
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(secs));
            eprintln!("[mine] --max-time {}s elapsed, stopping search", secs);
            stop_t.store(true, Ordering::Relaxed);
        });
    }

    // 6. Run search.
    let result = search_nonce(&cfg, n_threads, Arc::clone(&stop))
        .ok_or_else(|| anyhow!("search stopped (timed out or cancelled) without finding a nonce"))?;

    eprintln!("[mine] found winning nonce: {}", hex::encode(&result.nonce[..8]));

    // 7. Build witness and public inputs.
    let witness = MineUnoWitness {
        epoch,
        nonce: result.nonce,
        recipient,
        value_nano: mint_value,
        rseed: result.rseed,
    };
    witness.validate()?;

    let remaining_post = remaining_pre - mint_value;
    let public_inputs = MineUnoPublicInputs {
        epoch,
        target,
        value_nano: mint_value,
        output_cm: result.output_cm,
        remaining_pre,
        remaining_post,
    };
    public_inputs.validate()?;

    // 8. Call prover + submit the resulting BoC to wc=2 via uno_sendMineUno.
    let proof_status = match prove_mine_uno_stub(&witness, &public_inputs) {
        Ok(proof_bytes) => {
            // Build the canonical MineUno tx shell — tx_kind/version/scheme_id
            // + PublicInputs mirror what encode_mine_uno_to_boc expects on
            // the C++ side. The actual proof bytes travel in the chunk-tree
            // ref, not in the struct's `zk_proof` field.
            let tx = crate::mine_uno::MineUno {
                tx_kind:       crate::mine_uno::TX_KIND_MINE_UNO,
                version:       1, // kMineUnoVersion
                scheme_id:     1, // kSchemeIdV1
                chain_id:      0x554E4F54, // "UNOT" (testnet); mainnet = UNOM
                public_inputs: public_inputs.clone(),
                zk_proof:      None,
            };
            match crate::boc_encode::encode_mine_uno_boc(&tx, &proof_bytes) {
                Ok(boc) => match rpc.send_mine_uno(&boc).await {
                    Ok(tx_hash) => {
                        eprintln!(
                            "[mine] uno_sendMineUno accepted: tx_hash={}, boc_size={}B, proof_size={}B",
                            tx_hash, boc.len(), proof_bytes.len()
                        );
                        format!("submitted:{tx_hash}")
                    }
                    Err(e) => {
                        eprintln!("[mine] uno_sendMineUno failed: {e}");
                        format!("submit_failed:{e}")
                    }
                },
                Err(e) => {
                    eprintln!("[mine] encode_mine_uno_boc failed: {e}");
                    format!("encode_failed:{e}")
                }
            }
        }
        Err(e) => {
            eprintln!("[mine] prover: {e}");
            format!("prove_failed:{e}")
        }
    };

    Ok(MineSummary {
        epoch,
        era,
        value_nano: mint_value,
        nonce_hex: hex::encode(result.nonce),
        output_cm_hex: hex::encode(result.output_cm),
        proof_status,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mine_constants::{INIT_MINE_REWARD, MINE_SUPPLY_NANO};

    /// Build a minimal `MineUnoAddress` for tests (no real key material).
    fn test_address() -> MineUnoAddress {
        MineUnoAddress {
            diversifier: [0x11; 11],
            pk_d_compressed: [0x22; 32],
            ivk_commitment: [0x33; 32],
            pk_mlkem: vec![0x44u8; 1184],
        }
    }

    // -----------------------------------------------------------------------
    // 1. Test: nonce search converges with trivially-easy target (all 0xFF)
    // -----------------------------------------------------------------------

    #[test]
    fn search_converges_with_easy_target() {
        // Target = 2^256 - 1 (all bytes 0xFF): every hash wins immediately.
        let mut easy_target = [0u8; 32];
        easy_target.fill(0xFF);

        let cfg = MineConfig {
            recipient: test_address(),
            epoch: 0,
            target: easy_target,
            mint_value: INIT_MINE_REWARD,
            remaining_pre: MINE_SUPPLY_NANO,
        };

        let stop = Arc::new(AtomicBool::new(false));
        let result = search_nonce(&cfg, 1, stop);
        assert!(result.is_some(), "should find a nonce immediately with all-0xFF target");
        let r = result.unwrap();

        // Sanity: verify the output_cm round-trips via the pow hash.
        let h = compute_mine_pow_hash(cfg.epoch, &r.nonce, &r.output_cm);
        assert!(
            hash_below_target(&h, &easy_target),
            "winning hash should be below easy target"
        );
    }

    // -----------------------------------------------------------------------
    // 2. Test: search stops when stop flag is set before finding a nonce
    // -----------------------------------------------------------------------

    #[test]
    fn search_stops_when_flag_set() {
        // Impossible target (all zeros): no hash can win.
        let impossible_target = [0u8; 32];

        let cfg = MineConfig {
            recipient: test_address(),
            epoch: 0,
            target: impossible_target,
            mint_value: INIT_MINE_REWARD,
            remaining_pre: MINE_SUPPLY_NANO,
        };

        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);

        // Set stop after a tiny delay in a background thread.
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            stop_clone.store(true, Ordering::Relaxed);
        });

        let result = search_nonce(&cfg, 1, stop);
        assert!(result.is_none(), "should return None when stopped");
    }

    // -----------------------------------------------------------------------
    // 3. Test: PoW hash is deterministic
    // -----------------------------------------------------------------------

    #[test]
    fn pow_hash_is_deterministic() {
        let epoch = 42u32;
        let nonce = [0xABu8; 32];
        let output_cm = [0xCDu8; 32];

        let h1 = compute_mine_pow_hash(epoch, &nonce, &output_cm);
        let h2 = compute_mine_pow_hash(epoch, &nonce, &output_cm);
        assert_eq!(h1, h2, "PoW hash must be deterministic");
    }

    // -----------------------------------------------------------------------
    // 4. Test: different inputs produce different PoW hashes
    // -----------------------------------------------------------------------

    #[test]
    fn pow_hash_differs_on_input_change() {
        let nonce = [0xABu8; 32];
        let output_cm = [0xCDu8; 32];

        let h0 = compute_mine_pow_hash(0, &nonce, &output_cm);
        let h1 = compute_mine_pow_hash(1, &nonce, &output_cm);
        assert_ne!(h0, h1, "different epochs must produce different hashes");

        let mut nonce2 = nonce;
        nonce2[0] ^= 0x01;
        let h_n2 = compute_mine_pow_hash(0, &nonce2, &output_cm);
        assert_ne!(h0, h_n2, "different nonce must produce different hash");
    }

    // -----------------------------------------------------------------------
    // 5. Test: hash_below_target boundary conditions
    // -----------------------------------------------------------------------

    #[test]
    fn hash_below_target_boundary() {
        let target = [0x80u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let below = [0x7Fu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let equal = target;
        let above = [0x80u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert!(hash_below_target(&below, &target), "below target should win");
        assert!(!hash_below_target(&equal, &target), "equal to target should not win");
        assert!(!hash_below_target(&above, &target), "above target should not win");
    }

    // -----------------------------------------------------------------------
    // 6. Test: output_cm is derived consistently from recipient + value + rseed
    // -----------------------------------------------------------------------

    #[test]
    fn output_cm_is_deterministic() {
        let addr = test_address();
        let rseed = [0xAAu8; 32];
        let cm1 = compute_mine_output_cm(&addr, INIT_MINE_REWARD, &rseed);
        let cm2 = compute_mine_output_cm(&addr, INIT_MINE_REWARD, &rseed);
        assert_eq!(cm1, cm2, "output_cm must be deterministic");
    }

    #[test]
    fn output_cm_differs_with_different_value() {
        let addr = test_address();
        let rseed = [0xAAu8; 32];
        let cm1 = compute_mine_output_cm(&addr, INIT_MINE_REWARD, &rseed);
        let cm2 = compute_mine_output_cm(&addr, INIT_MINE_REWARD / 2, &rseed);
        assert_ne!(cm1, cm2, "different value must yield different output_cm");
    }

    // -----------------------------------------------------------------------
    // 7. Test: nonce increment wraps correctly
    // -----------------------------------------------------------------------

    #[test]
    fn increment_nonce_no_carry() {
        let mut n = [0u8; 32];
        increment_nonce(&mut n);
        assert_eq!(n[0], 1);
        for i in 1..32 {
            assert_eq!(n[i], 0);
        }
    }

    #[test]
    fn increment_nonce_carry_propagates() {
        let mut n = [0u8; 32];
        n[0] = 0xFF;
        increment_nonce(&mut n);
        assert_eq!(n[0], 0x00);
        assert_eq!(n[1], 0x01);
    }

    #[test]
    fn increment_nonce_full_carry_wraps() {
        let mut n = [0xFFu8; 32];
        increment_nonce(&mut n);
        assert_eq!(n, [0u8; 32]);
    }

    // -----------------------------------------------------------------------
    // 8. Test: RecipientJson roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn recipient_json_to_mine_address() {
        let json = RecipientJson {
            diversifier: hex::encode([0x11u8; 11]),
            pk_d: hex::encode([0x22u8; 32]),
            ivk_commitment: hex::encode([0x33u8; 32]),
            pk_mlkem_hex: hex::encode(vec![0x44u8; 1184]),
        };
        let addr = json.to_mine_address().unwrap();
        assert_eq!(addr.diversifier, [0x11u8; 11]);
        assert_eq!(addr.pk_d_compressed, [0x22u8; 32]);
        assert_eq!(addr.ivk_commitment, [0x33u8; 32]);
        assert_eq!(addr.pk_mlkem.len(), 1184);
    }

    #[test]
    fn recipient_json_rejects_wrong_pk_mlkem_length() {
        let json = RecipientJson {
            diversifier: hex::encode([0x11u8; 11]),
            pk_d: hex::encode([0x22u8; 32]),
            ivk_commitment: hex::encode([0x33u8; 32]),
            pk_mlkem_hex: hex::encode(vec![0x44u8; 512]), // wrong
        };
        assert!(json.to_mine_address().is_err());
    }

    // -----------------------------------------------------------------------
    // 9. Test: prove_mine_uno_stub produces a real Plonky3 proof (Phase 3)
    // -----------------------------------------------------------------------

    /// Phase 3 real-prover smoke test: build a consistent witness + PI,
    /// call the FFI prover, check we get non-empty proof bytes back, and
    /// verify them via the FFI verifier round-trip.
    ///
    /// Consistency constraint: `public_inputs.output_cm` MUST equal the
    /// off-circuit `Poseidon2("uno-cm-v1", d, pk_d, ivk_cm, value, rcm)`
    /// derived from the witness, otherwise the AIR's row-0 PI binding
    /// fails. We obtain the correct `output_cm` via
    /// `FfiWitness::compute_output_cm_bytes` and mirror it into PI.
    #[test]
    fn prove_mine_uno_real_proof_roundtrips() {
        use uno_plonky3_ffi::mine_uno_witness::MineUnoWitness as FfiWitness;
        use uno_plonky3_ffi::verifier::verify_mine_uno;

        let recipient = test_address();
        let epoch = 0u32;
        let value = INIT_MINE_REWARD;

        // Build the FFI witness first so we can compute the consistent
        // output_cm for the PI struct.
        let mut d = [0u8; 32];
        d[..11].copy_from_slice(&recipient.diversifier);
        let ffi_witness = FfiWitness {
            epoch,
            nonce: [0xBBu8; 32],
            d,
            pk_d: recipient.pk_d_compressed,
            ivk_commitment: recipient.ivk_commitment,
            value_nano: value,
            rseed: [0xCCu8; 32],
            remaining_pre: MINE_SUPPLY_NANO,
            remaining_post: MINE_SUPPLY_NANO - value,
        };
        let output_cm = ffi_witness.compute_output_cm_bytes();

        // Wallet-native witness + PI (matches what `execute()` builds).
        let w = MineUnoWitness {
            epoch,
            nonce: ffi_witness.nonce,
            recipient,
            value_nano: value,
            rseed: ffi_witness.rseed,
        };
        let pi = MineUnoPublicInputs {
            epoch,
            target: { let mut t = [0u8; 32]; t.fill(0xFF); t },
            value_nano: value,
            output_cm,
            remaining_pre: MINE_SUPPLY_NANO,
            remaining_post: MINE_SUPPLY_NANO - value,
        };

        let proof_bytes = prove_mine_uno_stub(&w, &pi)
            .expect("real STARK prover must succeed on a consistent witness + PI");
        assert!(!proof_bytes.is_empty(), "proof bytes must be non-empty");

        // Round-trip through the verifier.
        let pi_bytes = ffi_witness.public_inputs_bytes();
        let status = verify_mine_uno(&proof_bytes, &pi_bytes);
        assert_eq!(
            status,
            uno_plonky3_ffi::Plonky3Status::Ok,
            "verify_mine_uno must accept the proof we just produced",
        );
    }
}
