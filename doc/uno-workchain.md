# Uno Workchain (wc=2) — Design

**Status:** Draft v2
**Brand:** uno
**One-line positioning:** PQ-native privacy L1 on TOS workchain 2.
**Scope:** Shielded note-pool workchain on TOS at workchain id `2`, with Plonky3 STARK proving and hybrid post-quantum note encryption shipped in v1.
**Architecture class:** Shielded note-pool workchain. The cryptographic construction family (note commitments, nullifier scheme, diversified stealth addresses, randomized spend authorization, view-key hierarchy) derives from the Zcash Orchard specification (ZIP 224). The proof system is **Plonky3 STARK over the Goldilocks field** with Poseidon2 as the in-circuit hash — hash-based, transparent, post-quantum native, no trusted setup. Note encryption is **ECDH-over-Pallas + ML-KEM-768 hybrid** in v1, closing the HNDL window on on-chain ciphertexts at issuance. State is integrated into TOS cell-native storage via a single executor account on wc=2. Bridgelessness (§1.5), selective disclosure via view keys, and PQ-native posture are first-class design properties.

**Primary references:**
- **Zcash Orchard (ZIP 224)** — published specification we adopt for the shielded-pool construction family (note-commitment tree, nullifier derivation, randomized spend auth, diversified-address hierarchy). We adopt the construction; we substitute the proof backend.
- **Polygon Plonky3** — STARK toolkit (AIR construction, FRI commitments, Poseidon2 over Goldilocks) that replaces Halo2 as the proof system. Production-validated via Polygon AggLayer (pessimistic proofs, Feb 2025 mainnet) and Succinct SP1.
- **FIPS 203 (ML-KEM)** and **FIPS 204 (ML-DSA)** — NIST post-quantum standards; ML-KEM-768 is used for hybrid note encryption in v1, ML-DSA is reserved for a Phase 1 hybrid spend-auth signature upgrade (§6.2).
- **Zcash post-quantum privacy discussion (zcash/zips issue #1133)** — threat model and hybrid-KEM design principles we inherit.
- **Ethereum 2030 strawmap** (strawmap.org) — north-star framing under which this design positions as the intersection of *Private L1* and *Post-Quantum L1*.
- **`~/avatar`** — in-house pure-C crypto base; we reuse ChaCha20-Poly1305, BLAKE3, and BLAKE2b for off-circuit note encryption and KDF. Poseidon2-over-Goldilocks and Goldilocks field arithmetic are sourced from the Plonky3 toolkit, not from avatar.
- **`~/e`** — in-house reference for post-quantum signature primitives (used for the Phase 1 hybrid spend-auth signature trigger).

---

## 0. Vision — PQ-native Privacy L1

UNO is a **post-quantum-native privacy L1** on TOS workchain 2. The single-sentence claim is:

> **Privacy from inception, quantum-safe from inception, bridgeless by architecture.**

Three load-bearing commitments follow, and every other decision in this document is downstream of one of them.

### 0.1 Privacy from inception

UNO is not a public asset that can opt into privacy via a bridge, mixer, or rollup. It is an asset whose supply is born shielded at genesis (§10.3) and is never reachable by any public-asset pathway (§1.5).

Ethereum's 2030 strawmap names five L1 north stars; one of them is *Private L1 — "privacy as a first-class citizen, via L1 shielded transfers."* That framing admits two readings:

1. **Retrofit privacy**: a public asset (ETH, USDC) acquires privacy through a shielded pool and bridge. The bridge is the weakest link: entry-side gas binding, exit-side recipient binding, and cross-boundary timing/amount correlation structurally reintroduce the deanonymization vectors that terminal privacy is meant to close. Empirically this is how Zcash t↔z flows have been deanonymized in the research literature.
2. **Inception privacy**: the asset is private from the moment of issuance. There is no public-pathway leg and therefore no bridge to attack.

UNO adopts reading (2). The cost is the loss of cross-workchain composability — a UNO holder cannot use UNO in a wc=1 EVM DeFi protocol, and a wc=1 USDC holder cannot "make their USDC private." The trade is deliberate: a weaker-but-composable privacy guarantee is, for this chain, a strictly worse product than a stronger-but-isolated one. Users who want composable public liquidity hold public assets; users who want real privacy hold UNO.

### 0.2 Quantum-safe from inception

UNO's proof system is **Plonky3 STARK over the Goldilocks field**, with Poseidon2 as the in-circuit hash. It is hash-based, transparent, and post-quantum native. There is no elliptic curve whose discrete log Shor could break, no trusted-setup ceremony whose toxic waste could compromise soundness, and no mandatory Phase 2 migration of the proof system. This removes the largest quantum-migration liability that every Halo2 / Groth16 / Varuna shielded chain currently carries as technical debt.

The only remaining PQ extension surface is **note-encryption key material**: the ECDH that derives the AEAD key for each `enc_ciphertext`. v1 closes this surface immediately by adopting a hybrid **ECDH-over-Pallas + ML-KEM-768** construction (§2.6, §3.1). Harvest-now-decrypt-later adversaries who capture today's ciphertexts and wait for a CRQC cannot decrypt them without breaking ML-KEM — a 2030+ horizon under the most aggressive published forecasts. The PQ migration surface that remains after v1 is strictly narrower than that carried by any currently deployed shielded pool.

**A deliberate bet, acknowledged**: as of v1 ship, UNO is the first L1 to carry an Orchard-family shielded-pool protocol directly on Plonky3 AIRs. All prior Plonky3 mainnet deployments — Polygon AggLayer pessimistic proofs (via SP1), OP Succinct, Valida, Lurk/Sphinx — apply the toolkit to general-purpose zkVMs or cross-chain aggregation proofs, not to payment-protocol circuits. This design opens that application. The underlying cryptographic construction (note commitments, nullifiers, randomized spend authorization, diversified stealth addresses) is unchanged from a well-studied specification family; only the proving backend is new to this class of circuit. The specific risks and mitigations of this first-application posture are enumerated in §13 (phased roadmap) and §12 (test strategy).

### 0.3 Bridgeless by architecture

No Shield, no Unshield, no bridge in v1, v2, or any later phase. This is a **permanent architectural invariant**, not a scope decision (§1.5, §16 decision #16). UNO supply is fixed at genesis, monotonically non-increasing (fees are burned in UNO, §16 decision #19), and entirely contained within wc=2. Validator compensation is paid in native TOS at the masterchain level — wc=2 behaves as any other TOS shardchain from the consensus-reward perspective — so the chain does not require a UNO inflation path to remain economically viable (§16 decision #23).

Any future proposal to introduce a supply-creation pathway on wc=2 should be understood as a proposal to design a different chain, not as an extension of this one.

### 0.4 Scope within the Ethereum 2030 strawmap

The strawmap names five L1 north stars:

- *Fast L1* — seconds-level inclusion and finality
- *Gigagas L1* — ~10 K TPS via zkEVMs and real-time proving
- *Teragas L2* — ~10 M TPS via data availability sampling
- *Post-Quantum L1* — centuries-long security via hash-based schemes
- *Private L1* — privacy as a first-class citizen, via L1 shielded transfers

**UNO's product is the intersection of the last two** — a Private L1 that is also a Post-Quantum L1, delivered as a single product. Fast L1 is inherited from TOS's 1-second global block rate. Gigagas and Teragas are not pursued: §5.9 accepts 15–30 TPS sustained (≤50 burst) as the intrinsic cost of terminal privacy on commodity validator hardware, and raw-throughput optimization at the cost of privacy is explicitly rejected (§15). Privacy and PQ are the two axes this chain optimizes; every other parameter follows.

### 0.5 How to read this document

- Readers new to the project: start here (§0), then §1 (Goals), then §7 (Prove–Verify–Scan Lifecycle). Those three sections establish the vocabulary used throughout.
- Readers with a specific concern: jump to the relevant section — bridgelessness and deanonymization argument in §1.5; cryptographic foundations in §2; wire format in §4; state model in §5; PQ roadmap in §6; lifecycle in §7; test strategy in §12; design-choice record in §15; decision log in §16.
- Reviewers looking for what has been rejected and why: §15 (design choices table) and §16 (numbered decisions) are the authoritative sources.

---

## 1. Goals and Non-Goals

### 1.1 What "privacy" means here

Our target is **terminal privacy** — the four properties a modern shielded chain must deliver:

1. **Amount confidentiality** — no on-chain value appears anywhere except the public fee.
2. **Sender unlinkability** — no sender identifier appears on chain; two spends by the same holder look independent.
3. **Receiver unlinkability** — no receiver identifier appears on chain; the receiver's long-term keys are never transmitted.
4. **Transaction graph unlinkability** — an observer cannot tell which prior tx produced the notes being spent; the anonymity set is the live note pool.

Anything weaker — the account + homomorphic-ciphertext recipe — still leaks who transacts with whom and is a strictly inferior terminal state. We design for terminal now rather than stage a v2 architecture replacement later.

### 1.2 v1 Goals (what ships)

- **One user-facing transaction type**: `Transfer` with `1..4` spends and `1..4` outputs (outputs include sender change). Balance `Σ spends = Σ outputs + fee` is enforced by an in-circuit constraint — there is no separate value commitment or binding signature (§3.3).
- **Native single asset (UNO)**, fixed at genesis, monotonically non-increasing via fee burn (§1.5, §10.3).
- **Stealth addresses** with diversifier-based key derivation, Ristretto255 as the off-circuit curve.
- **View-key hierarchy** (`fvk`, `ivk`, `ovk`) for native selective disclosure, hash-derived via Poseidon2.
- **Plonky3 STARK proof system over Goldilocks**, no trusted setup, PQ-native proof backend — no Phase 2 proof-system migration debt.
- **Client-side proving only.** Witness never leaves sender device (§7.2). Server-assisted prove is opt-in and privacy-weakening (§9.2).
- **Hybrid ECDH + ML-KEM-768 note encryption** — closes the HNDL window on on-chain ciphertexts at v1 ship, not deferred to Phase 2.
- **Main-account seed derivation** — wc=2 identity deterministically derived from the user's primary TOS seed (`uno_seed = BLAKE2b("uno-seed-v1" ‖ main_tos_seed)`); no separate key management.
- **Compact block filters** — 16-bit per-output detection tags + GCS-encoded block filter, making wallet sync ≤100× cheaper. Mobile-viable from day one.
- **Parallel Plonky3 verify across `num_cores`** as an **activation prerequisite**, not a later optimization. The chain is structurally unable to produce 1 s blocks at target TPS without it; see §7.4 and §13 P.3.
- **Cell-native state** — note-commitment tree frontier, nullifier set, anchor window, stats all live as TOS cells in CellDb inside a single executor account on wc=2 (§5).
- **Crypto-agility** via `scheme_id : u8` on every artifact. v1 ships `scheme_id = 0x01`. Future PQ upgrades (ML-DSA hybrid spend-auth in Phase 1; see §6) do not require a hardfork of the structural protocol.
- **Consensus-deterministic** execution; restart-survival; cross-validator state parity (§12 P.5).
- **JSON-RPC surface** — `uno_*` namespace served from `validator-engine/` (§9).

### 1.3 v1 Non-Goals (explicit)

- **No smart contracts.** v1 runs one fixed Transfer AIR. Programmable privacy (Aleo/Aztec-class zkVM-on-shielded-pool) is v3+.
- **No multi-asset.** Single native asset. Multi-asset + asset-scoped nullifiers: v2.
- **No cross-chain bridges — ever.** Initial supply is set at genesis and is the sole source of UNO supply for the lifetime of the chain. Shield/Unshield between wc=2 and any other workchain is not a v2 item, not a roadmap item, and not a post-mainnet migration — it is a permanent architectural exclusion. See §1.5 for the rationale.
- **No DEX / batch auction.** Batch-auction shielded DEX mechanics: v3+.
- **No PQ signature primitives shipped in v1.** Note encryption ships ML-KEM hybrid (above), but the spend-auth signature remains classical Schnorr-on-Ristretto255 in v1, upgradable to ML-DSA-65 hybrid in Phase 1 via `scheme_id = 0x02` (§6). Rationale: spend-auth signatures are not HNDL-vulnerable (signatures reveal nothing useful to a future CRQC adversary that harvested them today); the PQ surface is the note-encryption layer, which we close in v1.
- **No server-side scanning by default.** Wallet scans locally using `ivk` + compact filters; server-assisted scan is opt-in and privacy-weakening (§9.2).
- **No on-chain discovery / address book.** Out of scope. Address-sharing UX (handle/naming services, deep links) is a wallet-layer concern.
- **No Tachyon-style off-chain ciphertext or oblivious sync in v1.** v1 keeps on-chain ciphertext + compact filters; v3+ may migrate to Tachyon-adjacent architectures once Zcash's Ragu PCD library and oblivious-sync protocols mature (§14). v1 state schema is designed not to preclude this migration (§5.7).

### 1.4 Success criteria

1. On-chain footprint of a Transfer reveals only: `{tx occurred, fee, anchor, spend count, output count}`. No amount, no sender identity, no receiver identity, no link to prior txs.
2. A wallet with `ivk` correctly detects all incoming notes sent to any of its diversified addresses via compact-filter scan + hybrid-KEM trial-decrypt; a wallet without `ivk` detects nothing.
3. Validator nodes restarted mid-chain reproduce byte-identical `note_tree_root`, nullifier set root, and anchor window.
4. Client-side proving ≤ **22 s** on a 2020-era laptop (M1 or 8-core x86) for a 1-spend / 2-output Transfer under the pinned FRI parameters (§2.1: `log_blowup=2, num_queries=128`); validator verify ≤ **20 ms** single-core, ≤ 7 ms on 4-core parallel (§7.2, §7.4). Mobile proving is best-effort; no committed target.
5. Nullifier lookup ≤ **1 ms** against a 10 M-entry set (cache-warm); ≤ 10 ms (cache-cold).
6. An auditor holding `fvk` for a target account can reconstruct the full note history with correct amounts (via `ivk`-derived hybrid-KEM `sk_mlkem` + Schnorr verifying key); without `fvk`, zero recovery.
7. **Sustained throughput: 15–30 TPS at 1 s global block time**, burst capacity up to ~50 TPS when the nullifier LRU cache is warm. Higher throughput requires proof aggregation (v2 roadmap). This ceiling is intrinsic to terminal privacy on commodity validator hardware; we do not fight it in v1.
8. HNDL (harvest-now-decrypt-later) exposure: a CRQC adversary capturing all on-chain `enc_ciphertext` + `mlkem_ct` artifacts today cannot decrypt them without breaking ML-KEM-768. This closes the HNDL window at v1 ship, without waiting for Phase 2.

### 1.5 Bridgelessness as a permanent invariant

UNO is a **native, bridgeless asset**. Its entire supply is fixed in the wc=2 zerostate (§10.3), and no mechanism — at any phase of the roadmap — ever moves value between wc=2 and any other workchain (wc=0, wc=1, future wc=3+, or any external chain). This is not a scope decision about v1; it is a load-bearing privacy property of the whole design.

#### Why no bridge, ever

Any bridge between a public workchain and a shielded pool opens four structural deanonymization vectors that cannot be closed by better cryptography. These are documented in the empirical record against t↔z flows on the Zcash main chain (Kappos, Yousaf, Maller, Meiklejohn 2018 and subsequent work) and are structural, not implementation-dependent:

1. **Entry-side gas binding.** Any Shield tx must be submitted from a wc=0 (or wc=1) account that pays gas in a public asset. That wc=0 account is therefore bound on-chain to the existence of a shield event, even if the *amount* being shielded is privacy-protected inside wc=2. The attacker learns: *this address shielded something, at this time, of approximately this size.*
2. **Exit-side recipient binding.** Any Unshield tx must specify a wc=0 recipient address in cleartext. That address is bound to a wc=2 note being spent. Unshielding amount + time identifies the recipient path with near-certainty when the anonymity set is bounded.
3. **Timing and amount correlation across the boundary.** Shield(t₁, amount ≈ X) followed by Unshield(t₂, amount ≈ X) is a two-event fingerprint. Even with mixing inside the pool, research on t↔z flows shows that only a small fraction of shielded volume is actually well-mixed; most flows are linkable by a naive clustering attack.
4. **Anonymity-set collapse.** The *effective* anonymity set for a bridged flow is the subset of the pool that participated in shield/unshield within a similar window — not the full pool. UI claims of "full-pool anonymity" are empirically false when only a minority of supply crosses the bridge, because the bridged subset is distinguishable from dormant genesis-era supply.

No amount of circuit cleverness closes these. Gas must be paid; recipient addresses must be written; cross-chain timestamps are public. The only structural fix is to not have a bridge.

#### What this costs us, and why we pay it

The cost is loss of *cross-workchain composability* for UNO holders. A user with USDC on wc=1 cannot "make their USDC private." A user with UNO on wc=2 cannot use it in a wc=1 DeFi protocol. There is no atomic path between UNO and any other asset.

This is a real and accepted cost. It is not a defect. The claim this design makes is:

> Privacy, when it is a real guarantee, is a property of an asset from its inception. Retrofitting privacy onto a public asset via a bridge produces a weaker guarantee than users are led to believe. We ship the stronger guarantee.

A user who wants privacy holds UNO. A user who wants USDC's liquidity holds USDC. These are different products with different trade-offs. We do not conflate them and we do not attempt to market an intermediate form.

#### Implication for the rest of the design

This invariant is load-bearing across the doc:

- **Supply (§10.3):** genesis-only; no mint function exists; the code path to mint UNO does not appear in any workchain.
- **Economics (§16 decision #19, #23):** transaction fees are paid in UNO (plaintext in the tx header, §4.1) and are burned. Validator rewards for wc=2 are paid out of masterchain validator revenue in native TOS, not in UNO — wc=2 behaves as any other TOS shardchain from consensus-reward perspective. UNO supply is therefore monotonically non-increasing across the chain's lifetime, and validator economics do not require a UNO inflation path.
- **Scope (§14):** Shield/Unshield does not appear in v2, v3, or any later phase. It is removed entirely from the roadmap.
- **Auditability (§10.3):** the genesis distribution list is published in plaintext as `zerostate-genesis-notes.json`. This is the *only* transparency trade; it establishes the total supply exactly once, after which all movement is private.

Anyone reviewing this design should read "no bridges in v1" as shorthand for "no bridges, full stop" throughout. The earlier v2-roadmap Shield/Unshield placeholder was an error of scope and is retracted.

---

## 2. Cryptographic Foundations

### 2.0 Crypto-agility (scheme_id)

Every on-chain artifact — `Transfer`, `NoteCommitment`, `Nullifier`, every proof, every transcript — carries `scheme_id : u8` alongside `version : u8`.

- `version` — wire-format version. Bumped when fields change.
- `scheme_id` — cryptographic suite. Bumped when a primitive is swapped.

**v1 defines only** `scheme_id = 0x01`. Reserved IDs:

| ID | Name | Suite | Status |
|---|---|---|---|
| `0x01` | `v1-plonky3-goldilocks` | Plonky3 STARK / Goldilocks / Poseidon2 / Ristretto255 Schnorr spend-auth / ECDH+ML-KEM-768 hybrid note encryption | **v1 (now)** |
| `0x02` | `v2-mldsa-hybrid-spend-auth` | v1 + ML-DSA-65 hybrid spend-auth signature (co-signs every spend) | Phase 1 |
| `0x03` | `v3-tachyon-like` | v1 + PCD recursion + oblivious sync + off-chain ciphertext (Ragu-compatible) | Phase 3, capability-gated |
| `0x04..0xFE` | unassigned | — | — |
| `0xFF` | test | reserved for internal / fuzz; never accepted on mainnet | — |

Dispatch: the verify path is keyed `(workchain_id=2, scheme_id) → verifier`. v1 installs exactly one entry. Unknown `scheme_id` is a **deterministic reject**, never a silent fallthrough.

Transcript binding: every Fiat-Shamir transcript used in this design starts with the fixed root tag `"uno-workchain-v1"` (ASCII, 16 bytes, zero-padded to one Poseidon2-over-Goldilocks absorb). Immediately after the root, the transcript absorbs `"scheme-id" || u8` as its first variable field. Challenges are thus domain-separated per scheme; no cross-scheme proof replay is possible even under byte-level wire-format collisions.

Cost: 1 byte per tx, 1 byte per transcript absorb, one dispatch map entry.

### 2.1 Field and proof system

- **Field**: **Goldilocks** prime field `Fp = Fp_G` with `p = 2⁶⁴ − 2³² + 1`. 64-bit, CPU-friendly, SIMD-friendly, the native operating field of Plonky3.
- **Proof system**: **Plonky3 STARK** with FRI polynomial commitments. No trusted setup. Transparent, post-quantum-native (hash-based). Proofs for the Transfer AIR are ~40–100 KB depending on circuit shape (with our pinned FRI parameters below); verify is ~7–20 ms on a modern validator core.
- **Transfer AIR**: hand-written Plonky3 Algebraic Intermediate Representation for the Transfer claims in §4.2. Proof system components reused from Plonky3's production toolkit (AggLayer/SP1 baseline); the Transfer AIR is project-specific.

**FRI parameters (pinned, consensus-binding)**:

```
log_blowup         = 2     // trace domain = 2^log_blowup · trace length
num_queries        = 128   // FRI verifier query rounds
proof_of_work_bits = 16    // Fiat-Shamir grinding bits
```

**Security posture**: ~128-bit conjectured soundness / ~64-bit proven soundness against classical adversaries, ~64-bit conjectured / ~32-bit proven against a quantum adversary (Grover halves bits). For a payment chain this is the appropriate level — tighter than Plonky3/SP1/AggLayer defaults (`num_queries=84-100`, ~100-bit conjectured) because a soundness break on a privacy L1 is strictly more damaging than on a cross-chain aggregation proof (forged proof → unauthorized value creation, not just bridge-balance inconsistency).

**Rejected alternatives**:
- `num_queries=84` (Plonky3 default): ~100-bit conjectured, ~50-bit proven. Sufficient for zkVMs/aggregation, not for native-value L1.
- `num_queries=200` with `log_blowup=1`: same proven security but +50% proof size.
- `log_blowup=4, num_queries=84`: ~128-bit proven (stronger) but prove time +80% — UX-negative without security gain against realistic classical adversaries.

See §16 decision #33 for the rationale.

Why Goldilocks over alternatives:
- **vs. Pallas/Vesta (Halo2)**: Pallas has no PQ path; every shielded chain on it (Zcash Orchard) carries a Phase 2 proof-system migration debt. Goldilocks with FRI is PQ-native at v1 ship — no Phase 2 debt on the proof layer.
- **vs. BabyBear (31-bit field used by Risc0 and some SP1 configurations)**: BabyBear is faster on 32-bit architectures and GPUs, but the security overhead is tighter; 64-bit Goldilocks is the industry middle ground. Plonky3 supports both; we pick Goldilocks for a conservative security margin on a payment chain.
- **vs. Binary / tower fields (Binius)**: research-stage. Too early for a payment L1.
- **vs. BN254 / BLS12-381 pairing curves**: per-circuit or universal trusted setup required; rejected.

### 2.2 In-circuit hash: Poseidon2 over Goldilocks

- **Poseidon2** (Grassi, Khovratovich, Schofnegger 2023) — same algorithm family used in Halo2 / Orchard, but parameterized over Goldilocks (width `t = 8` for 4-to-1 absorb, `t = 16` for wide sponge as needed), not over Pallas `Fp`.
- Used inside the Plonky3 AIR for: note-commitment hashing, Merkle-tree path hashing, key derivation (`nk`, `ivk`, `ovk`), in-circuit Fiat-Shamir transcript absorbs, nullifier derivation.
- Used outside the circuit (plain software) for: wallet-side `nf` recomputation, address-hash domain separation, compact-filter tag derivation (§5.8).

**Off-circuit hashes**:
- **BLAKE3** — TOS cell representation hashing (chain-internal, unchanged from base TOS) and `tx_hash` computation (§4.1).
- **BLAKE2b** — seed derivation for off-circuit secrets (`ask`, Ristretto secret, ML-KEM seed). Standardized, byte-oriented, well-audited.

**Not used inside circuits**: Keccak, BLAKE3, SHA-2 — these are byte-oriented and prohibitively expensive in an AIR. Poseidon2 is the only in-circuit hash we admit.

### 2.3 Note commitment tree

- **Type**: depth-32 sparse Merkle tree (SMT); supports up to 2³² ≈ 4 B live notes.
- **Node hash**: `Poseidon2(left, right)` over Goldilocks. Each node is 4 field elements (256 bits of state) encoded as `bits256`.
- **Append-only**: new commitments are appended at `next_position`; no mutation or deletion.
- **On-chain storage**: only the **frontier** — the 32 right-edge node hashes needed to append and compute the root — persists on-chain (~1 KB, §5.2). Full history is reconstructable by clients from the tx log.
- **Anchors**: at the end of each block the current root is pushed into a 100-block ring buffer. Spends reference an anchor by root hash; validator accepts iff that anchor is in the window.

### 2.4 Nullifier scheme

For a note with commitment `cm` at position `pos` in the tree, under nullifier key `nk`:

```
nf = Poseidon2("uno-nf-v1", nk, cm, pos)   // output: 256 bits (4 × Goldilocks field elements)
```

Properties:
- **Hiding**: `nf` reveals no information about `cm`, `pos`, or `nk` to a chain observer.
- **Deterministic**: same note → same `nf` → double-spend caught by set-membership check.
- **Unlinkable**: two different notes owned by the same `nk` produce `nf`s indistinguishable from random.
- **In-circuit verifiable**: the AIR constrains `nf = Poseidon2(...)` directly; no external hash needed.

### 2.5 Spend authorization (fresh per-spend Schnorr on Ristretto255)

Spend authorization is **off-circuit** and **decoupled from any long-term identity key**. Ownership is proven entirely in-circuit via the ivk-commitment binding (§4.2 claim 3). The Schnorr signature merely binds the transaction to a one-time ephemeral key, preventing mempool tampering.

- **Curve**: Ristretto255 over Curve25519 (RFC 9496).
- **Per-spend fresh keypair**: the wallet samples `rsk ∈ scalars(Ristretto255)` fresh for each spend; publishes `rk = rsk · G`. There is **no derivation** from any long-term holder key.
- **Signature**: Schnorr-on-Ristretto255 with `rsk` over `tx_hash` (§4.1).

**Unlinkability**: each `rk` is a uniformly random fresh public key. No observer (nor even the holder's `fvk`) can cluster spends by `rk`.

**Why no Orchard-style `rk = ak + α·G` randomization?** Orchard ties `rk` to the holder's long-term `ak` so that `fvk` holders can trace their own spends through the randomizer `α`. Our design achieves equivalent audit by having the sender encrypt a `ovk`-decryptable memo into `out_ciphertext` (§4.1); the `fvk = (ivk, nk, ovk, sk_mlkem)` audit path (§2.6, §7.5) recovers spend history via `ovk`, not via `rk` inversion. This lets us avoid **all** curve operations inside the AIR — structurally why the Plonky3-over-Goldilocks path is cheap.

**No in-circuit curve operations.** The AIR manipulates only hash-chained scalars and Poseidon2 hashes; every Ristretto255 op (address derivation, ECDH for hybrid KEM, Schnorr sign/verify) is off-circuit.

**Phase 1 upgrade** (`scheme_id = 0x02`): the spend-auth signature is promoted to a hybrid Schnorr-Ristretto + ML-DSA-65 co-signature. Both verify on every spend. Trigger: production-grade ML-DSA-65 library with constant-time verify. See §6.2.

### 2.6 Key hierarchy (hash-native)

All secrets and viewing keys are hash-derived. The only curve-based public material is the Ristretto255 spend-auth key and the Ristretto255 ECDH transmission key.

The wc=2 seed is deterministically derived from the user's primary TOS seed:

```
uno_seed = BLAKE2b-256("uno-seed-v1" || main_tos_seed)
```

This binding is intentional (§1.2): a user with any TOS account automatically has a wc=2 identity without maintaining separate key material.

From `uno_seed`, the wallet derives three layers of material:

```
// (1) Off-circuit, byte-oriented secrets (BLAKE2b-256 with domain separators):
esk_seed    = BLAKE2b-256("uno-esk-v1"    || uno_seed)   // per-output ephemeral seed
mlkem_seed  = BLAKE2b-256("uno-mlkem-v1"  || uno_seed)   // deterministic ML-KEM KeyGen seed
ovk         = BLAKE2b-256("uno-ovk-v1"    || uno_seed)   // outgoing viewing key, 32 B

// (2) In-circuit-reproducible secrets (Poseidon2-over-Goldilocks):
nk          = Poseidon2("uno-nk-v1",  uno_seed)          // nullifier key, 256 bits
ivk         = Poseidon2("uno-ivk-v1", uno_seed, nk)      // incoming viewing key (Ristretto scalar), 256 bits

// (3) Off-circuit public material:
(pk_mlkem, sk_mlkem) = ML-KEM-768.KeyGen(mlkem_seed)     // deterministic PQ KEM keypair

// Full viewing key (audit bundle):
fvk         = (ivk, nk, ovk, sk_mlkem)
```

**Design note — no long-term spend-auth key `ak`.** Earlier drafts derived `ak = ask · G` as a long-term Ristretto255 spend-auth pubkey, analogous to Orchard. Per decision §2.5 (fresh per-spend `rk`), `ak` has no role in spending or verifying, so it is removed from the key hierarchy. This shrinks `fvk` by 32 B and eliminates one curve op from wallet key-gen.

**Why `nk` and `ivk` use Poseidon2 while the rest use BLAKE2b**: `nk` is the in-circuit input to the nullifier derivation (§2.4); `ivk` is the in-circuit input to the ivk-commitment binding (§4.2 claim 3). Both must be cheaply re-derivable inside the AIR. Poseidon2 over Goldilocks is orders of magnitude cheaper to constrain in-circuit than BLAKE2b. Everything else is off-circuit and stays byte-oriented for audit clarity.

**Addresses (stealth + diversifiers)**:

```
d              : bits88                                             // diversifier chosen by recipient
g_d            = HashToRistretto("uno-diversifier-v1" || d)         // diversified base point
pk_d           = ivk · g_d ∈ Ristretto255                           // diversified transmission key (off-circuit)
ivk_commitment = Poseidon2("uno-ivk-cm-v1", ivk, d)                 // 256-bit binding of ivk to this diversifier
Address        = (d, compress(pk_d), ivk_commitment, pk_mlkem)
               = 11 B + 32 B + 32 B + 1184 B
               ≈ 1259 B total
```

`HashToRistretto` is the standard hash-to-curve for Ristretto255 (RFC 9380). A single `uno_seed` yields ~2⁸⁸ distinct diversified addresses; addresses of the same holder are unlinkable by an observer.

**Role of `ivk_commitment` in the address.** The field is the in-circuit hash-chain binding anchor (§4.2 claim 3). Sender writes it into `cm` at note-creation time (§3.2); spender recomputes it from their own `ivk` + `d` inside the AIR to prove ownership. `ivk_commitment` is public; `ivk` is never.

**Consistency of `pk_d` and `ivk_commitment`.** Both are derived off-circuit by the receiver from the same `(ivk, d)`. The AIR does **not** verify that `pk_d` matches `ivk` (that would require an in-circuit curve op, rejected by §2.5). A malformed address that desynchronizes the two produces a stuck output (encryption uses `pk_d`, decryption matches against `ivk_commitment`) — the affected sender loses funds, but no pool-level security property is violated. Wallets produce addresses deterministically from `uno_seed`, so this is effectively impossible in practice.

**Address size is the deliberate UX cost of v1's PQ posture.** The ~1.26 KB address carries the recipient's ML-KEM-768 public key plus the 32-byte ivk-commitment, which are required for the sender to perform the PQ half of hybrid encapsulation and write a valid note commitment. Addresses are expected to be shared via QR code, NFC, deep link, or wallet-to-wallet DM — not as plain text in a social-media bio.

### 2.7 Note encryption: hybrid ECDH + ML-KEM-768

Every `OutputDescription` carries a note ciphertext locked by an AEAD key derived from **both** a classical ECDH shared secret **and** an ML-KEM-768 shared secret. HNDL (harvest-now-decrypt-later) security requires breaking both to decrypt a v1 ciphertext. Combiner follows the split-KDF pattern established in eprint 2025/1444 ("The Best of Both KEMs").

**Sender encrypts a note** to an address `(d, pk_d, pk_mlkem)`:

```
// 1. Classical ECDH on Ristretto255
esk        ∈ scalars(Ristretto255), fresh per output
epk        = esk · g_d                          // published in OutputDescription
s_dh       = esk · pk_d                         // shared point, 32 B compressed

// 2. Post-quantum KEM encapsulation
(mlkem_ct, s_pq) = ML-KEM-768.Encap(pk_mlkem)   // 1088 B ct, 32 B shared secret

// 3. Hybrid KDF (split-combiner, eprint 2025/1444)
k_aead = BLAKE3(
    "uno-hybrid-kem-v1"       ||
    compress(s_dh) (32 B)     ||
    s_pq (32 B)               ||
    compress(epk) (32 B)      ||
    BLAKE3(mlkem_ct) (32 B)
)[0..32]

// 4. AEAD with deterministic nonce
nonce      = BLAKE3("uno-nonce-v1" || compress(epk))[0..12]
enc_ct     = ChaCha20-Poly1305.Encrypt(k_aead, nonce, plaintext)
// Outputs: (mlkem_ct, epk, enc_ct) → OutputDescription (§4.1)
```

**Receiver decrypts** on scan:

```
s_dh'      = ivk · epk                          // ECDH symmetry; receiver derives same s_dh
s_pq'      = ML-KEM-768.Decap(sk_mlkem, mlkem_ct)
k_aead'    = BLAKE3(...)                        // same transcript
plaintext  = ChaCha20-Poly1305.Open(k_aead', nonce, enc_ct)
// AEAD tag failure → output not for this wallet; cheap rejection
```

**Security argument (informal)**:
- An adversary breaking only Ristretto255 ECDH (e.g., via Shor) still faces ML-KEM-768 soundness; cannot derive `k_aead`.
- An adversary breaking only ML-KEM-768 (classical cryptanalysis discovery) still faces Ristretto255; cannot derive `k_aead`.
- The transcript binds `epk` and `BLAKE3(mlkem_ct)`, preventing an adversary from substituting one ciphertext with another and having the key still derive correctly. Formal argument follows eprint 2025/1444, which proves the split-KDF combiner is IND-CCA2-secure under the conjunction of either component's IND-CCA2.

**Phase 1+**: the hybrid KEM need not change in Phase 1. In Phase 3 (Tachyon-like), `enc_ct` + `mlkem_ct` move off-chain, and the HNDL surface disappears entirely.

### 2.8 Compact filter tag and block-filter encoding

Each `OutputDescription` carries a 16-bit `filter_tag` derived from the hybrid AEAD key:

```
filter_tag : bits16
           = Truncate_16bit( Poseidon2("uno-filter-v1", k_aead) )
```

The tag is computable by **sender** (knows `k_aead` at encrypt time) and **receiver** (derives `k_aead` on scan); an observer without `ivk` + `sk_mlkem` cannot compute it. The 16-bit width gives a per-block per-wallet false-positive rate of `2⁻¹⁶`, so a wallet rejects ~99.9985% of outputs via filter match before attempting AEAD decryption.

**Tag privacy**: since each output uses fresh `esk`, `k_aead` is fresh, so `filter_tag` is cryptographically unlinkable across outputs even for the same receiver. Observers cannot cluster outputs by recipient.

#### 2.8.1 Per-block filter encoding (consensus-binding spec)

At end of block, the validator collects all `filter_tag` values emitted in the block, deduplicates, sorts ascending as u16, and emits a **Golomb-Coded Set (GCS)** encoding over the raw 16-bit values:

```
BlockFilter(block_seqno) :=
  tags    : sorted_deduplicated_list(OutputDescription[*].filter_tag)
  encoded : GCS_encode(tags, P = 15, M = 2^16)
```

**Parameters pinned**:
- `P = 15` (Golomb parameter; unary-terminated deltas use 2^P buckets).
- `M = 2^16 = 65536` (tag universe; matches the `filter_tag` width exactly).
- **No secondary hash**. `filter_tag` is already a cryptographic derivative of `k_aead` (§2.8 above); GCS operates directly on the u16 value. This differs from BIP-158, which hashes bitcoin-script entries into a uniform pseudo-random space before GCS; our tags are already uniformly random, so the extra hash layer would add spec complexity without privacy benefit.

**Encoding procedure** (byte-identical across every implementation):
1. Sort the u16 tag multi-set ascending; drop duplicates.
2. Prepend a varint of `N = |tags|`.
3. For each `i ≥ 1`, compute delta `Δᵢ = tagᵢ − tagᵢ₋₁ − 1`; write Golomb-Rice of `Δᵢ` with quotient `q = Δᵢ >> P` in unary followed by remainder `r = Δᵢ & ((1 << P) − 1)` in `P` bits.
4. Byte-align with zero bits.

**Decoding procedure**: reverse; emit `tagᵢ` by accumulating `Δᵢ + 1` from `tagᵢ₋₁`.

**Expected size**: at 30 TPS × 2 outputs/tx the block has ~60 distinct tags; GCS with `P=15, M=2^16` produces ~100–150 B per block. At 50 TPS burst, ~180–260 B per block.

**Consensus status**: the filter itself is a **derived view**, not consensus state (§5 state model). Validators recompute it end-of-block from the accepted `OutputDescription`s; any full node can reconstruct it from the ordered tx log. The filter is served via `uno_getBlockFilter(seqno)` (§9.1) — callers cross-check by refetching and re-GCS-encoding if desired. Because the encoding is byte-identical across implementations, wallet SDKs that build against this spec match validator output exactly; **no keyed-hash agreement is required**.

**Why GCS over a bit-vector or a sorted plain list**:
- Plain sorted u16 list: ~120-200 B/block. Simpler but ~50% larger than GCS.
- 65536-bit bit-vector: 8 KB/block fixed — prohibitive daily download.
- GCS over raw u16: best trade-off; simple spec (no hash choice); byte-identical across implementations.

---

## 3. Note, Commitment, Nullifier

Note that there is no separate **value commitment (`cv`)** or **binding signature** in this design. Balance (`Σ spend.value = Σ output.value + fee`) is enforced by an in-circuit constraint in the Transfer AIR (§4.2 claim 8), not by a homomorphic Pedersen trick. Removing `cv` / `binding_sig` eliminates two Pallas-specific constructs from the protocol, shrinks every tx by 32 B per spend/output + 64 B per tx, and matches the natural expressive shape of a Plonky3 AIR over 64-bit Goldilocks (u64 values are cheap to constrain directly).

### 3.1 Note (plaintext, off-chain)

```
Note :=
  d       : bits88           // recipient diversifier
  pk_d    : Ristretto255     // recipient's diversified transmission key (32 B compressed)
  value   : uint64           // amount in UNO nano-units
  rseed   : bits256          // randomness seed; derives the note-commitment trapdoor
```

Never transmitted on-chain in plaintext. Transmitted encrypted to the receiver inside `enc_ciphertext` of the tx output description (§2.7).

From `rseed`, the sender derives the note-commitment trapdoor:
- `rcm = Poseidon2("uno-rcm-v1", rseed)` — 4 Goldilocks field elements (256 bits) fed directly into the note-commitment hash in §3.2.

No `rcv` blinding factor is needed — there is no Pedersen `cv`.

### 3.2 Note commitment (on-chain, in `OutputDescription`)

```
cm = Poseidon2("uno-cm-v1", d, pk_d.bytes, ivk_commitment, value, rcm)
```

where `ivk_commitment = Poseidon2("uno-ivk-cm-v1", ivk, d)` (§2.6) — the receiver's 256-bit ivk-binding anchor.

- Inputs packed into Goldilocks field elements: `d` (11 B) → 2 fes; `pk_d.bytes` (32 B compressed Ristretto) → 4 fes; `ivk_commitment` (256 bits) → 4 fes; `value` (u64) → 1 fe; `rcm` (256 bits) → 4 fes. Total Poseidon2 input: 15 field elements → one wide-sponge Poseidon2 permutation (width t=16) with output truncated to 4 field elements (256 bits) as `cm`.
- The sender gets `(d, pk_d, ivk_commitment, pk_mlkem)` from the recipient's published address and thus can compute `cm` without knowing `ivk` itself.
- Computed inside the Plonky3 AIR by the prover at spend time for consistency with the witness; the chain takes `cm` as-is at output time.
- Leaks zero bits about `value` by the pre-image resistance and hiding of Poseidon2, given a 256-bit seed `rseed` feeding `rcm`.

**Why include `ivk_commitment`?** This is the on-chain anchor that the AIR's ownership proof (§4.2 claim 3) hashes into — the prover must show they know an `ivk` satisfying `Poseidon2("uno-ivk-cm-v1", ivk, d) == ivk_commitment`. Without this field in `cm`, there would be no in-circuit binding from the note to the holder's seed, since we reject in-circuit curve operations (§2.5). With this field, ownership is proven purely through hash-chain reproducibility — no Ristretto scalar multiplication inside the AIR.

**Why include `pk_d.bytes`?** So that the commitment is fully determined by the note's off-chain content, not just by `(d, ivk_commitment, value, rcm)`. A chimera address that desynchronizes `pk_d` from `ivk_commitment` produces a stuck output (§2.6), but the `cm` itself remains well-defined and uniquely bound to the full note contents.

### 3.3 Balance constraint (in-circuit, not a separate artifact)

The Transfer AIR proves value conservation directly:

```
Σ_{i ∈ spends}  value_i  =  Σ_{j ∈ outputs} value_j  +  fee
```

Each `value_i` / `value_j` is a u64 private witness. The AIR enforces:

1. **Range check**: every `value_i`, `value_j ∈ [0, 2⁶⁴)` — trivial in Goldilocks since `u64 < p_Goldilocks`, so each value is one field element with no modular wraparound.
2. **Sum equality**: the linear equation above. ≤ 4 + 4 = 8 field additions, one equality check. Negligible circuit cost.

The `fee` is a public input (declared in the tx header and visible on chain). There is no hidden component of the fee; a plaintext fee is intentional (§4.1).

**No homomorphic trick is needed**. The Halo2/Orchard construction used Pedersen commitments because in-circuit 64-bit arithmetic was expensive in Pallas `Fp`; the homomorphic Schnorr binding signature was a byte-saver and verify-cost optimization. In Plonky3 over 64-bit Goldilocks, 64-bit arithmetic is native and free — the optimization no longer applies.

**Consequence for the wire format**: `SpendDescription` and `OutputDescription` omit the `cv` field; `Transfer` omits the `binding_sig` field. See §4.1.

### 3.4 Nullifier (on-chain, in `SpendDescription`)

When a note is spent:

```
nf = Poseidon2("uno-nf-v1", nk, cm, pos)
```

where `nk` is the owner's nullifier key (256 bits, hash-derived from seed, §2.6) and `pos` is the leaf index of `cm` in the note commitment tree, set at append time.

**Simplification vs Orchard**: the Zcash Orchard nullifier is `Extract(Hash_nk(ρ) + Commit(ψ, cm))` using Sinsemilla commitments over per-note trapdoors `(ρ, ψ)`. Our construction replaces the `(ρ, ψ)` trapdoors with the public leaf position `pos`. This simplification:
- Reduces the Note struct by 64 bits.
- Removes Sinsemilla (a Pallas-specific hash-to-curve commitment) from the AIR entirely — Sinsemilla has no natural Goldilocks analogue, so this simplification also avoids a non-native primitive.
- Relies on `pos` being unique per committed note (true by tree-append semantics).
- Security analysis: `nf` is still computationally binding to the note and hiding under Poseidon2. The simplification trades per-note pseudo-randomness (from `ρ, ψ`) for the chain-provided uniqueness of `pos`. Under Poseidon2 modeled as a random oracle, the scheme is sound.

Published in the `SpendDescription`. Added to the nullifier set (§5.3). A second appearance of the same `nf` in any future tx is an attempted double-spend and is rejected at §4.3 step 2.

---

## 4. Transaction Format

### 4.1 `Transfer` wire body

```
Transfer :=
  version           : uint8                     = 1
  scheme_id         : uint8                     = 0x01
  chain_id          : uint32
  anchor            : bits256                    // past tree root these spends are proved against
  expiry_block      : uint64                     // tx invalid after this block seqno
  fee               : uint64                     // plaintext, native asset nano-units
  spend_count       : uint8                      // 1..4
  output_count      : uint8                      // 1..4
  spends            : Array<SpendDescription, spend_count>
  outputs           : Array<OutputDescription, output_count>
  zk_proof          : ^Cell                      // Plonky3 STARK proof, serialized via CellString

SpendDescription :=
  nullifier         : bits256                    // nf = Poseidon2("uno-nf-v1", nk, cm, pos)
  rk                : bits256                    // randomized spend pubkey = ak + α·G (compressed Ristretto255)
  spend_auth_sig    : bits512                    // 64 B Schnorr on Ristretto255 under rsk over tx_hash

OutputDescription :=
  cm                : bits256                    // note commitment (Poseidon2 over Goldilocks)
  epk               : bits256                    // ephemeral pubkey epk = esk·g_d (compressed Ristretto255)
  filter_tag        : bits16                     // 2 B compact-filter detection tag (§2.8)
  enc_ciphertext    : ^Cell                      // ~580 B ChaCha20-Poly1305 over Note plaintext + memo
  mlkem_ct          : ^Cell                      // 1088 B ML-KEM-768 ciphertext
  out_ciphertext    : bytes[80]                  // 80 B inline, AEAD-encrypted memo recoverable with ovk
```

Inline field sizes:
- Fixed tx header (everything before `spends`): `1+1+4+32+8+8+1+1 = 56` bytes.
- Each `SpendDescription` inline: `32+32+64 = 128` bytes (no `cv`).
- Each `OutputDescription` inline (excluding `enc_ciphertext` and `mlkem_ct` refs): `32+32+2+80 = 146` bytes (no `cv`, plus `filter_tag`).
- No `binding_sig` on the tx.
- `zk_proof` is a ref to a cell chain — Plonky3 STARK proof under the pinned §2.1 FRI parameters, ~52 KB for a 1-spend/2-output Transfer, ~100 KB worst-case 4/4. See §17.1.

`enc_ciphertext` layout (~580 B total, unchanged from v1 design pre-Plonky3):
- 84 B: `Note` plaintext fields packed and aligned (11 B `d` + 32 B `pk_d` + 8 B `value` + 32 B `rseed` + 1 B padding = 84 B).
- 480 B: encrypted memo (padded to fixed size to prevent length-based metadata leakage).
- 16 B: Poly1305 authentication tag.
- 12 B ChaCha20 nonce is derived deterministically from `epk` (`BLAKE3("uno-nonce-v1" || compress(epk))[0..12]`), not transmitted.

`mlkem_ct` layout: 1088 B ML-KEM-768 ciphertext, serialized via `CellString` (~9 cells).

**Size breakdown** (typical 1-spend / 2-output tx):
- Inline tx body: `56 + 128 + 2×146 = 476` bytes.
- Ref cell chain for 2 × `enc_ciphertext` (~580 B each, ~5 cells): ~1.4 KB with overhead.
- Ref cell chain for 2 × `mlkem_ct` (~1088 B each, ~9 cells): ~2.4 KB with overhead.
- Ref cell chain for `zk_proof` (~52 KB Plonky3 proof, ~420 cells): ~64 KB with overhead.
- **Total: ~68 KB per typical tx.** Worst-case 4-spend / 4-output with 100 KB proof: ~135 KB.

Larger than a Halo2-based shielded tx (~15 KB) due to the STARK proof size. This is the intrinsic cost of PQ-native proving. Bandwidth impact analyzed in §5.9 and §7.4; stays within datacenter-validator budgets and is borderline tight for residential operators, a conscious trade against Phase 2 migration debt.

**Canonical tx hash** (used by `spend_auth_sig` as the message it signs, and by `uno_getTransactionStatus` as the lookup key):

```
tx_hash := BLAKE3(
    version(1) || scheme_id(1) || chain_id(4) || anchor(32) ||
    expiry_block(8) || fee(8) || spend_count(1) || output_count(1) ||
    for each spend in declared order:
        nullifier(32) || rk(32)                              // SpendDescription EXCEPT spend_auth_sig
    for each output in declared order:
        cm(32) || epk(32) || filter_tag(2) ||
        cell_hash(enc_ciphertext) || cell_hash(mlkem_ct) || out_ciphertext(80)
)
```

The signature fields (`spend_auth_sig[i]`) and the `^zk_proof` cell ref are **excluded** — signing outputs over `tx_hash` would be circular, and the proof's public inputs bind the same tuple transitively. Cell-content fields (`enc_ciphertext`, `mlkem_ct`) are hashed via cell root, keeping `tx_hash` O(inline) to compute.

`filter_tag` is included in `tx_hash` so malicious senders cannot substitute filter tags after the fact. Its correctness (match against actual `k_aead`) is **not** attested by the ZK proof — a wrong tag only causes the intended receiver to fail filter matching and fall back to full scan, not a consensus event.

Every signature and every ZK-proof public input binds `tx_hash` (or equivalently, binds the same tuple transitively). Replay across chain_ids, schemes, or block heights is structurally impossible.

### 4.2 What the ZK proof attests

The Plonky3 Transfer AIR (for `scheme_id = 0x01`) proves the following claims simultaneously. All arithmetic is over Goldilocks; all hashes are Poseidon2-over-Goldilocks. **No curve operations appear inside the AIR** (§2.5); every identity claim is expressed as a hash-chain.

Per `SpendDescription` (index `i`):

1. **Tree membership**: spent `cm_i` is a leaf of the tree rooted at `anchor`. Proved via a 32-level Merkle path with Poseidon2 internal nodes. Witness: the 32 sibling hashes + leaf position `pos_i`.

2. **Note opening**: prover knows `(d_i, pk_d_i.bytes, ivk_commitment_i, value_i, rseed_i)` such that
   ```
   cm_i = Poseidon2("uno-cm-v1", d_i, pk_d_i.bytes, ivk_commitment_i, value_i, rcm_i)
   ```
   where `rcm_i = Poseidon2("uno-rcm-v1", rseed_i)`. Here `pk_d_i.bytes` is a 32-byte private witness treated as opaque bytes inside the AIR — no curve-level consistency is checked.

3. **Ownership (ivk-commitment hash-chain)**: prover knows `(uno_seed, ivk_i)` such that
   ```
   nk_i            = Poseidon2("uno-nk-v1",  uno_seed)
   ivk_i           = Poseidon2("uno-ivk-v1", uno_seed, nk_i)
   ivk_commitment_i = Poseidon2("uno-ivk-cm-v1", ivk_i, d_i)
   ```
   and the computed `ivk_commitment_i` equals the value opened from `cm_i` in claim 2. This is the **only** ownership anchor — it binds the note to the holder of `uno_seed` without any in-circuit curve operation. Only the holder with the matching `ivk` can satisfy the constraint; no one can construct a valid spend proof for a note addressed to a different `ivk_commitment`.

4. **Nullifier correctness**:
   ```
   nf_i = Poseidon2("uno-nf-v1", nk_i, cm_i, pos_i)
   ```
   where `nk_i` comes from the same seed-material chain as claim 3 and `pos_i` is the leaf position opened in claim 1.

5. **Range**: `value_i ∈ [0, 2⁶⁴)` — enforced trivially by the Goldilocks field constraint, since `value_i < p_Goldilocks = 2⁶⁴ − 2³² + 1` implies the value fits as one unmodded field element.

Per `OutputDescription` (index `j`):

6. **Well-formed commitment**: prover knows `(d_j, pk_d_j.bytes, ivk_commitment_j, value_j, rseed_j)` such that
   ```
   cm_j = Poseidon2("uno-cm-v1", d_j, pk_d_j.bytes, ivk_commitment_j, value_j, rcm_j)
   ```
   with the sender-chosen recipient address fields `(d_j, pk_d_j.bytes, ivk_commitment_j)` matching the address the sender encrypted to. No in-circuit link between these fields is required — the AIR treats them as opaque witnesses.

7. **Range**: `value_j ∈ [0, 2⁶⁴)` — same Goldilocks-native check as claim 5.

Whole-tx balance:

8. **Value conservation** (replaces the Pedersen `cv` / binding-signature mechanism used by Orchard):
   ```
   Σ_i value_i = Σ_j value_j + fee
   ```
   Enforced in-circuit as a single field-element equality over summed u64 values. `fee` is a public input.

**No claim for `rk_i` ↔ `ak` randomization**. Under §2.5, `rk_i` is a fresh per-spend Ristretto255 public key with no long-term anchor. The Schnorr `spend_auth_sig[i]` on `tx_hash` under `rk_i` is verified off-circuit (§4.3 step 3); the AIR has no responsibility for linking `rk_i` to the seed.

Public inputs visible to the verifier: `scheme_id`, `chain_id`, `expiry_block`, `fee`, `anchor`, per-spend `(nf_i, rk_i)`, per-output `(cm_j, epk_j, filter_tag_j)`. All other values are private witnesses.

The Plonky3 proof attests claims 1–8 in one shot. The verifier additionally checks the per-spend Schnorr `spend_auth_sig` off-circuit. No separate balance proof, no binding signature, no in-circuit curve operations.

### 4.3 Deterministic verification order

`uno_workchain::verify_transfer()` runs during the compute phase and is **consensus-critical**: every validator must agree on accept/reject. Mempool admission is a separate, cheaper filter — see §4.3a and §7.3. The order below is the full consensus verify; any failure is a deterministic reject:

1. **Cheap syntax**:
   1. `version == 1`, `scheme_id == 0x01`, `chain_id == expected`.
   2. `expiry_block ≥ current_block` AND `expiry_block ≤ current_block + expiry_window_blocks` (ConfigParam 84).
   3. `1 ≤ spend_count ≤ 4`, `1 ≤ output_count ≤ 4`.
   4. `fee ≥ min_fee_nano + fee_per_byte_nano · tx_size_bytes + fee_per_spend_nano · spend_count + fee_per_output_nano · output_count`.
   5. `anchor` matches one of the 100 roots in `state.anchor_window`.
   6. All `spend.nullifier` pairwise distinct within tx; all `output.cm` pairwise distinct within tx.
   7. Every 32-byte Ristretto255 point field (`rk`, `epk`) decompresses to a valid non-identity point on Ristretto255.
2. **Nullifier not-spent**: for each spend, `nf ∉ nullifier_set` (LRU hit is sufficient for positive-lookup reject; negative LRU must be followed by a cell-dict lookup per §5.3).
3. **Each `spend_auth_sig`** verifies as Schnorr-on-Ristretto255 under the corresponding `rk`, signed over `tx_hash` (BLAKE3 over canonical tx bytes excluding signatures and proof).
4. **Plonky3 proof** verifies (covers claims 1–8 from §4.2). Public inputs are assembled into a canonical Goldilocks field-element vector. Verifier and prover must agree **bit-identically**; the encoding below is consensus-binding and pinned for `scheme_id = 0x01`.

   **Element order** (from `PublicInputs(tx)`):

   1. `scheme_id`         (u8)  → 1 Goldilocks element.
   2. `chain_id`          (u32) → 1 Goldilocks element.
   3. `expiry_block`      (u64) → 1 Goldilocks element, with `x < p_Goldilocks` asserted.
   4. `fee`               (u64) → 1 Goldilocks element, with `x < p_Goldilocks` asserted.
   5. `anchor`            (256 bits) → 4 Goldilocks elements.
   6. For each spend `i` in declared order: `nf_i` (4 elements), `rk_i.bytes` (4 elements).
   7. For each output `j` in declared order: `cm_j` (4 elements), `epk_j.bytes` (4 elements), `filter_tag_j` (u16 → 1 element).

   Total element count: `8 + 8·spend_count + 9·output_count` Goldilocks field elements. Verifier rejects proofs whose public-input vector has a different length or encoding.

   **Byte-level encoding** (each element serialized as **8 bytes little-endian u64**, matching Plonky3 `Goldilocks::from_canonical_u64` / `Goldilocks::from_wrapped_u64` canonical form):

   ```
   encode_u8 (x)            → 1 fe = x as u64;            byte form: 8 B LE
   encode_u16(x)            → 1 fe = x as u64;            byte form: 8 B LE
   encode_u32(x)            → 1 fe = x as u64;            byte form: 8 B LE
   encode_u64(x)            → 1 fe = x; assert x < p_G;   byte form: 8 B LE
   encode_256(bytes[32])    → 4 fes, reading 32-byte input as four u64 chunks
                              in little-endian order, each reduced mod p_G:
       fe[0] = u64::from_le_bytes(bytes[0..8])   mod p_G
       fe[1] = u64::from_le_bytes(bytes[8..16])  mod p_G
       fe[2] = u64::from_le_bytes(bytes[16..24]) mod p_G
       fe[3] = u64::from_le_bytes(bytes[24..32]) mod p_G
                              byte form: 32 B (unchanged byte order, canonical
                              form after mod p_G reduction)
   ```

   **Total byte length** of the serialized public-input vector: `64 + 64·spend_count + 72·output_count` bytes.

   **Why `mod p_G` reduction**: `p_Goldilocks = 2⁶⁴ − 2³² + 1`; a uniformly random u64 chunk has probability `(2⁶⁴ − p_G) / 2⁶⁴ = 2⁻³²` of exceeding the field. For every 256-bit input (all are Poseidon2 / Schnorr / hybrid-KEM outputs — uniformly pseudo-random by construction), the aggregate bias across four chunks is ≈ 2⁻³⁰, negligible for soundness analysis. Adversary-controlled inputs (`scheme_id`, `chain_id`, `expiry_block`, `fee`, `filter_tag`) are asserted to fit without reduction at admission.

   **Cross-implementation parity is enforced by golden fixture**. P.1 (§13) produces `uno/test/golden/public-inputs-v1.hex`: a set of `(Transfer bytes, PublicInputs bytes)` pairs computed by A4's Rust encoder and re-verified by A5's C++ encoder on every CI run. Any byte-level drift is a breaking change to `scheme_id = 0x01` and triggers a `scheme_id` bump.
5. **Apply state transition** (only after steps 1–4 all pass):
   - For each output in declared order: `state.commitment_tree.append(output.cm)`; `state.next_position += 1`; record `output.filter_tag` into this block's filter accumulator (for `uno_getBlockFilter`, §9.1).
   - For each spend in declared order: `state.nullifier_set.insert(spend.nf)`; update the nullifier LRU.
   - `state.stats.burned_fees += fee`; `state.stats.tx_count += 1`; `state.stats.note_count += output_count`.

**Verify-before-mutate is a hard invariant**: any failure in steps 1–5 produces zero state delta. There is no rollback path, so there is never a partial state.

No randomness, no wall-clock, no HashMap iteration, no floats anywhere in the verify path.

### 4.3a Mempool admission (non-consensus pre-filter)

To prevent DoS from obviously-invalid txs, the JSON-RPC admission path runs a **cheaper** subset of checks before queuing a tx into the mempool:

1. §4.3 step 1 (all cheap syntax checks).
2. Nullifier LRU check only (do NOT touch the cell-dict — that is a tx-per-block cost; the LRU hit is sufficient to reject obvious replays).
3. `spend_auth_sig` verification (cheap: N × ~1 ms).
4. Binding sig verification (cheap: ~1 ms).
5. **Does NOT** run the Plonky3 proof verify — that is the expensive step, deferred to the compute phase where at least the block producer is paid to pay for it.

Txs that pass 1–4 are queued for inclusion; the compute phase runs the full §4.3 sequence including Plonky3 verify. A tx that passes admission but fails compute (e.g. an invalid proof that nevertheless carried valid signatures) is recorded as `TxRejected` in the block and **costs the mempool its admission slot** — but, since v1 has no way to charge fees for rejected txs (the fee is claimed only on inclusion), such an adversarial tx gives the attacker a free proof-verify consumption. Mitigations:
- **Admission rate-limit per IP** (validator-configurable, not consensus): bounds attacker's effective rate.
- **Proof-verify is the only costly operation** and it runs in the compute phase's parallel pool (§13 P.3), so one bad proof does not block a block's progress; it only wastes one verifier slot.

A future extension (v2 candidate) may require an `admission_stake` — a small amount pre-committed to the mempool and slashed on rejection — but this is out of scope for v1.

This separation bounds the mempool's DoS surface to the cheap checks and keeps the collator's expensive budget on actually-includable txs.

### 4.4 What the format deliberately hides

| Attribute | Method |
|---|---|
| Amount | Encrypted in note; commitment is hash. |
| Sender identity | `rk` is a one-time key. No link to `ak`. |
| Receiver identity | `epk` is a fresh ephemeral; `cm` is a hash. No link to `pk_d`. |
| Which prior note is spent | Only `nf` is revealed; anonymity set = all live commitments. |
| Balance composition | No per-note values; `Σ spend.value = Σ output.value + fee` enforced by in-circuit AIR constraint (§3.3, §4.2 claim 8). |
| Tx graph | No input references; Merkle membership is inside the ZK proof. |

What remains public: fee, anchor, expiry, tx size (hence spend/output counts up to the max of 4/4 — a fixed envelope). We do **not** pad to fixed 4/4 in v1; cost vs privacy trade-off deferred to v2.

---

## 5. State Model and TOS Cell Integration

This is the load-bearing section. Every property of our state model that diverges from the Orchard-style primitives' typical deployment flows from the fact that our chain is a TOS workchain and must fit inside TOS's cell-native state and AccountBlock invariant.

### 5.1 UnoShardState

```
UnoShardState :=
  version                : uint8                          // schema version of this cell
  scheme_id              : uint8                          // which crypto suite is active
  next_position          : uint64                         // index of next tree append
  config_hash            : bits256                        // BLAKE3 over live wc=2 config params; sanity
  commitment_tree_root   : bits256                        // current Poseidon2 root
  ^commitment_tree_cell  : Cell                           // ref 1 → frontier (linked chain of 32 hashes)
  ^nullifier_set_cell    : Cell                           // ref 2 → HashmapE(256, True)
  ^meta_cell             : Cell                           // ref 3 → { anchor_window, stats } combined
                                                          // ref 4 = RESERVED for v1.1 / Phase 1 extensions
```

**MetaCell** (one ref deeper) packs anchor window + stats together so the root cell keeps one ref free:

```
MetaCell :=
  ^anchor_window : Cell         // ring buffer of last 100 tree roots
  ^stats         : Cell         // StatsCell (burned_fees, tx_count, note_count)
```

**Cell-layout budget**:
- Inline bits: `8 + 8 + 64 + 256 + 256 = 592 bits` ≤ 1023.
- Refs: **3 used, 1 reserved** ≤ 4. The reserved slot lets v1.1 extensions (PQ config, asset registry for v2, selective-disclosure root) add a ref without a cell-schema migration.
- Fits in a single root cell.

### 5.2 Note commitment tree: frontier storage

Stored as a linked chain of 32 **FrontierLevel** cells. Each level holds:
- The sibling hash needed to recompute the root when the next leaf is appended.
- A flag indicating whether the sibling is an "empty" (canonical empty-subtree hash) or a real hash.

Append is O(log N) hash ops + one cell-write per changed level. The root is recomputed on every append and stored in `commitment_tree_root` for fast verification against `anchor`.

Full history (all committed notes) is NOT persisted on-chain. Clients that want to re-derive the tree or produce inclusion proofs for historical notes do so from the ordered tx log — this is the standard practice for frontier-only storage.

**No chain-side `cm → pos` index is needed.** The wallet tracks the position of each note it owns at receive-scan time (the block containing the output tells the wallet the leaf index). At spend time, the wallet feeds `(cm, pos, merkle_path)` as private witnesses to the ZK circuit; the circuit attests (§4.2 claims 1 and 4) that the same `pos` is used for both the membership proof and the nullifier derivation, so the chain does not re-verify `pos` explicitly.

### 5.3 Nullifier set

A TOS `vm::Dictionary` with 256-bit keys and a unit value. Cell-friendly, O(log N) lookup, O(log N) insert. At 10M spends, on-disk size roughly 500 MB (dict node overhead dominates). Scales linearly; pruning is not possible (nullifiers are forever).

**Implementation requirement (M2) — nullifier LRU cache**: the validator maintains an in-memory LRU of recently-inserted nullifiers, default capacity **1 M entries (~100 MB RAM)**, tunable via ConfigParam 84. Cold-cache dictionary lookups on a 10 M-entry set traverse ~24 cell levels and can exceed the per-tx block-time budget under a 1 s cadence; the LRU makes insert-and-immediately-check paths hot.

The LRU is **advisory, not consensus**. The on-cell dictionary remains the authoritative source of truth. A negative answer from the LRU (miss) MUST be followed by a dictionary lookup before declaring the nullifier unseen. A positive answer (hit) is sufficient to reject a double-spend without touching the dictionary. State-root hashing only ever reflects the dictionary.

### 5.4 Anchor window

Ring buffer of the last 100 block roots, stored as a single cell chain (~3.2 KB). At end of block the current `commitment_tree_root` is pushed; oldest is evicted. The spend's `anchor` field must equal one of the 100 stored roots.

**Why 100**: typical wallet latency between fetching an anchor and submitting a tx is < 10 s; 100 blocks (≈ 100 s at 1 s block time) absorbs most mempool lag without enlarging state.

### 5.5 Stats

```
StatsCell :=
  burned_fees : uint64
  tx_count    : uint64
  note_count  : uint64
```

Plain ints, stored in one inline cell. Not consensus-critical; exposed via RPC for audit / observability.

### 5.6 Single-executor account

All `Transfer` txs are addressed to one fixed executor account on wc=2:
- Address: `(workchain = 2, account_id = 0x0000…0001)`.
- Fixed at genesis; not user-reachable; outer balance permanently zero.
- Executor's `StateInit.data` cell **is** the root of the serialized `UnoShardState`.

This preserves the TOS `AccountBlock` invariant (one AccountBlock per account per block) — every `Transfer` is a delta on the same executor account.

**Crucially, there are no other accounts on wc=2.** Users exist only as off-chain keypairs; the chain tracks their notes (commitments in the tree) and spends (nullifiers in the set) — never the users themselves. This eliminates several problems that the previous account-based design struggled with:

- **Dust-creation attacks** (adversary bloats state with empty accounts): impossible; no accounts exist.
- **Storage rent on ciphertexts**: no ciphertext balances exist; only hash commitments.
- **Per-receiver auto-creation semantics**: none needed; any address can receive immediately (commitment is just a new leaf).
- **Account scheme mismatch checks**: nothing to mismatch; all state is canonical hashes.

### 5.7 Block execution flow

```
BEGIN block N:
  load UnoShardState from executor.StateInit.data
  snapshot_root = state.commitment_tree_root

FOR each Transfer tx in block-order (from mempool):
  result = verify_transfer(tx, state)   // §4.3 steps 1–5; NO mutation
  IF result == Ok:
    apply_transfer(tx, state)           // §4.3 step 6
    emit TxIncluded(tx_hash, block=N)
  ELSE:
    emit TxRejected(tx_hash, code=result.err)

END block N:
  state.anchor_window.push(state.commitment_tree_root)
  serialize UnoShardState → executor.StateInit.data
  // TOS block-commit path writes the cell tree atomically via WriteBatch
```

**Verify-before-mutate discipline**: `verify_transfer` reads state immutably and returns a decision. `apply_transfer` only runs on Ok. There is no partial state because there is no partial-apply path. A block with 100 txs of which 5 fail produces deltas from exactly the 95 that passed.

### 5.8 Wallet sync

Wallets hold `fvk` or `ivk` + `sk_mlkem`. They sync by fetching per-block compact filters (§2.8, §9.1 `uno_getBlockFilter`), evaluating filter membership for their wallet, and trial-decrypting only on filter hits.

Trial-decrypt cost per filter-hit output ≈ **1.1 ms** (one Ristretto255 scalar multiplication for `s_dh = ivk · epk` ~1 ms + ML-KEM-768 decapsulation ~80 μs + hybrid KDF ~5 μs + ChaCha20-Poly1305 AEAD open ~10 μs).

Concrete sync budget (with compact filters, the v1 default):
- **Sustained load** (30 TPS × 2 outputs/tx, 16-bit filter tag, 2⁻¹⁶ FP rate): ~5.2 M outputs/day filtered down to ~80 false-positives + real hits for an active wallet. Total daily trial-decrypt work: **seconds**, not minutes.
- **Burst load** (50 TPS × 2 outputs/tx): similar budget, trivial work on any device.
- **Filter download bandwidth**: ~5 MB/day at 30 TPS under GCS encoding.

Mobile-viable without further optimization.

Three scan modes, ordered from v1 default to opt-in escape hatch:

- **Compact-filter scan** (v1 default): wallet fetches per-block GCS filter (§2.8, §9.1), rejects ~99.99% of outputs before any AEAD work. Residual trial-decrypt cost: tens of outputs per day for an active wallet, seconds of CPU. Mobile-viable.
- **Parallel scan** (v1, trivial): wallet uses all local cores; irrelevant once compact filters are in.
- **Server-assisted scan** (v1, opt-in, privacy-weakening): wallet sends `ivk` and/or `sk_mlkem` to a trusted server; server trial-decrypts and returns matches. Server learns which notes belong to this wallet. User-chosen, never default, explicit warning in wallet UI.

No per-wallet on-chain state is ever created. The chain has no idea who the wallets are.

### 5.9 Throughput budget

TOS simplex consensus runs a global block rate (ConfigParam 30); per-workchain block intervals are not configurable in v1. Given the current 1 s block setting and the per-tx verify cost of Plonky3 over Goldilocks, the per-block serial budget breaks down:

| Stage | Typical |
|---|---|
| Consensus overhead (catchain rounds, proposal, propagation) | 400–500 ms |
| Block commit WriteBatch | 25–55 ms (slightly higher than Halo2 era due to larger proof cell chains) |
| Mempool drain + signature routing | 20 ms |
| End-of-block compact filter compilation (§2.8) | 1–2 ms |
| **Remaining for compute phase** | **~400–500 ms** |

Per-tx compute cost in the compute phase (Plonky3 / Goldilocks under `scheme_id = 0x01`, with the pinned FRI parameters from §2.1):

| Component | Time |
|---|---|
| Cheap checks (anchor, dedup, Ristretto decompression) | 2 ms |
| Nullifier existence check (LRU-hit path) | < 1 ms |
| `spend_auth_sig × N` Schnorr-on-Ristretto verify | ~2 ms per spend |
| **Plonky3 proof verify** (`num_queries=128`; FRI Merkle paths + PoW check) | **7–20 ms** |
| State mutation (tree append + nullifier insert + filter accumulation + cell writes) | 6–9 ms |
| **Total per tx, single-threaded, 1-spend/2-output** | **~25 ms** |

**Serial TPS ceiling: 400 / 25 ≈ 16 TPS.** With parallel Plonky3 verify across `num_cores` workers (§13 P.3, **activation prerequisite**), the ceiling rises to **~50 TPS burst / 30 TPS sustained** on 4-core validator hardware, matching the design target (§1.4).

This ceiling is **by design**. The trade-off: every user gets terminal privacy + PQ-native proving, validators run on commodity hardware, the chain does not market throughput. If sustained demand exceeds the ceiling, the response is proof aggregation (v2) — not block-rate adjustment and not weakening of privacy properties.

**Note on bandwidth**: Plonky3 proofs under the pinned FRI parameters are ~5× larger than Halo2 proofs (~52 KB typical vs ~10 KB). At 30 TPS × 52 KB × 100 validators = ~160 MB/s of inter-validator bandwidth during consensus — datacenter-feasible, tight on residential links. This is the principal cost of choosing Plonky3 over Halo2 with 128-bit conjectured soundness, accepted as the price of PQ-native proving with payment-chain-grade security.

---

## 6. Post-Quantum Posture and Migration Path

v1 is **PQ-native by design** (§0.2). This section documents what is already closed at v1 ship, what narrow surface remains, and how the `scheme_id` mechanism handles the one remaining upgrade.

### 6.1 PQ status at v1 ship

Per-layer quantum exposure of `scheme_id = 0x01`:

| Layer | v1 primitive | Quantum impact | HNDL footprint | v1 status |
|---|---|---|---|---|
| Note commitments | Poseidon2 over Goldilocks | Grover halves; 128-bit margin with ≥256-bit output | None | **PQ-native** |
| Nullifiers | Poseidon2 | Grover halves | None | **PQ-native** |
| Merkle tree nodes | Poseidon2 | Grover halves | None | **PQ-native** |
| Anchor roots | Poseidon2 | Grover halves | None | **PQ-native** |
| **Proof system** | **Plonky3 / FRI / Goldilocks** | **Hash-based; no Shor-breakable primitive** | None | **PQ-native** — no Phase 2 proof-system migration |
| In-circuit balance / range | Goldilocks field arithmetic | None | None | **PQ-native** |
| Spend-auth sig | Schnorr-on-Ristretto255 | Shor breaks Ristretto DL | None (one-time sig; HNDL not useful) | Classical; Phase 1 upgrade to ML-DSA hybrid |
| Note encryption (KEM) | **Ristretto255 ECDH ⊕ ML-KEM-768 hybrid** | Shor breaks Ristretto; ML-KEM-768 assumed secure | **Closed by hybrid** — both must fall to decrypt | **PQ-native in v1** |

**Two observations driving this design:**

1. **The chain stores only hashes, proofs, and ciphertexts**. There are no on-chain secrets, balances, or identity artifacts that leak historical information post-quantum. The HNDL surface is the ciphertext set (`enc_ciphertext` + `mlkem_ct`), and the hybrid KEM closes it at v1 ship.
2. **Spend-auth signatures are not HNDL-vulnerable**. A captured Schnorr signature today reveals nothing useful to a future CRQC — it certifies a one-time spend that has already happened. Phase 1 migrates the spend-auth layer to PQ defensively, not urgently.

Compared to the status of the Halo2/Pallas-based Zcash Orchard deployment (2026-04):

| | Zcash Orchard | UNO v1 |
|---|---|---|
| Proof-system PQ | ✗ (Pallas DL; Phase 2 migration needed) | ✓ (Plonky3 STARK) |
| Note-encryption PQ | ✗ (ZIP #1133 proposal, not shipped) | ✓ (ML-KEM-768 hybrid from day one) |
| Spend-auth PQ | ✗ (Schnorr-on-Pallas) | ~ (classical at ship; Phase 1 hybrid upgrade) |
| Commitments / nullifiers PQ | ✓ (Poseidon2, hash-based) | ✓ (Poseidon2, hash-based) |

UNO v1 closes two of the three PQ surfaces that Zcash still carries as migration debt.

### 6.2 Phased roadmap

Capability-gated (availability of production PQ libraries and audits), not date-gated. All phases are **intra-wc=2** cryptosuite migrations; no cross-chain bridges are ever introduced (§1.5).

#### Phase 0 — v1 (now, `scheme_id = 0x01`)

The PQ baseline described in §6.1. Shipped PQ primitives:
- Plonky3 STARK / Goldilocks proof system.
- Poseidon2-over-Goldilocks for all in-circuit hashes.
- ML-KEM-768 hybrid note encryption.

Classical primitives retained (with reasoning):
- Schnorr-on-Ristretto255 for spend-auth — not HNDL-vulnerable, Phase 1 upgrade path is clean.
- Ristretto255 ECDH for the classical half of hybrid KEM — combined with ML-KEM, eliminates HNDL exposure.

#### Phase 1 — `scheme_id = 0x02` hybrid spend authorization

**Trigger**: production-grade ML-DSA-65 (Dilithium3) C/C++ library with constant-time verify, ≥1 round of external cryptographic audit, and credible ≤10-year CRQC forecast.

- Spend-auth signature = Schnorr-on-Ristretto255 **AND** ML-DSA-65. Both verify on every spend.
- Requires extending `SpendDescription` to carry a second pubkey and a second signature (≈ 3.3 KB per spend).
- Note encryption, proof system, commitment/nullifier primitives all **unchanged** — only the spend-auth layer gains a PQ co-signature.
- Tx size grows by ~13 KB for a 4-spend worst case; within TOS cell-tree capacity.
- No note-migration is required; `scheme_id = 0x01` Transfers remain valid.

#### Phase 2 — additional PQ hardening (optional, trigger-gated)

Items that may become relevant if the cryptographic landscape shifts (e.g., a flaw is discovered in ML-KEM-768 variant Round-3, or Ristretto255 becomes the weakest link):

- Upgrade ML-KEM-768 → ML-KEM-1024 for stronger PQ margin.
- Add a hash-based signature scheme (SLH-DSA / SPHINCS+) as a third layer in the spend-auth hybrid.
- Swap Ristretto255 to an FROM-lattice PQ KEM that fits in the hybrid framework.

None of these are currently planned; they are `scheme_id = 0x03+` slots reserved for triggered response to cryptanalytic developments.

#### Phase 3 — Tachyon-compatible architecture (capability-gated, v3+)

**Trigger**: Zcash's Ragu PCD crate reaches production-grade audit + stable oblivious-sync protocol (PIR or OPRF-based) is academically settled + independent engineering resources available.

- Move `enc_ciphertext` + `mlkem_ct` **off-chain** to sync-server infrastructure (§14).
- On-chain shrinks to commitments, nullifiers, Plonky3 PCD recursion proof.
- Wallet sync switches from "download all outputs + trial-decrypt via filter" to oblivious queries against sync servers.
- HNDL surface on ciphertexts closes *structurally* — no on-chain target to harvest.
- `scheme_id` bumped accordingly.

As of 2026-04, Zcash Ragu is still under construction and audit; Tachyon is not on any testnet. UNO v1 is designed to **not preclude** this migration (§5.7 state schema, §9 RPC abstraction), but does not commit to delivering it.

#### Phase 4 — freeze legacy schemes (reactive)

**Trigger**: credible imminent CRQC (≤ 2 yr) or discovered HNDL compromise.

- Chain rejects new Transfer with superseded `scheme_id`.
- Historical state remains queryable; unmigrated notes become permanently unspendable (owners are expected to have migrated through Phase 1/2 upgrades by this point).

### 6.3 Invariants v1 locks in for the migration path

1. Every on-chain artifact carries `scheme_id`. A validator reading a `scheme_id = 0x01` Transfer under a Phase 1 configuration knows instantly which verifier to route to.
2. Fiat-Shamir transcripts absorb `"scheme-id" || u8` as their first variable field (§2.0). No cross-scheme proof replay is possible even under byte-level wire-format collisions.
3. Verifier dispatch is keyed `(workchain_id, scheme_id) → handler`. Unknown `scheme_id` is a deterministic reject, never a silent fallthrough.
4. **Hash-based backbone is already in place**: commitments, nullifiers, Merkle nodes, and the proof system are all hash-based in v1. No Phase 2 rehash / retreefication needed.
5. **Wire format accommodates growth**: `scheme_id = 0x02` adds ~3.3 KB per spend; the TOS external-message envelope supports this without hardcap changes.
6. **Note continuity**: `cm` content is `Poseidon2(...)` over Goldilocks — the same hash primitive survives every phase. There is no Phase 2 "forced note migration" event; all Phase upgrades are backwards-compatible additions, not full-pool re-commitments.

The `priv_migrate` intra-wc=2 tx type described in earlier drafts is **not required** under the Plonky3-native design — it was a Halo2→STARK migration artifact that no longer applies. The doc earlier mentioned it; that mention has been retracted. If a future Phase (e.g., Phase 3 Tachyon) does require re-committing notes, the mechanism will be designed at that time, intra-wc=2, preserving §1.5's bridgeless invariant.

---

## 7. Prove–Verify–Scan Lifecycle

A `Transfer` transaction moves through four structurally distinct phases with different actors, different performance budgets, and different security constraints. This section is the authoritative description of that lifecycle; anywhere else in the doc that mentions "prove time," "verify time," or "scan cost" should be read against this section. The single-sentence summary:

> **Prove** happens once, on the sender's device. **Verify** happens once per transaction on every validator, and once more on every future replaying node. **Scan** happens on the receiver's device and is independent of consensus.

Conflating these three into "performance" is the single most common source of design-review confusion on shielded chains. They are three independent cost axes with different scaling behavior. The rest of this section makes that split explicit.

### 7.1 Timeline overview

```
T0  user taps "Send" in wallet
 │
 ├─── Phase 1: PROVE — sender's device only ────────────────────────
 │    • select notes, compute nf, build outputs, ML-KEM encap, AEAD
 │    • construct witness (private inputs never leave the device)
 │    • run Plonky3 STARK prover                       ← 10–30 s
 │    • sign spend_auth_sig (Schnorr-on-Ristretto255)
 │    • serialize Transfer, submit over JSON-RPC
 │
 ├─── Phase 2: ADMISSION — any full node (non-consensus) ───────────
 │    • §4.3a cheap subset: syntax, anchor, LRU, sigs
 │    • §4.3 step 4 (Plonky3 verify) is DELIBERATELY SKIPPED
 │    • accept → mempool; reject → silent drop or JSON-RPC error
 │
 ├─── Phase 3: VERIFY — every validator in catchain ────────────────
 │    • block producer runs the full §4.3 sequence INCLUDING proof
 │    • every peer validator re-runs §4.3 during block validation
 │    • every future replaying node runs §4.3 again from genesis
 │    • state mutation only after all verify steps pass
 │
 └─── Phase 4: SCAN — receiver's wallet (post-inclusion) ───────────
      • fetch compact block filter for each new block
      • reject ~99.99% of outputs via filter_tag mismatch
      • for each filter hit: trial-decrypt hybrid KEM + AEAD
      • recover (d, pk_d, value, rseed) for each owned note
```

### 7.2 Phase 1 — Prove (sender-side, once per tx)

**Actor**: the user's wallet software running on their own device — laptop, desktop, phone, or a paired hardware device.
**When**: between "user taps Send" and "tx hits any RPC endpoint."
**What**: build the witness, run the Plonky3 STARK prover, produce one proof.

Client-side proving is a structural invariant, not an optimization choice. The prover must know, simultaneously:

- `ask`, `nk` — long-term spend authority and nullifier key
- `rseed`, `value`, `pk_d`, `d` — full plaintext of each spent note
- Merkle path opening each spent `cm` against the declared `anchor`
- `esk`, new note plaintexts for each output

Any party holding this witness can reconstruct amounts, sender identity, receiver addresses, and the entire transaction graph. The privacy claim of the chain (§1.1) requires that the witness never leaves the sender's trust boundary. The v1 chain therefore does not offer a server-side prover, and the opt-in `uno_prove_delegated` RPC (§9.2) is a privacy-weakening escape hatch that wallets must surface with an explicit warning — it is not a default path.

Concrete cost on a 2020-era laptop (M1 or 8-core x86) for a 1-spend / 2-output Transfer under `scheme_id = 0x01`:

| Step | Work | Time |
|---|---|---|
| Witness construction | select notes, compute `nf`, build outputs, ML-KEM encap, AEAD encrypt | ~10 ms |
| Plonky3 STARK proving (`log_blowup=2, num_queries=128`; FRI + Poseidon2-Goldilocks) | the dominant cost | **15–40 s** |
| Schnorr-on-Ristretto255 signatures | `spend_auth_sig × N` | ~3 ms |
| Serialize + JSON-RPC submit | TLB codec + HTTP | ~20 ms |

Scaling to other hardware (Plonky3 proving is slower than Halo2 by ~4–6× at our pinned security level, but benefits more from multi-core parallelism):

| Device class | 1-spend/2-output | 4-spend/4-output |
|---|---|---|
| Server / workstation | 3–7 s | 12–22 s |
| Modern laptop (M2/M3, 8-core x86) | 15–22 s | 45–75 s |
| Flagship phone (iPhone 15 Pro, Pixel 8 Pro) | 45–90 s | likely fails / OOM |
| Mid-range phone (Pixel 6a, mid-tier Snapdragon) | 90–180 s | OOM |
| Low-end phone (4 GB RAM) | OOM | OOM |

**Implication for product design**: prove latency on Plonky3 with payment-chain-grade FRI parameters is higher than on Halo2 — the trade we accepted for PQ-native + 128-bit-conjectured soundness. Mobile flagship can handle simple txs but 4/4 max txs are out of reach even on flagship. Wallets should:
- surface proving as an explicit "generating proof…" step with progress indication;
- encourage laptop / desktop proving for non-trivial transactions;
- degrade gracefully on low-memory devices (e.g., limit to 1-spend / 2-output on phones with ≤ 4 GB RAM).

§1.4 targets ≤ 22 s laptop proving for 1-spend/2-output under pinned parameters; no committed phone target. If prove UX becomes critical, the v2+ path is delegated proving with blinded witnesses (research-grade) or Tachyon-style PCD which compresses prove into smaller recursive steps.

### 7.3 Phase 2 — Admission (non-consensus, cheap pre-filter)

**Actor**: any full node accepting transactions via JSON-RPC or peer gossip.
**When**: immediately on receipt, before the tx is queued for block inclusion.
**What**: run the subset of §4.3 that does not include Plonky3 proof verify.

The Plonky3 verify is **deliberately excluded** at admission (§4.3a). Including it would amplify DoS: an adversary submitting syntactically valid but proof-invalid transactions to many mempool nodes would force every one of them to burn 5–15 ms of verify budget per malicious tx, without paying the admission-refunded fee (v1 fees are only collected on inclusion, not rejection). Admission runs only checks whose total cost is bounded and whose failure is common enough to be worth filtering at the edge:

| Check | Cost |
|---|---|
| Syntax (version, `scheme_id`, chain_id, counts, fee floor) | < 1 ms |
| Anchor present in 100-block window | < 1 ms |
| Nullifier LRU: hit → reject; miss → accept (no dict walk) | < 1 ms |
| `spend_auth_sig × N` Schnorr-on-Ristretto verify | ~2 ms per spend |

Typical admission cost for a 1-spend tx: ~3 ms. An adversary can force bounded waste by submitting txs with valid signatures but invalid proofs — the cost per such tx is capped at admission-subset, and the victim is the mempool's accept-rate limiter, not the block-production budget. Validator-configurable per-IP rate limits (not consensus) bound the adversary's effective rate.

### 7.4 Phase 3 — Verify (every validator, consensus-critical)

**Actor**: every validator participating in wc=2 catchain consensus, plus every full node replaying history.
**When**: once when the block producer assembles a candidate block; once more on every peer validator during catchain validation; once more on every future node bootstrapping from genesis.
**What**: run the complete §4.3 verification sequence, including the Plonky3 proof verify. Every validator must independently reach the same accept/reject decision.

Determinism is a hard requirement (§5.7 verify-before-mutate; §12 P.5 cross-validator replay). Every call path invoked here uses no randomness, no wall-clock, no HashMap iteration, no floats, no uninitialized reads. Cross-validator state-root parity is enforced by golden-fixture tests.

Per-tx cost, single-threaded, 1-spend/2-output under `scheme_id = 0x01` (pinned FRI parameters from §2.1):

| Component | Time |
|---|---|
| Cheap syntax + anchor + dedup + Ristretto decompression | 2 ms |
| Nullifier existence (LRU-hit path) | < 1 ms |
| Nullifier existence (LRU-miss → 24-level dict walk) | ~10 ms |
| `spend_auth_sig × N` Schnorr verify | ~2 ms/spend |
| **Plonky3 proof verify (128 FRI queries + PoW check + Merkle paths)** | **7–20 ms** |
| State mutation (tree append × outputs, nf dict insert × spends, filter accumulate, stats) | 6–9 ms |
| **Total (LRU-hit case)** | **~25 ms** |

At target throughput 30 TPS, single-threaded verify consumes 30 × 25 ms = **750 ms** of compute per block — exceeding the ~400–500 ms compute-phase budget (§5.9). Parallel Plonky3 verify across `num_cores` workers (§13 P.3, **activation prerequisite**) cuts effective per-tx time to ~7 ms on 4-core hardware; 30 TPS then consumes ~210 ms, which fits. Parallel verify is not a later optimization — it is a precondition for the chain producing blocks at target TPS, and the release gate is accordingly a hard activation gate.

**Verify bandwidth**: each proof is produced once but consumed many times. For a network of `V` validators, every tx's proof crosses the validator-to-validator catchain links `V − 1` times during consensus, plus once per future replaying node. At `V = 100`, 30 TPS, ~52 KB Plonky3 proofs (payment-chain FRI params), per-validator aggregate inbound proof bandwidth is ~160 MB/s — datacenter-feasible, tight on residential links. This is the principal cost of 128-bit conjectured soundness under Plonky3 and is accepted as the price of PQ-native proving with payment-grade security. See §7.6 for the axis analysis.

### 7.5 Phase 4 — Scan (receiver-side, post-inclusion)

**Actor**: the receiver's wallet.
**When**: any time after the block is finalized; typically on wallet foreground or background sync.
**What**: identify outputs belonging to this wallet, and decrypt them.

**Scanning is not verifying.** The wallet trusts consensus — every output it inspects has already passed Phase 3 on every validator. The wallet does not re-run the Plonky3 proof. Its job is detection and decryption.

Per-block scan flow:

1. Fetch the compact block filter via `uno_getBlockFilter(seqno)` (§9.1). One filter per block, GCS-encoded, ~KB.
2. For each bucket in the filter, compute the expected `filter_tag` for this wallet's `ivk` + `sk_mlkem`. Reject the ~99.9985% of outputs that do not match. A 16-bit tag with `N` outputs per block gives false-positive rate `2⁻¹⁶`; wallet does ~`N/65536` trial-decrypts per block in expectation plus real hits.
3. For each filter hit, fetch the full `OutputDescription` + `mlkem_ct` (if not already cached via full block fetch) and trial-decrypt:
   - `s_dh = ivk · epk` (Ristretto255 scalar mul) ~1 ms
   - `k_pq = ML-KEM-768.Decap(sk_mlkem, mlkem_ct)` ~80 μs
   - `k_aead = BLAKE3(hybrid-KEM transcript)` ~5 μs
   - AEAD open with tag check; failure rejects cheaply
4. Successful open recovers `(d, pk_d, value, rseed)` — the full note plaintext.

Cost on a single commodity core:

- Filter eval per block: ~1 μs
- Trial-decrypt per filter hit: ~1.1 ms
- Real hits per day for an active wallet: tens
- Daily CPU cost: seconds, not minutes

Without compact filters (unfiltered scan path), cost at 30 TPS is ~24 min/day of trial-decrypt — tolerable on desktop, unusable on mobile. Compact filters are therefore a v1 activation requirement for mobile-first privacy UX, not a later optimization. See §5.8 for wallet-sync budget detail and §9.1 for the RPC surface.

**Audit vs scan**: the scan path uses `ivk` (detection + decryption of incoming notes). The audit path uses `fvk` (full viewing key), which includes `ovk` and a derived `sk_mlkem` so that the auditor can also decrypt historical outgoing notes. Both paths are consensus-independent and happen post-inclusion.

### 7.6 Cost model summary

| Phase | Actor | Frequency per tx | Time budget | Binding constraint |
|---|---|---|---|---|
| Prove | Sender device | 1 | 15–40 s laptop (UX) | Plonky3 FRI (`num_queries=128`) + Poseidon2 on user hardware |
| Admission | Any full node | 1 × (nodes that see it) | ~3 ms (DoS-bounded) | Schnorr-on-Ristretto verify |
| Verify | Each validator + replay nodes | `V` + replay count | ~25 ms serial, ~7 ms parallel | Plonky3 verify; parallel-verify gate |
| Scan | Receiver wallet | 1 per owned output | ~1.1 ms per filter hit | AEAD + ML-KEM decap (both negligible) |

**Three independent cost axes — do not collapse them**:

1. **Prove time** — a one-off UX cost borne on the sender's device. Scales with the sender's hardware, not with network size. Slow prove on mobile is an inherent property of shielded L1 and is orthogonal to verify budget. Optimizations here (GPU proving, Plonky3 tuning, delegated proving research) help UX but not consensus throughput.
2. **Verify time** — a recurring consensus cost borne by every validator. Scales with validator count. Sets the block-throughput ceiling. Parallel verify (§13 P.3) is the only within-v1 lever; proof aggregation (v2+) and Tachyon-style PCD compression (Phase 3) are the out-of-v1 levers.
3. **Proof bandwidth** — an inter-validator cost borne `V − 1` times per tx during catchain propagation, plus once per replay. Scales with proof size (~52 KB Plonky3 typical under pinned FRI params). The PQ-native-with-payment-grade-security trade: Plonky3 proofs at 128-bit conjectured soundness are ~5× larger than Halo2 would have produced; we accepted this cost in exchange for no Phase 2 migration debt and stronger soundness margin.

An optimization that improves one axis at the expense of another is a real trade-off and must be evaluated against which axis is the currently binding constraint, not against an aggregate "performance" metric. Example: choosing Plonky3 over Halo2 costs prove time (~4–6× slower) and proof bandwidth (~5× larger), but it delivers native PQ and removes the Phase 2 migration debt (§6). Likewise, choosing `num_queries=128` over Plonky3's `num_queries=84` default costs ~40% prove time and ~30% proof size, but adds ~28 bits of soundness margin — a rational trade for a native-value L1.

### 7.7 File-by-file trace of `uno_sendTransfer`

The code path that implements Phases 1–3 for one externally submitted `Transfer` routes through these files in this order:

| Step | Phase | File | Purpose |
|---|---|---|---|
| 1 | Phase 1 (client) | wallet codebase (outside this repo) | Build witness, run prover, sign, serialize. |
| 2 | Phase 2 (edge) | `uno/rpc/handlers.cpp::uno_sendTransfer` | Decode hex / JSON, sanity-check. |
| 3 | Phase 2 (edge) | `uno/core/transaction.cpp::decode_transfer()` | Parse wire → `Transfer` struct. |
| 4 | Phase 2 (edge) | same | Admission subset of §4.3 (syntax, anchor, LRU, sigs — no Plonky3 verify). |
| 5 | Phase 2 (edge) | `uno/rpc/handlers.cpp` | Wrap as external message to `(wc=2, executor)`; submit via `liteServer_sendMessage`. |
| 6 | Phase 3 (consensus) | Collator admission | Standard TOS external-message pool intake. |
| 7 | Phase 3 (consensus) | `crypto/block/transaction.cpp` (modified) | On the executor account, invoke `uno_workchain_dispatch::invoke_uno_compute()` via the `case 2:` dispatch branch. Called once per tx in block-order. |
| 8 | Phase 3 (consensus) | `uno/core/compute-phase.cpp::run_compute_phase()` | Per tx: full §4.3 `verify_transfer` → if Ok, `apply_transfer`. Verify-before-mutate. In-memory state mutates; nothing written to cells yet. |
| 9 | Phase 3 (consensus) | End-of-block hook (installed by `uno_workchain::init_uno_workchain`) | After the last tx: `state.anchor_window.push(state.commitment_tree_root)`; compile block's `filter_tag`s into GCS filter for §9.1 serving. Last in-memory mutation of the block. |
| 10 | Phase 3 (consensus) | `uno/core/cell-state.cpp::serialize()` | Serialize the fully-mutated `UnoShardState` into executor `StateInit.data` — one serialization per block, not per tx. |
| 11 | Phase 3 (consensus) | TOS block commit | CellDb `WriteBatch` — atomic across all cells touched this block. |

One serialization per block, one WriteBatch per block. Every `Transfer` contributes to the same final serialization. There is no pending-state concept; the entire block is either persisted or not, atomically.

Phase 4 (scan) runs entirely on the receiver's device after the block is committed and is implemented in wallet code that calls `uno_getBlockFilter`, `uno_getOutputsAtBlock`, and the local AEAD/KEM primitives — no server-side state is consulted beyond the RPC responses.

---

## 8. TOS Core Integration

Follows the EVM workchain's dispatch pattern exactly: a thin dispatcher header in `crypto/block/` + the real implementation as a top-level module (`~/tos/uno/`) that registers its handler at startup. This mirrors how `~/tos/evm/` relates to `crypto/block/evm-workchain-dispatch.{h,cpp}`.

### 8.1 Dispatch header (in `crypto/block/`, part of `tos_crypto`)

`crypto/block/uno-workchain-dispatch.{h,cpp}`:

```cpp
namespace uno_workchain_dispatch {

using UnoComputeHandler = std::function<bool(
    block::ComputePhase& cp,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32])>;

/// Registered once at startup by uno/core/init.cpp.
void set_uno_compute_handler(UnoComputeHandler handler);
bool has_uno_compute_handler() noexcept;
bool invoke_uno_compute(
    block::ComputePhase& cp, vm::CellSlice& body,
    uint64_t gas_limit, uint64_t seqno, uint64_t ts,
    const uint8_t rand_seed[32]);

/// Single-byte cell containing 0x55 ('U'). Used as StateInit.code for the
/// wc=2 executor account, analogous to EVM's 0x45 ('E') marker. Cached singleton.
td::Ref<vm::Cell> get_uno_code_marker_cell();

}  // namespace uno_workchain_dispatch
```

The dispatcher is compiled into `tos_crypto` (alongside `evm-workchain-dispatch.cpp`) so that `crypto/block/transaction.cpp` can route to wc=2 without creating a circular link dependency on `uno_workchain`.

### 8.2 Routing patch

`crypto/block/transaction.cpp::prepare_compute_phase()`:

```cpp
switch (account.workchain) {
  case 1:
    if (evm_workchain_dispatch::has_evm_compute_handler())
      return evm_workchain_dispatch::invoke_evm_compute(cp, body, gas_limit, seqno, ts, rand_seed);
    break;
  case 2:
    if (uno_workchain_dispatch::has_uno_compute_handler())
      return uno_workchain_dispatch::invoke_uno_compute(cp, body, gas_limit, seqno, ts, rand_seed);
    break;
}
// fallthrough to TVM for wc=0
```

Parallel dispatchers with no shared registry. The rule-of-three trigger to unify into a single `map<WorkchainId, ComputeHandler>` is the arrival of a third non-TVM workchain (wc=3).

### 8.3 Initialization

`validator-engine/validator-engine.cpp`, immediately after the existing EVM init:

```cpp
#include "uno/core/init.h"
// ...
evm_workchain::init_evm_workchain(db_root_);
uno_workchain::init_uno_workchain(db_root_);
```

`uno_workchain::init_uno_workchain(db_root)` (in `uno/core/init.cpp`):

1. Calls `uno_workchain_dispatch::set_uno_compute_handler(&run_compute_phase)` to register the real handler with the dispatcher.
2. Loads (or zero-inits from genesis) the wc=2 executor account's `UnoShardState` from CellDb at `db_root`.
3. Installs the end-of-block hook that pushes the current commitment-tree root into the anchor window and compiles the per-block compact filter (§2.8, §9.1).
4. **Pre-loads the Plonky3 verifier state (M3)** into a process-lifetime `static const` structure: verifier-side FRI parameters, Poseidon2 constants, public-input schema, and any precomputed domain data for the Transfer AIR. The verifier configuration is known at compile time; pre-loading avoids per-tx setup overhead and guarantees that verify cost is memory-bandwidth bound, not parse-time bound.
5. Warms the nullifier LRU (M2, §5.3) by scanning the most recent K blocks of nullifier insertions (K tunable, default 1000) into the LRU at startup. This prevents a cold-start performance cliff on the first few blocks after restart.

### 8.4 Gas reporting (no VM)

Uno has no VM. The compute handler populates `ComputePhase` fields deterministically:

- `gas_used = FIXED_VERIFY_COST + per_byte_cost × tx_size_bytes + per_spend_cost × |spends| + per_output_cost × |outputs|`
- `gas_fees = fee` (the plaintext tx fee)
- `vm_steps = 1`
- `exit_code = 0` (ok) or a dedicated Uno reject code
- `success = (verify == Ok)`
- `new_data = serialized updated state root` (the key hash-match field)

`gas_limit` is ignored (no metering needed; verify cost is bounded by tx structure).

### 8.5 No changes to TOS block header or ShardState serialization

wc=2 blocks are structurally normal TOS workchain blocks. All Uno-specific data rides inside the executor account's `StateInit.data`, exactly mirroring the wc=1 pattern.

---

## 9. JSON-RPC Surface

New `uno_*` namespace, served by handlers in `uno/rpc/handlers.cpp` and registered in `validator-engine/json-rpc-server.cpp` alongside `eth_*` methods. The RPC surface lives inside the `uno_workchain` library (like EVM's `rpc/handlers.cpp`), not in `validator-engine/` directly.

### 9.1 v1 methods

| Method | Purpose |
|---|---|
| `uno_chainInfo()` | `{ chain_id, workchain_id=2, head_seqno, executor, active_schemes, anchor_window_size }` |
| `uno_getAnchor()` | Current `commitment_tree_root`; last-100 anchor window. Wallet uses this to pick `anchor` for a tx. |
| `uno_getAnchorAtSeqno(seqno)` | Historical anchor lookup for stale-tx handling. |
| `uno_getCommitmentTreeFrontier()` | Current frontier (~1 KB); wallet needs this to build an output's path. |
| `uno_getNullifierStatus(nf)` | `{ spent: bool, block_seqno?: uint64 }`. |
| `uno_getOutputsAtBlock(seqno, from_index, limit)` | Paginated raw `OutputDescription`s. Wallet scans locally with `ivk`. |
| `uno_getOutputsForIvk(ivk_hex)` | **Server-assisted sync** — opt-in, privacy-weakening. Server trial-decrypts and returns matches. |
| `uno_estimateFee(n_spends, n_outputs)` | Minimum fee in native nano-units. |
| `uno_sendTransfer(hex_blob)` | Submit a signed, proven `Transfer`. Returns tx hash. |
| `uno_getTransactionStatus(tx_hash)` | `pending / included(block_seqno) / rejected(reason)`. |

### 9.2 Explicitly not in v1

- **No server-side prover**. Wallet proves locally; the chain only verifies.
- **No server-side spend builder**. Wallet selects notes, derives nullifiers, produces the proof.
- **No `uno_decrypt` or `uno_getBalance`**. The chain never sees a balance; the wallet computes its own balance by scanning and summing.
- **No `uno_scan(start, end)` over-RPC batch scan**. Server-assisted scan exists only as the `ivk`-supplied variant; even that is discouraged.

### 9.3 RPC consistency

All `uno_*` reads return the last-committed block's state. No mempool-projected reads in v1.

---

## 10. Genesis and Configuration

TOS has not launched. wc=2 is enabled from genesis. No hardfork machinery; the code path is always registered; ConfigParam 12 ships wc=2 in the masterchain zerostate.

### 10.1 Workchain descriptor (ConfigParam 12)

wc=2 entry:
- `vm_version = 0x554E4F31` (`"UNO1"`)
- `vm_mode = 0` (no VM)
- `min_split = 0`, `max_split = 0` (single shard; no sharding in v1 — the commitment tree is global)
- `active = true`, `accept_msgs = true`
- `basic = false`
- `flags = UNO_FLAG` (new bit)

Built by `uno_workchain::build_workchain_descr()`.

### 10.2 Chain config (ConfigParam 84, new)

```
UnoConfig :=
  version             : uint8    = 1
  chain_id            : uint32
  min_fee_nano        : uint64         // baseline fee
  fee_per_byte_nano   : uint64         // per-byte charge
  fee_per_spend_nano  : uint64         // per-spend charge
  fee_per_output_nano : uint64         // per-output charge
  max_spends_per_tx   : uint8    = 4
  max_outputs_per_tx  : uint8    = 4
  anchor_window_size  : uint16   = 100
  tree_depth          : uint8    = 32
  expiry_window_blocks: uint32   = 64     // max blocks between current and expiry_block; 64 gives ~64 s
                                          // forward window at 1 s block rate, comfortable vs 2–5 s proving
```

### 10.3 Zerostate

`uno_workchain::build_zerostate()`:

1. Create executor account `(2, 0x…01)` with `UnoShardState`:
   - Empty frontier (32 canonical empty-subtree hashes).
   - Empty nullifier set.
   - Anchor window seeded with the root of an empty tree (one entry).
   - Stats zeroed.
2. Seed **N genesis notes**: a list of `(address, value)` pairs baked into genesis. Each becomes an output in a synthetic "genesis tx" whose `cm`s are appended in canonical order to the initial tree.
3. Publish `zerostate-genesis-notes.json` alongside the state cell: contains the `(Note plaintext, Address)` pairs so genesis recipients can claim their notes.

**After genesis, note plaintexts are never on-chain.** The publication of genesis plaintexts is an intentional, one-time transparency trade — initial distribution is auditable; no other plaintext value is ever on chain afterwards.

**Zerostate is the sole and permanent source of UNO supply.** No minting, no Shield, no bridge, no validator inflation, no governance-issued emission. UNO supply is set exactly once, at genesis, and is monotonically non-increasing thereafter (fees are burned; see §16 decision #19). This is not a v1 scope decision — it is the invariant that makes bridgelessness possible (§1.5). Any future proposal to introduce a supply-creation path on wc=2 would structurally reopen the deanonymization vectors enumerated in §1.5 and is therefore out of scope for every phase of the roadmap.

### 10.4 Chain id

- Testnet: e.g. `0x554E4F54` (`"UNOT"`).
- Mainnet: TBD by network ops.
- Bound in every tx's transcript (§2.0) → no cross-network replay possible.

---

## 11. Build and Module Layout

### 11.1 Top-level directory: `~/tos/uno/`

Uno follows the same layout convention as the EVM workchain (`~/tos/evm/`):

- The main implementation lives at the top of the repo (`~/tos/uno/`), not inside `crypto/block/`. This keeps the large workchain implementation out of `tos_crypto` and avoids a circular link dependency between `transaction.cpp` (which routes dispatch) and the workchain's compute-phase code.
- A **thin dispatcher header** sits in `crypto/block/uno-workchain-dispatch.{h,cpp}` — exactly mirroring `crypto/block/evm-workchain-dispatch.{h,cpp}`. This header is part of `tos_crypto`; it exposes a registration interface (`set_uno_compute_handler`, `has_uno_compute_handler`, `invoke_uno_compute`, `get_uno_code_marker_cell`) that `crypto/block/transaction.cpp` calls from the `case 2:` branch of `prepare_compute_phase`.
- The workchain module registers its real implementation via the dispatcher at startup, from `uno_workchain::init_uno_workchain(db_root)`.

```
~/tos/uno/
├── CMakeLists.txt              // builds uno_workchain static lib
├── core/                       // state, compute, codec, primitives integration
│   ├── workchain.h             // wc id, chain id constants, sizes, domain-sep strings
│   ├── init.{h,cpp}            // node-startup entry point, calls set_uno_compute_handler
│   ├── transaction.{h,cpp}     // Transfer / SpendDescription / OutputDescription wire codec
│   ├── compute-phase.{h,cpp}   // verify_transfer + apply_transfer (§4.3)
│   ├── state.{h,cpp}           // in-memory UnoShardState struct (§5.1)
│   ├── cell-state.{h,cpp}      // State ↔ cell serializer (§5)
│   ├── cell-codec.{h,cpp}      // raw TLV: Transfer body, note desc encodings
│   ├── commitment-tree.{h,cpp} // incremental Merkle tree over Poseidon2-Goldilocks (§5.2)
│   ├── nullifier-set.{h,cpp}   // vm::Dictionary wrapper + LRU (§5.3)
│   ├── anchor-window.{h,cpp}   // ring buffer (§5.4)
│   ├── block-filter.{h,cpp}    // GCS compact-filter compilation per block (§2.8, §9.1)
│   ├── config-param.{h,cpp}    // ConfigParam 12 + 26 builders
│   └── genesis.{h,cpp}         // build_zerostate, genesis distribution loader (§10.3)
├── crypto/                     // cryptographic primitives (off-circuit + verifier bridge)
│   ├── goldilocks.{h,cpp}      // Goldilocks field arithmetic (C++ SIMD wrappers over Plonky3 FFI)
│   ├── poseidon2.{h,cpp}       // Poseidon2 over Goldilocks (FFI to Plonky3 reference)
│   ├── ristretto255.{h,cpp}    // Ristretto255 curve ops (off-circuit KEM + sig curve)
│   ├── schnorr-ristretto.{h,cpp} // Schnorr-on-Ristretto255 (spend-auth sig)
│   ├── mlkem768.{h,cpp}        // ML-KEM-768 KeyGen / Encap / Decap (FFI)
│   ├── hybrid-kem.{h,cpp}      // Split-KDF combiner (eprint 2025/1444) + AEAD wrapper
│   ├── plonky3-verifier.{h,cpp}// Plonky3 STARK verifier for Transfer AIR (C++ over FFI)
│   ├── stealth-address.{h,cpp} // Diversifier-based address derivation
│   └── note-encryption.{h,cpp} // Hybrid-KEM + ChaCha20-Poly1305 pipeline for enc_ciphertext
├── rpc/                        // JSON-RPC handlers
│   ├── handlers.{h,cpp}        // uno_sendTransfer, uno_getAnchor, uno_getBlockFilter, etc. (§9)
│   ├── filter-service.{h,cpp}  // end-of-block filter serving; paginated output fetch
│   └── subscriptions.{h,cpp}   // optional eth_subscribe-like pub/sub for included txs
├── plonky3-ffi/                // Rust crate: uno_plonky3_ffi
│   ├── Cargo.toml              // depends on plonky3 workspace crates
│   ├── src/
│   │   ├── lib.rs              // C ABI surface
│   │   ├── transfer_air.rs     // hand-written Transfer AIR (§4.2 claims 1–8)
│   │   ├── prover.rs           // reference prover used by tosctl + P.6
│   │   └── verifier.rs         // verifier entrypoint called from crypto/plonky3-verifier.cpp
│   └── cbindgen.toml           // header generation for C++ consumers
└── test/                       // integration tests for uno_workchain
    ├── CMakeLists.txt
    ├── test-transfer.cpp       // end-to-end 1-spend/2-output round-trip
    ├── test-determinism.cpp    // P.5 cross-validator determinism fixtures
    ├── test-filter.cpp         // compact-filter compilation + match correctness
    └── test-restart.cpp        // P.4 restart-survival two-node fixtures
```

Include paths, mirroring EVM's convention: `"uno/core/*.h"`, `"uno/crypto/*.h"`, `"uno/rpc/*.h"` resolved from `${CMAKE_SOURCE_DIR}`.

### 11.2 Thin dispatcher in `crypto/block/`

One file pair, matching the EVM pattern exactly:

```
crypto/block/uno-workchain-dispatch.{h,cpp}
```

Surface (namespace `uno_workchain_dispatch`, matching EVM's `evm_workchain_dispatch`):

```cpp
namespace uno_workchain_dispatch {

using UnoComputeHandler = std::function<bool(
    block::ComputePhase& cp,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32])>;

void set_uno_compute_handler(UnoComputeHandler handler);
bool has_uno_compute_handler() noexcept;
bool invoke_uno_compute(
    block::ComputePhase& cp,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32]);

/// Canonical "Uno activated account" code marker cell.
/// Single-byte cell containing 0x55 ('U'). Used as StateInit.code of the wc=2
/// executor account. Analogous to EVM's 0x45 ('E') marker. Cached singleton.
td::Ref<vm::Cell> get_uno_code_marker_cell();

}  // namespace uno_workchain_dispatch
```

The dispatcher is part of `tos_crypto` (linked by `crypto/block/transaction.cpp`). The real compute handler is registered at startup from `uno/core/init.cpp`, which is part of the `uno_workchain` library linked into `validator-engine`.

### 11.3 External / ported dependencies

- **Plonky3 toolkit** (Rust): the `plonky3` family of crates from Polygon Labs / Succinct — FRI commitments, Poseidon2 over Goldilocks, AIR builder. The validator links `uno_plonky3_ffi` (our Rust crate in `uno/plonky3-ffi/`) via a minimal C ABI. The hand-written Transfer AIR (`transfer_air.rs`) is project-specific; we do not depend on any upstream zkVM crate (SP1, Valida) for the Transfer circuit itself.
- **Ristretto255 / Curve25519**: well-audited C implementation (libsodium's Ristretto primitives or an in-tree port). Off-circuit only.
- **ML-KEM-768**: NIST-standard implementation, candidate libs include Open Quantum Safe `liboqs` or a Rust reference via FFI. Final choice pinned during P.1.
- **ChaCha20-Poly1305 AEAD**: already in `~/avatar`; reuse.
- **BLAKE3 / BLAKE2b**: already in repo; BLAKE3 for cell hashing and `tx_hash`, BLAKE2b for off-circuit seed derivation.

### 11.4 CMake

`~/tos/uno/CMakeLists.txt` (mirrors `~/tos/evm/CMakeLists.txt`):

```cmake
# Uno Workchain — TOS-side adapter for the wc=2 shielded-pool execution domain.
#
# Organised in four source directories:
#   core/          state, compute-phase, transaction codec, genesis
#   crypto/        primitives: Goldilocks, Poseidon2, Ristretto255, ML-KEM,
#                  hybrid-KEM, Plonky3 verifier bridge, note encryption
#   rpc/           uno_* JSON-RPC handlers and filter-service
#   plonky3-ffi/   Rust crate exposing the Plonky3 Transfer AIR verifier
#                  (and reference prover) over C ABI
#
# core/ and rpc/ are symbolically circular (rpc handlers depend on state;
# compute-phase writes events consumed by subscriptions), so they compile
# into one static library `uno_workchain`.

set(UNO_SRC
  # core/
  core/init.cpp
  core/transaction.cpp
  core/compute-phase.cpp
  core/state.cpp
  core/cell-state.cpp
  core/cell-codec.cpp
  core/commitment-tree.cpp
  core/nullifier-set.cpp
  core/anchor-window.cpp
  core/block-filter.cpp
  core/config-param.cpp
  core/genesis.cpp
  # crypto/
  crypto/goldilocks.cpp
  crypto/poseidon2.cpp
  crypto/ristretto255.cpp
  crypto/schnorr-ristretto.cpp
  crypto/mlkem768.cpp
  crypto/hybrid-kem.cpp
  crypto/plonky3-verifier.cpp
  crypto/stealth-address.cpp
  crypto/note-encryption.cpp
  # rpc/
  rpc/handlers.cpp
  rpc/filter-service.cpp
  rpc/subscriptions.cpp
)

add_library(uno_workchain STATIC ${UNO_SRC})

target_include_directories(uno_workchain
  PUBLIC
    ${CMAKE_SOURCE_DIR}             # for "uno/core/*.h", "uno/crypto/*.h", "uno/rpc/*.h"
    ${CMAKE_SOURCE_DIR}/crypto      # for "block/*.h"
    ${CMAKE_SOURCE_DIR}/crypto/vm   # for "vm/cells/*.h"
)

# Rust FFI crate: uno_plonky3_ffi (built via corrosion-rs or equivalent)
corrosion_import_crate(MANIFEST_PATH plonky3-ffi/Cargo.toml)

target_link_libraries(uno_workchain
  PUBLIC
    tos_crypto           # cells, vm types, block types, dispatcher
    tddb                 # RocksDB wrapper if needed for auxiliary storage
    uno_plonky3_ffi      # Rust Plonky3 + Transfer AIR via C ABI
)

add_subdirectory(test)
```

Top-level `~/tos/CMakeLists.txt` adds:

```cmake
# next to add_subdirectory(evm)
if (NOT TOS_ONLY_TOSLIB)
  add_subdirectory(uno)
endif()
```

`validator-engine/CMakeLists.txt` adds:

```cmake
target_link_libraries(validator-engine uno_workchain)
```

### 11.5 TL-B schema

New file `tos/uno-tl.hpp` defining `Transfer`, `SpendDescription`, `OutputDescription`, `UnoShardState` and its sub-cells. Lives at the tos-wide schema level, not inside `uno/core/`, so it can be consumed by `tosctl` and external indexers without linking `uno_workchain`.

### 11.6 Modified files (the only in-place edits outside `uno/`)

1. `CMakeLists.txt` (top level) — add `add_subdirectory(uno)` next to the existing EVM entry.
2. `crypto/block/transaction.cpp` — add `case 2:` dispatch via `uno_workchain_dispatch::invoke_uno_compute`.
3. `crypto/block/CMakeLists.txt` — add `uno-workchain-dispatch.cpp` to `tos_crypto` sources.
4. `validator-engine/validator-engine.cpp` — `#include "uno/core/init.h"`; call `uno_workchain::init_uno_workchain(db_root_)` near the existing `evm_workchain::init_evm_workchain(db_root_)` call.
5. `validator-engine/json-rpc-server.cpp` — register `uno_*` method dispatch (pointing into `uno/rpc/handlers.h`).
6. `validator-engine/CMakeLists.txt` — add `uno_workchain` to `target_link_libraries`.
7. Genesis / zerostate builder — add wc=2 initial shard state with seed notes (§10.3); consumes `uno/core/genesis.h`.

Everything else is additive inside `~/tos/uno/`.

---

## 12. Test Strategy

Mirrors the EVM workchain's gate model.

### P.1 Primitive parity
- **Goldilocks field arithmetic**: cross-verify against Plonky3's reference Rust impl.
- **Poseidon2 over Goldilocks**: test vectors from Plonky3 reference; cross-check with eprint reference (Grassi, Khovratovich, Schofnegger 2023).
- **Ristretto255**: test vectors from RFC 9496; cross-verify against libsodium / curve25519-dalek.
- **Schnorr-on-Ristretto255**: cross-verify against a reference implementation.
- **ML-KEM-768**: NIST ACVP test vectors + cross-verify with liboqs and a second independent implementation.
- **Hybrid KEM combiner**: round-trip encrypt/decrypt with known keys; verify key-derivation transcript matches eprint 2025/1444 spec exactly.
- **Nullifier derivation**: test vectors against the `Poseidon2("uno-nf-v1", nk, cm, pos)` definition.
- **Plonky3 Transfer AIR**: honest prover produces accepting proof; adversarial prover with invalid witness is rejected; public-input vector encoding matches §4.3 exactly.

### P.2 Transaction codec fuzz
- Round-trip: build Transfer in `tosctl` (Rust), submit, decode back. Byte-identical re-serialization.
- 1 M iterations of random-bytes fuzz: no crashes, no panics, no non-deterministic decode.
- Malformed payloads: truncated proof, swapped nullifier order, invalid Ristretto decompress, truncated `mlkem_ct`, bad `filter_tag`, duplicated nf, duplicated cm, stale anchor, wrong chain_id.

### P.3 State-transition golden tests
- Deterministic fixtures: `state X + tx Y → state X'`. Assert `commitment_tree_root`, `nullifier_set_root`, anchor window post-state byte-identical.
- Include cases: valid 1-spend/1-output, 4/4 max, double-spend attempt, stale anchor, invalid proof, failed in-circuit balance check, over-max spends, fee < min_fee, expiry exceeded, invalid `spend_auth_sig`.

### P.4 Restart survival
- Two-node mini-net, drive 10 K valid txs + 1 K invalid txs mixed, kill and restart both nodes. Post-restart state roots must equal pre-crash state roots.

### P.5 Cross-validator determinism
- 4-node replay: identical tx stream, randomly permuted mempool order, assert identical state roots at every block.
- Also assert: parallel-verify pool output is byte-identical to serial verify (tx-order-preserving).
- Catch HashMap iteration, wall-clock dependence, float, RNG, uninitialized read.

### P.6 Client-side proving performance
- Plonky3 prover latency on reference hardware: 1-spend/2-output Transfer ≤ 15 s on M1 MacBook Air; ≤ 8 s on 8-core x86.
- Memory footprint ≤ 4 GB during proving (Plonky3 tends toward lower memory than Halo2 but AIR shape matters).
- Mobile: best-effort, no committed target.

### P.7 View-key audit correctness
- Seed wallet, send 100 txs, run audit with:
  - `fvk` (= `(ak, nk, ovk, sk_mlkem)`): recovers all incoming + outgoing notes with exact amounts.
  - `ivk` + `sk_mlkem` only: recovers all incoming, no outgoing.
  - `ovk` only: recovers all outgoing (via `out_ciphertext`), no incoming.
  - None: zero recovery.

### Mandatory negatives
- Replay attack: resubmit an included tx → rejected at nullifier check.
- Cross-chain replay: change `chain_id` but keep proof → rejected at transcript.
- Stale anchor (>100 blocks old) → rejected.
- Inflation attempt: hand-crafted tx with output sum > input sum → rejected at the in-circuit balance constraint (§3.3).
- Sender-linkage attack: given many `rk`s, try to cluster → no statistical advantage.
- Receiver-linkage attack: given many `(cm, epk, filter_tag)` triples, try to cluster → no statistical advantage (each output uses fresh `esk`, tags are unlinkable).
- HNDL simulation: attacker collects all historical ciphertexts + proofs; without either the Ristretto DL oracle or ML-KEM decap oracle, cannot recover note plaintext.

---

## 13. Phased Roadmap

| Phase | Deliverable | Done-when |
|---|---|---|
| **P.0** Plonky3 toolchain bring-up | Integrate Plonky3 Rust crates; write a minimum viable AIR (single-Poseidon2 hash + single Merkle-path verification); measure prove/verify times; validate C ABI approach via a "Hello World" Transfer-adjacent circuit. 2–3 weeks. | Minimal AIR produces and verifies; FFI round-trip works; Rust↔C++ build integrates cleanly. **This is a prerequisite before we can commit the full Transfer AIR design.** |
| **P.1** Crypto scaffolding + public-input golden fixture | Goldilocks field ops, Poseidon2 over Goldilocks, Ristretto255, Schnorr-on-Ristretto255, ML-KEM-768, hybrid-KEM combiner, stealth-address derivation, note encryption. **Cross-agent consensus-binding test**: `uno/test/golden/public-inputs-v1.hex` — fixed Transfer inputs produce byte-identical serialized `PublicInputs` vectors (§4.3 step 4) from both A4's Rust encoder and A5's C++ encoder. Test vectors pass. | Cross-verify against RFC 9496 (Ristretto255), NIST ACVP (ML-KEM), Plonky3 reference (Poseidon2), eprint 2025/1444 (hybrid KEM). Public-input fixture cross-checked between Rust and C++; mismatch blocks P.2 start. |
| **P.2** Transfer AIR + prover (Rust) | Hand-written Plonky3 AIR implementing claims 1–8 of §4.2: spends 1..4, outputs 1..4, in-circuit balance, Merkle paths, nullifier derivation, hash-chain key identity. Reference prover CLI in `tosctl`. | Valid witnesses produce accepting proofs; invalid witnesses fail at proving or verify. Cross-implementation fuzz. |
| **P.3** Parallel verifier in C++ (FFI) | Link `uno_plonky3_ffi` into validator via minimal C ABI. **Must support parallel verification across N worker threads (N = num_cores) with deterministic output ordering — this is an ACTIVATION PREREQUISITE, not a later release gate or optimization.** Per-tx signatures and proof verifies run concurrently in the pool; state mutations remain serialized by tx order. | Verify ≤ 15 ms per 1-spend/2-output tx single-thread; ≥ 3.5× scaling on 4 cores; byte-identical state root across parallel and serial execution. The chain cannot produce blocks at target TPS without this; it is blocking. |
| **P.4** State model + dispatch | `UnoShardState`, commitment-tree cells, nullifier dict, anchor window, block-filter accumulator, init hook, dispatch (§8). | Empty-state boot; no-tx blocks commit cleanly; state roots stable across restart. |
| **P.5** End-to-end compute + RPC | verify_transfer, apply_transfer, block-commit path. `uno_sendTransfer`, `uno_getAnchor`, `uno_getBlockFilter`, `uno_getOutputsAtBlock`, `uno_estimateFee`, `uno_getNullifierStatus`. | Two-wallet demo: A sends to B, B scans via compact filter + trial-decrypts, detects, `fvk` audit matches. |
| **P.6** Wallet (CLI via tosctl) | Key gen from main TOS seed (§2.6), address derivation (including `pk_mlkem`), compact-filter scan, hybrid-KEM decrypt, build+prove+send, balance from scan. | A → B → C chained; each recipient detects and spends their note; mobile test build runs at least one prove. |
| **P.7** Conformance + audit + docs | Full test matrix green; one external crypto audit (6–10 weeks, extended scope for first-application-of-Plonky3-to-shielded-pool) covering the Transfer AIR, key derivation, transcript composition, hybrid-KEM combiner, verifier FFI, deterministic-reject ordering. Upstream primitives (Plonky3 crates, ML-KEM reference, Ristretto255 impl) out of scope. | Audit clean; `doc/uno-workchain-known-divergences.md` authored; 60-day stable 5-validator testnet run. |

v1 release gate: all of P.0–P.7 green + 60 days of 5-validator testnet stability.

---

## 14. Explicit v2+ Items (not in v1)

**Not on this list, and deliberately so:** Shield / Unshield between wc=2 and any other workchain. This was proposed in earlier drafts and has been retracted as a permanent architectural exclusion (§1.5). A bridge structurally reopens deanonymization vectors that no downstream cryptography can close, and UNO's value proposition collapses to a weaker form the moment supply becomes cross-chain-mobile. Requests to add a bridge should be treated as requests to design a different chain, not as an extension of this one.

- **Multi-asset**: add `asset_id: bits256` to `Note`; per-asset nullifier scoping; per-asset in-circuit balance constraints (one equality per asset). Asset registry on masterchain. Note that multi-asset on wc=2 means *multiple natively-issued wc=2 assets*, each with its own fixed-at-genesis supply — it does **not** mean bridged assets from other workchains (§1.5).
- **Proof aggregation**: one Plonky3 recursive proof covers N Transfers; cuts per-block bandwidth by ~N×, enables higher throughput. Natural fit for Plonky3 since recursive FRI is well-supported.
- **Tachyon-compatible architecture** (Phase 3): oblivious sync + off-chain ciphertext + PCD recursion, following Zcash's Ragu direction as that ecosystem matures. v1 state schema is designed not to preclude this (§5.7, §6.2 Phase 3). Capability-gated on Ragu reaching production audit (currently targeted by Zcash for late 2026 / 2027; treat as v3+).
- **Programmable privacy (Aleo/Aztec-class)**: user-supplied AIRs over notes. Requires a privacy-aware zkVM or a DSL compiler targeting Plonky3. Plonky3 selection makes the proof-system layer ready; the state model and semantic design are the real work.
- **Shielded DEX (batch-auction design)**: periodic batch clearing with concealed amounts and prices; no continuous public order book.
- **Stealth-address discovery (opt-in)**: senders DM recipients asynchronously without exposing sender identity. Complements the ~1.2 KB address-size UX cost by providing an out-of-band handle layer.
- **Handle / naming service**: human-readable short aliases (`@alice.uno`) resolving to full addresses, since addresses are too large for social-media-bio style sharing. Wallet-layer product concern.
- **Phase 1 PQ spend-auth upgrade (ML-DSA hybrid, `scheme_id = 0x02`)**: see §6.2.
- **Sharding wc=2**: non-trivial — the commitment tree is global, so sharding requires either multiple independent pools or a recursive cross-shard inclusion proof (natural with Plonky3 recursion). Research item.

---

## 15. Design Choices Record

Every non-trivial choice below was made against the alternative space of published shielded-pool constructions. The column "Alternative considered and rejected" is included so a reviewer can see the design was chosen, not inherited.

| Dimension | Our choice | Alternative considered and rejected |
|---|---|---|
| Proof system | **Plonky3 STARK over Goldilocks** | Halo2/Pallas (rejected: Phase 2 proof-system migration debt mandatory; not PQ-native); Groth16 (per-circuit ceremony); Varuna (universal ceremony); Nova/Binius (research-stage). |
| Field | **Goldilocks (p = 2⁶⁴ − 2³² + 1)** | Pallas `Fp` (no PQ); BabyBear 31-bit (conservative security margin favors Goldilocks on a payment chain); binary fields (research-stage). |
| Curve (off-circuit, KEM + sig) | **Ristretto255** | Pallas (legacy from Halo2 era, not independently useful here); secp256k1 (ubiquitous but less modern); Ed25519 directly (co-factor issues avoided by Ristretto encoding). |
| Hash | **Poseidon2 over Goldilocks** | Poseidon v1 (slower, same security); Rescue-Prime, Monolith (slower on CPUs in 2026 measurements); Keccak/BLAKE3 (non-arithmetic, expensive in-circuit). |
| Tree depth | **32** (≈ 4 B-leaf cap) | Depth 24 tested in other systems; rejected as too tight for long-term growth. |
| Address model | **Orchard-style diversifiers over Ristretto255 + ML-KEM-768 hybrid** | Single-key addresses (Monero-family stealth) rejected as less flexible; EIP-5564 stealth-only (rejected: no PQ path for note encryption). |
| Spend auth | **Randomized Schnorr-on-Ristretto255** | Direct Schnorr without randomization (leaks owner identity across spends); ML-DSA-only (works but wastes bandwidth for a non-HNDL artifact in v1; deferred to Phase 1 hybrid). |
| Value commitment | **None — in-circuit balance check** | Pedersen `cv` + homomorphic binding signature (Orchard pattern): rejected as a Halo2-specific optimization made obsolete by Goldilocks u64-native arithmetic. |
| Note encryption | **Hybrid ECDH-Ristretto255 + ML-KEM-768** | ECDH-only (HNDL-vulnerable; Zcash is still debating this since 2022 issue #1133); ML-KEM-only (single point of failure if ML-KEM is broken); alternative hybrid KEMs (Saber, NTRU) — not NIST-standardized. |
| Max spends/outputs | **4 / 4** | Higher counts increase tx size linearly and proving time super-linearly; we pick a middle ground. |
| Anchor window | **100 blocks** | Shorter window tightens wallet UX; longer increases stored anchor size. 100 is middle ground. |
| State storage | **TOS cells** | Sidecar KV store (RocksDB, LMDB) rejected as violating the AccountBlock invariant and duplicating persistence machinery. |
| Single-executor account | **Yes** | Per-user accounts rejected: dust attacks, storage rent, per-user state bloat, no TOS AccountBlock parity. |
| No on-chain account state | **Yes** | Account+encrypted-balance model (our earlier v0 draft) rejected: hides amounts but not identities, inferior terminal privacy properties. |
| `scheme_id` crypto-agility | **Yes** | Hardfork-on-primitive-migration pattern rejected as unnecessary in a pre-launch network. |
| Client-side proving only | **Yes** | Server-assisted proving rejected as a trust regression. |
| Selective disclosure via view keys | **Yes, built in** | Bolt-on disclosure retrofits rejected as structurally harder; native hierarchies are cheap if designed up front. |
| Trusted setup | **None** | Per-circuit and universal setups both rejected; ceremony coordination, toxic-waste assumptions, and social-trust scope ruled out. |
| Genesis plaintext publication | **Yes (zerostate only)** | Zerostate blinded-distribution rejected as audit-hostile for a pre-launch network; one-time transparency preferable. |
| TPS posture | **~15–30 sustained / ~50 burst** at 1 s global block time | Not a design choice so much as an acceptance: inherent to terminal-privacy proof verify cost. Raw-throughput optimization at the cost of privacy is rejected. |
| Bridge posture | **None — permanent** | Shield/Unshield between wc=2 and any other workchain rejected permanently: entry-side gas binding, exit-side recipient binding, timing/amount correlation, and anonymity-set collapse are structural properties of any cross-chain flow and empirically deanonymize Zcash-style t↔z paths regardless of cryptographic strength inside the pool. UNO is a native, fixed-supply asset; privacy is an inception property, not a retrofit. See §1.5. |
| Supply model | **Fixed at genesis, monotonically non-increasing** | Inflationary emission rejected: any supply-creation path (block rewards in UNO, governance mint, bridge mint) requires a public accounting event that either leaks the beneficiary or duplicates bridge leakage. Validator compensation handled at masterchain in native TOS, not on wc=2. |

---

## 16. Decisions Log

1. **Architecture — decided: shielded note pool.** Terminal privacy properties (sender/receiver/graph unlinkability) require a pool model. Account+ElGamal is rejected as a local optimum with a 2-year shelf life.
2. **Proof system — decided: Plonky3 STARK over Goldilocks.** PQ-native (hash-based, FRI); no trusted setup; no Phase 2 proof-system migration debt. Trade: ~3–5× slower prove and ~4× larger proofs than Halo2 equivalent. The first L1 application of Plonky3 to a shielded-pool circuit; first-application risk is accepted (§0.2, §13).
3. **Off-circuit curve — decided: Ristretto255.** Used for stealth-address ECDH and Schnorr spend-auth. Well-audited, modern, no cofactor issues. No Pallas/Vesta dependency.
4. **Hash — decided: Poseidon2 over Goldilocks.** Plonky3-native in-circuit hash. Off-circuit content hashes use BLAKE3 (cells, transcripts) and BLAKE2b (seed derivation).
5. **Address hierarchy — decided: Orchard-style diversifiers over Ristretto255 + ML-KEM-768 pubkey.** View-key tiers (`fvk`, `ivk`, `ovk`) built in. Address size ~1.2 KB, accepted UX trade-off for PQ-native note encryption.
6. **Single-executor — decided: yes.** TOS AccountBlock invariant; zero per-user state.
7. **No accounts on chain — decided: yes.** Chain tracks notes and nullifiers only. Dust attacks and storage rent vanish.
8. **Crypto-agility — decided: `scheme_id` on every artifact.** 1 byte; no future hardfork for Phase 1 spend-auth upgrade.
9. **PQ posture — decided: PQ-native in v1, with one PQ upgrade deferred.** Proof system, note encryption, commitments, nullifiers, and Merkle tree are all PQ-native at v1 ship. Spend-auth signature remains classical Schnorr-on-Ristretto; Phase 1 adds ML-DSA-65 hybrid co-signature. The HNDL surface on note encryption closes at v1 via hybrid ECDH + ML-KEM-768.
10. **Trusted setup — decided: never.** Hard requirement. Plonky3 FRI is transparent.
11. **Max spends/outputs — decided: 4 / 4.** Size/time balance.
12. **Single asset — decided: v1 only.** Multi-asset in v2.
13. **Client-side proving — decided.** No prover server. Witness never leaves sender device (§7.2). Delegated-prove is opt-in privacy-weakening.
14. **Selective disclosure — decided: view keys mandatory in v1.** `fvk` includes derived `sk_mlkem` so audit remains possible with a single credential bundle.
15. **Anchor window — decided: 100 blocks.**
16. **No bridges, ever — permanent invariant.** Initial supply from zerostate only; no Shield/Unshield in v1, v2, or any later phase. Rationale in §1.5: cross-chain bridges structurally reopen four deanonymization vectors (entry-side gas binding, exit-side recipient binding, cross-boundary timing/amount correlation, anonymity-set collapse) that no downstream cryptography can close. UNO is a native, bridgeless asset by architectural commitment.
17. **Genesis plaintext publication — decided: exceptional, one-time, zerostate only.**
18. **Dispatch shape — decided: parallel to evm-workchain-dispatch.** Unify to a registry when wc=3 arrives.
19. **Fee model — decided: plaintext fee in UNO, burned.** Transaction fees are denominated in UNO (the only asset on wc=2), expressed as a plaintext `uint64` in the tx header (§4.1), and are burned on inclusion — destroyed from UNO supply. This makes total UNO supply monotonically non-increasing over the chain's lifetime. Validator compensation for wc=2 is **not** paid out of these burned fees; see decision #23.
20. **Genesis activation — decided: no hardfork.** TOS hasn't launched; wc=2 ships in the zerostate.
21. **Throughput posture — decided: accept low TPS.** TOS simplex consensus uses a global block rate (ConfigParam 30); per-workchain block intervals are not configurable in v1 and we do not propose extending the consensus protocol to support them. Proof aggregation moves to v2+ roadmap. v1 optimization is strictly within-block: parallel verify as an **activation prerequisite** (§13 P.3), nullifier LRU cache (§5.3), verifier pre-load (§8.3), compact filters to offload wallet work (§2.8), and one reserved ref slot on the root state cell (§5.1). Expected ceiling: 15–30 TPS sustained, up to ~50 TPS burst. Intrinsic cost of terminal privacy on commodity validator hardware; we don't fight it.
22. **Cell constraints — decided: we engineer around, not expand.** TOS cell limits (1023 data bits, 4 refs per cell) are Schelling points of the state layer and ecosystem tooling. We never propose increasing them. All over-sized artifacts (Plonky3 proofs, hybrid-KEM ciphertexts, nullifier dictionaries, tree frontiers) are expressed as cell trees. Details in §17.
23. **Validator compensation — decided: masterchain in native TOS, not UNO.** wc=2 is a TOS shardchain from the consensus reward perspective; its block producers are compensated out of masterchain validator revenue in native TOS, exactly as wc=0 and wc=1 producers are. UNO is never minted as a validator reward. This closes the economic model cleanly without requiring a UNO inflation path, preserving decision #16's bridgeless invariant and decision #19's monotonic-non-increasing supply property.
24. **UNO as an inception-private asset — decided.** "Privacy as a first-class citizen" (Ethereum 2030 strawmap framing) is interpreted here as: *the asset is private from the moment of issuance*, not *a public asset can opt into privacy via a retrofit*. The second interpretation requires a bridge and, per §1.5, is strictly weaker in practice. This is the load-bearing design claim of the chain.
25. **ML-KEM hybrid note encryption shipped in v1 — decided.** The HNDL window on on-chain ciphertexts is closed at v1 ship, not deferred to Phase 2. Cost: address size grows from ~43 B to ~1.2 KB (ML-KEM-768 pubkey); tx grows by ~1 KB per output (ML-KEM ciphertext). Accepted as the UX and bandwidth cost of taking "PQ-native privacy L1" seriously. KEM combiner follows eprint 2025/1444 split-KDF construction.
26. **Main-account seed derivation — decided: `uno_seed = BLAKE2b("uno-seed-v1" ‖ main_tos_seed)`.** A user with any TOS account automatically has a wc=2 identity; no separate key management. Specification-only change, zero runtime cost, determines the UX of cross-workchain identity for the life of the chain.
27. **Compact block filters shipped in v1 — decided.** 16-bit per-output detection tags + GCS-encoded per-block filter. Wallet scan cost drops ~500× at negligible validator cost (end-of-block compilation, ~1 ms/block). Activation requirement for mobile-viable privacy UX (§7.5).
28. **Parallel verify as activation prerequisite — decided (upgraded from "release gate").** The chain is structurally unable to produce 1 s blocks at target TPS without parallel Plonky3 verify across `num_cores` workers (§13 P.3). Not a later optimization; not a release gate; a precondition for the chain running at all. Encoded in §1.2 goals, §7.4 budget, and §13 roadmap as blocking.
29. **Value commitment / binding signature — decided: removed.** Balance is enforced by an in-circuit AIR constraint (§3.3), not by a Pedersen homomorphic trick. Removes 32 B per spend/output + 64 B per tx from the wire format. The Orchard/Halo2 trick was an optimization for a context where in-circuit u64 arithmetic was expensive; Goldilocks-native 64-bit arithmetic makes it obsolete.
30. **Ownership claim — decided: ivk-commitment hash-chain binding (no in-circuit curve ops).** §4.2 claim 3 is reformulated from Orchard's in-circuit `pk_d = ivk · g_d` to a pure hash-chain: `ivk_commitment = Poseidon2("uno-ivk-cm-v1", ivk, d)` is published in the address (§2.6) and bound into `cm` (§3.2); the AIR proves `ivk_commitment` matches an `ivk` hash-chained from `uno_seed`. **No curve operations inside the AIR.** The sole adversary-relevant property — "only the holder of `uno_seed` can produce a valid spend proof" — is preserved under the Poseidon2 random-oracle model.
31. **Spend-auth `rk` — decided: fresh per-spend Ristretto255 key, no `ak` randomization.** §2.5 is simplified from Orchard's `rk = ak + α·G` randomization scheme. Each spend samples a fresh `rsk ∈ scalars(Ristretto255)`, publishes `rk = rsk · G`, and signs `tx_hash` with Schnorr. No long-term spend-auth key `ak` exists; it is removed from `fvk`. Audit recovery of spend history goes through `ovk`-decrypted `out_ciphertext`, not through `rk` inversion. Rationale: Orchard's `rk-ak` randomization required in-circuit curve ops (claim 6 in earlier drafts); removing it eliminates the last curve op from the AIR, consistent with §2.5.
32. **Block-filter encoding — decided: GCS over raw 16-bit tags, `P=15, M=2¹⁶`, no secondary hash.** §2.8.1 pins the exact encoding as a consensus-binding spec. `filter_tag` is already cryptographic (§2.8), so no BIP-158-style keyed second hash is needed; GCS operates directly on the sorted deduplicated u16 multiset. Expected size ~100–150 B per block at 30 TPS, ~180-260 B at 50 TPS burst. The filter is a **derived view**, not consensus state — any full node reconstructs it from on-chain data. Byte-identical across every implementation; wallet SDKs match validator output by spec, not by keyed-hash agreement.
33. **FRI security parameters — decided: `log_blowup = 2`, `num_queries = 128`, `proof_of_work_bits = 16`.** §2.1 pins these as consensus-binding. Gives ~128-bit conjectured / ~64-bit proven classical soundness, ~64-bit conjectured / ~32-bit proven quantum soundness. Tighter than Plonky3/SP1/AggLayer defaults (`num_queries=84-100`, ~100-bit conjectured) because a soundness break on a privacy L1 with fixed-supply native asset enables unauthorized value creation, not just cross-chain bridge inconsistency. Cost: prove time +40%, proof size +30%, verify time +30% vs Plonky3 defaults. Accepted as the price of payment-chain-grade security. Rejected: `log_blowup=4` (doubled prove time for minimal conjectured-soundness gain); `num_queries=200` (same soundness as our choice, +50% proof size); pure 128-bit-proven target (prove time >2× slower, no meaningful real-world adversary advantage).
34. **ConfigParam slot for UnoConfig — decided: `ConfigParam 84`.** §10.2 slot allocation follows the TOS convention of placing workchain-specific / bridge-adjacent protocol parameters in the 70s-80s cluster (existing usage: 71-73 oracle bridges, 79/81/82 jetton bridges). 84 is the first free slot after the cluster. Rejected: `26` / `27` (core-band gaps that TOS/TON upstream may backfill with future low-numbered core-protocol extensions — clash risk); `100+` (arbitrary, breaks spatial locality with 71-82). Canonical registry entry added to `doc/ConfigParam.md`.
35. **Public-input byte encoding — decided: Plonky3-canonical little-endian u64 per Goldilocks element; 256-bit inputs split into 4 × u64 chunks in LE order with `mod p_Goldilocks` reduction.** §4.3 step 4 pins the exact byte-level spec. Total serialized length is `64 + 64·spend_count + 72·output_count` bytes. A golden fixture `uno/test/golden/public-inputs-v1.hex` enforces Rust (A4) ↔ C++ (A5) byte-identical output as a P.1 gate. Rejected: big-endian (breaks Plonky3 convention; no benefit); Bincode / serde (couples spec to crate version); application-specific formats (audit burden without gain). The `mod p_Goldilocks` reduction introduces ≈ 2⁻³⁰ aggregate bias on pseudo-random 256-bit inputs, negligible for soundness; adversary-controlled inputs are asserted `< p_Goldilocks` at admission.

---

## 17. TOS Cell Constraints and Our Strategy

This workchain lives inside TOS's cell-native state model. The cell primitive's hard limits are defined in `crypto/vm/cells/CellTraits.h`:

| Constant | Value | Meaning |
|---|---|---|
| `max_bits` | **1023 bits (≈ 128 B)** | Inline data per cell |
| `max_refs` | **4** | Child references per cell |
| `max_bytes` | 128 | Byte-equivalent of `max_bits` |
| `hash_bytes` | 32 | Cell representation-hash size |
| `max_depth` | 1024 | Maximum cell-tree depth |
| `max_level` | 3 | Level mask for Merkle-proof / virtualization cells |

These are **compile-time `enum` constants, not configuration parameters**. They are not extensible without:

- Rehashing every cell in the chain's history (cell representation hashes depend on the bit and ref limits).
- Rewriting the BoC (bag-of-cells) wire serialization format used for block transport, state sync, and light-client proofs.
- Invalidating every TL-B schema that pre-computes dictionary-node layouts, Merkle-proof shapes, or serialized sizes.
- Breaking wire compatibility with every TOS-ecosystem tool (indexers, wallets, light clients, dApp SDKs) that assumes the current constants.

**Uno does not propose expanding these constants.** They are a Schelling point of the TOS state layer; forking them is strictly more expensive than engineering around them.

### 17.1 How Uno fits its large artifacts into 128-byte cells

All over-sized data is stored as **cell trees** using the standard TOS idiom.

| Artifact | Raw size | Representation | Cells | Walk depth |
|---|---|---|---|---|
| Plonky3 proof (typical 1-spend/2-output, pinned FRI params) | ~52 KB | contiguous byte blob via `CellString` | ~420 | ~5 levels |
| Plonky3 proof (4-spend/4-output worst case) | ~100 KB | contiguous byte blob via `CellString` | ~800 | ~5 levels |
| `enc_ciphertext` (per output) | ~580 B | `CellString` | ~5 | 1 level |
| `mlkem_ct` (per output) | 1088 B | `CellString` | ~9 | 1 level |
| Commitment-tree frontier (32 Poseidon2-Goldilocks siblings) | ~1 KB | linked chain | ~8 | 1 level |
| Anchor window (100 roots) | ~3.2 KB | ring buffer cell chain | ~25 | 1–2 levels |
| Nullifier `vm::Dictionary` at 10 M | ~500 MB | 256-bit-keyed sparse dict | ~5 M | ~24 levels |

Each cell carries ~32 bytes of representation-hash and depth metadata, so a 40 KB proof pays ~10 KB of cell-tree overhead (≈ 24% bloat). This is the fixed cost of persisting non-trivially-sized artifacts in the cell model; we accept it.

### 17.2 Concrete mitigations in v1

- **Nullifier LRU** (§5.3 M2) — short-circuits the 24-level dict lookup for recent entries. The single largest performance lever we have at the 1 s block cadence.
- **Plonky3 proof serialization tuning** — target compact encoding for the Transfer AIR during P.2 (prover) + P.3 (verifier FFI) bring-up. Goal: minimize FRI query footprint without reducing soundness parameters.
- **Reuse `CellString`** (`crypto/vm/cells/CellString.h`) for contiguous byte arrays (proofs, `enc_ciphertext`, `mlkem_ct`). Avoids hand-rolling cell-chain code; consistent with the rest of the codebase.
- **Reserved root-cell ref** (§5.1) — one of the four refs on `UnoShardState` is intentionally unused, giving Phase 1 / Phase 3 extensions a single-ref budget to add state without a cell-schema migration.

### 17.3 Cell-count scaling frontier

Plonky3 proofs under the pinned FRI parameters (40–100 KB per tx) translate to 320–800 cells per proof. Tractable, but it makes **cell count per tx** — not inline bit width — the binding scaling axis. Proof-chain traversal must keep ≤ 5 levels; use all four refs per internal node where possible.

Phase 3 (Tachyon-compatible) would move `enc_ciphertext` and `mlkem_ct` off-chain entirely, shrinking on-chain per-tx to just the proof + commitments + nullifiers. This is the long-term route to reducing cell-tree scaling pressure.

**Cell-tree depth, not cell size, is the scaling axis we design against.** Any future artifact that cannot tolerate a ≥ 5-level walk against very large data must be pre-structured with the 4-ref fan-out in mind, never by requesting larger cells.

---

## 18. References

**Cryptographic primitives and specifications adopted:**
- **Zcash Orchard** (ZIP 224): published specification we adopt for the shielded-pool construction family (note-commitment tree, nullifier derivation, randomized spend authorization, diversified-address hierarchy). We adopt the construction; the proof backend is substituted with Plonky3.
- **Polygon Plonky3** (Plonky3/Plonky3, github.com): STARK toolkit — FRI commitments, Poseidon2 over Goldilocks, AIR builder. Production-validated via Polygon AggLayer pessimistic proofs (Feb 2025 mainnet) and Succinct SP1.
- **FIPS 203 (ML-KEM)**: NIST Module-Lattice-Based KEM. We use ML-KEM-768 (Level 3 security) for the PQ half of hybrid note encryption.
- **FIPS 204 (ML-DSA)**: NIST Module-Lattice-Based DSA. Reserved for Phase 1 hybrid spend-auth upgrade.
- **RFC 9496 (Ristretto255)**: prime-order group encoding over Curve25519. Off-circuit curve.
- **RFC 9380 (hash-to-curve)**: applied for Ristretto255 diversified-base derivation.
- **Grassi, Khovratovich, Schofnegger (2023)**: Poseidon2 specification.
- **Zcash post-quantum privacy discussion** (zcash/zips issue #1133): design principles for hybrid note encryption. Proposal-level in Zcash since 2022; we ship it.
- **"The Best of Both KEMs"** (eprint 2025/1444): combiner construction for hybrid KEMs, followed for our split-KDF design (§2.7).
- **Ethereum 2030 strawmap** (strawmap.org): north-star framing.

**Systems considered and not adopted:**
- **Zcash Halo2/Pallas**: structurally closest to our construction, but carries mandatory Phase 2 proof-system migration debt. Plonky3 chosen to eliminate this debt.
- **Project Tachyon** (Sean Bowe, Zcash 2025+): oblivious-sync + PCD + off-chain ciphertext. Not shipped (2026-04: under construction, no testnet). Our v1 is designed to not preclude a Phase 3 migration toward this direction (§6.2 Phase 3), but does not depend on it.
- Ring-signature-based shielded systems (UTXO + ring CT / Monero-family): rejected as structurally inferior to note-commitment + nullifier for anonymity-set growth.
- Mimblewimble (Grin / Beam): fails transaction-graph unlinkability.
- Account + encrypted balance (Solana confidential transfer, ZkBob): rejected as local optimum; amounts hidden but identity graph exposed.
- Hardware-enclave privacy (SGX-family): rejected due to extensive side-channel vulnerability history.
- Trusted-setup proof systems (Groth16, Varuna): rejected on decentralization grounds.

**In-house references:**
- **`~/avatar`**: in-house pure-C cryptography base; source for ChaCha20-Poly1305, BLAKE3, BLAKE2b.
- **`~/e`**: in-house PQ-signature reference for the Phase 1 hybrid spend-auth upgrade (ML-DSA-65 / Dilithium3).
