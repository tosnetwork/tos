# Uno Workchain (wc=2) — Design

**Status:** Draft v1
**Brand:** uno
**Scope:** Shielded note-pool workchain on TOS at workchain id `2`.
**Architecture class:** Shielded note-pool workchain. The cryptographic primitive family (Pallas/Vesta curves, Poseidon2 hash, nullifier scheme, diversified stealth addresses, randomized spend authorization, and view-key hierarchy) derives from the Zcash Orchard specification (ZIP 224). Proof system is Halo2 with IPA polynomial commitments — no trusted setup. State is integrated into TOS cell-native storage via a single executor account on wc=2. Selective disclosure and PQ-migration crypto-agility are first-class design properties.

**Primary references:**
- Zcash Orchard (ZIP 224) — standard shielded-pool primitive specification; we port these primitives rather than reinvent them, on the reasoning that reproducing a well-specified scheme faithfully is safer than drafting our own.
- `~/x` — prior art within the team; we do not clone its account model.
- `~/avatar` — in-house pure-C crypto base; we port selected primitives (Poseidon2, curve ops) into our C++ wrappers.
- `~/e` — in-house reference for post-quantum signature primitives used in Phase 1 (Dilithium3).

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

- One user-facing transaction type: **`Transfer`** with `1..4` spends and `1..4` outputs (outputs include sender change). Balance: `Σ spends = Σ outputs + fee`.
- **Native single asset.** No asset registry, no multi-asset circuits.
- **Stealth addresses** with diversifier-based key derivation.
- **View-key hierarchy** (`fvk`, `ivk`, `ovk`) for native selective disclosure.
- **Client-side proving** (Halo2, Pallas/Vesta, no trusted setup).
- **Cell-native state** — the note-commitment tree frontier, nullifier set, anchor window, and stats all live as TOS cells in CellDb inside a single executor account on wc=2.
- **Crypto-agility** via `scheme_id : u8` on every artifact, reserving the ID space for PQ migration.
- **Consensus-deterministic** execution; restart-survival; cross-validator state parity.
- **JSON-RPC surface** — `uno_*` namespace served from `validator-engine/`.

### 1.3 v1 Non-Goals (explicit)

- **No smart contracts.** v1 runs one fixed Transfer circuit. Programmable privacy (Aleo-class) is v2+.
- **No multi-asset.** Single native asset. Multi-asset + asset-scoped nullifiers: v2.
- **No cross-chain bridges.** Initial supply via zerostate only. Shield/Unshield between wc=0 and wc=2: v2.
- **No DEX / batch auction.** Batch-auction shielded DEX mechanics: v3.
- **No PQ primitives shipped.** Only the `scheme_id` hook. §6 lists phases.
- **No server-side scanning by default.** Wallet scans locally; server-assisted scan is opt-in and privacy-weakening.
- **No on-chain discovery / address book.** Out of scope.

### 1.4 Success criteria

1. On-chain footprint of a transfer reveals only: `{tx occurred, fee, anchor, spend count, output count}`. No amount, no sender identity, no receiver identity, no link to prior txs.
2. A wallet with `ivk` correctly detects all incoming notes sent to any of its diversified addresses; a wallet without `ivk` detects nothing.
3. Validator nodes restarted mid-chain reproduce byte-identical `note_tree_root`, nullifier set root, and anchor window.
4. Client-side proving ≤ **5 s** on a 2020-era laptop (M1 or 8-core x86); validator verify ≤ **15 ms** per tx.
5. Nullifier lookup ≤ **1 ms** against a 10 M-entry set (cache-warm); ≤ 10 ms (cache-cold).
6. An auditor holding `fvk` for a target account can reconstruct the full note history with correct amounts; without `fvk`, zero recovery.
7. **Sustained throughput: 15–30 TPS at 1 s global block time**, with burst capacity up to ~50 TPS when the nullifier LRU cache is warm. Higher throughput requires proof aggregation (v2 roadmap); we accept this ceiling as the intrinsic cost of terminal privacy on commodity validator hardware and do not fight it in v1.

---

## 2. Cryptographic Foundations

### 2.0 Crypto-agility (the only PQ-related work in v1)

Every on-chain artifact — `Transfer`, `NoteCommitment`, `Nullifier`, every proof, every transcript — carries `scheme_id : u8` alongside `version : u8`.

- `version` — wire-format version. Bumped when fields change.
- `scheme_id` — cryptographic suite. Bumped when a primitive is swapped.

**v1 defines only** `scheme_id = 0x01`. Reserved IDs:

| ID | Name | Suite | Status |
|---|---|---|---|
| `0x01` | `v1-halo2-pallas` | Halo2 IPA / Pallas-Vesta / Poseidon2 / Schnorr-on-Pallas / EIP-5564 stealth | v1 (now) |
| `0x02` | `v2-hybrid-dilithium` | v1 + ML-DSA-65 (Dilithium3) hybrid spend-auth signature | Phase 1 |
| `0x03` | `v3-stark-plonky3` | Plonky3 STARK / Goldilocks / Poseidon2 / hash-based sig / ML-KEM note encryption | Phase 2 |
| `0x04..0xFE` | unassigned | — | — |
| `0xFF` | test | reserved for internal / fuzz; never accepted on mainnet | — |

Dispatch: the verify path is keyed `(workchain_id=2, scheme_id) → verifier`. v1 installs exactly one entry. Unknown scheme_id is a **deterministic reject**, never a silent fallthrough.

Transcript binding: every Fiat-Shamir transcript used in this design starts with the fixed root tag `"uno-workchain-v1"` (ASCII, 16 bytes, zero-padded to one Poseidon2 absorb). Immediately after the root, the transcript absorbs `"scheme-id" || u8` as its first variable field. Challenges are thus domain-separated per scheme; no cross-scheme proof replay is possible even under byte-level wire-format collisions.

Cost: 1 byte per tx, 1 byte per transcript absorb, one dispatch map entry. Zero lattice/hash-sig code ships in v1. Full PQ roadmap lives in §6.

### 2.1 Curve and fields

- **Pallas** — prime-order short-Weierstrass curve (`y² = x³ + 5`) from the pasta_curves family, 255-bit base field.
- **Vesta** — pair curve, same family, same shape.
- **Base field `Fp`** of Pallas — used by Poseidon2 inside circuits.
- **Scalar field `Fq`** of Pallas (≡ base field of Vesta) — used for ECC scalar math.
- **Cycle property**: `|Fp(Pallas)| = |Fq(Vesta)|` and vice versa; a Pallas curve operation over `Fp` can be proved in a Halo2 circuit over `Fq(Vesta)` and composed recursively. This enables Phase 2 proof aggregation without field emulation.
- **Point encoding**: compressed form is 32 bytes = 255 bits of `x`-coordinate + 1 parity bit of `y`. We use this compressed form throughout the wire format (`rk`, `epk`, `pk_d`).

Why Pallas/Vesta over alternatives:
- **vs. Decaf377 / BLS12-377-based curves**: they need pairings + per-circuit trusted-setup ceremony under Groth16. We reject trusted setup.
- **vs. BN254 (Ethereum zk legacy)**: per-circuit ceremony required. Same objection.
- **vs. BLS12-377 + Varuna (Aleo)**: universal ceremony is better than per-circuit but still a ceremony. Pallas/Vesta's Halo2-IPA has none.
- **vs. Goldilocks (Plonky2/3)**: tempting for PQ-friendliness but prover tooling is less mature in 2025. Plonky3 is the `scheme_id=0x03` target, not v1.

### 2.2 Hash: Poseidon2

- **Poseidon2** (Grassi, Khovratovich, Schofnegger 2023) — ~30% faster than original Poseidon, same security analysis.
- Parameters: state width `t=3` for 2-to-1 merging; `t=4` for 3-to-1 and 4-to-1 variants; all over the Pallas base field `Fp`.
- Used **inside the Halo2 circuit** for: note-commitment hashing, Merkle tree path hashing, key derivation, in-circuit Fiat-Shamir transcript (needed for Phase 2 recursion readiness).
- Used **outside the circuit** (plain software) for: Fiat-Shamir challenges during verifier operation, value-commitment randomizer derivation from `rseed`, `ivk` derivation, `nf` computation on the wallet side.
- **Not Keccak / BLAKE3 inside circuits** — these are byte-oriented and prohibitively expensive in a SNARK.

BLAKE3 remains for (a) TOS cell representation hashing (chain-internal, unrelated to the privacy circuit) and (b) off-circuit seed derivation for `ask`, `nk`, `ovk` where there is no benefit from Poseidon2's in-circuit friendliness.

### 2.3 Note commitment tree

- **Type**: depth-32 sparse Merkle tree (SMT); supports up to 2³² ≈ 4 B live notes.
- **Node hash**: `Poseidon2(left, right)` over `Fp`.
- **Append-only**: new commitments are appended at `next_position`; no mutation or deletion.
- **On-chain storage**: only the **frontier** — the 32 right-edge node hashes needed to append and compute the root — persists on-chain (~1 KB). Full history is reconstructable by clients from the tx log if needed.
- **Anchors**: at the end of each block the current root is pushed into a 100-block ring buffer. Spends reference an anchor by root hash; validator accepts iff that anchor is in the window.

### 2.4 Nullifier scheme (Orchard-style)

For a note with commitment `cm` at position `pos` in the tree, under nullifier key `nk`:

```
nf = Poseidon2(nk, cm, pos)
```

Properties:
- **Hiding**: `nf` reveals no information about `cm`, `pos`, or `nk` to a chain observer.
- **Deterministic**: same note → same `nf` → double-spend caught by set membership check.
- **Unlinkable**: two different notes owned by the same `nk` produce `nf`s that are indistinguishable from random.

### 2.5 Spend authorization (randomized Schnorr)

- Spend authority scalar `ask ∈ Fq` (secret).
- Base public spend key `ak = ask · G ∈ Pallas`.
- For each spend, the wallet samples a fresh randomizer `α ∈ Fq`, computes:
  - Randomized spend key scalar `rsk = ask + α`
  - Randomized public spend key `rk = rsk · G = ak + α · G`
- **Spend-auth signature**: Schnorr-on-Pallas using `rsk`, over the canonical tx hash.
- The ZK proof attests that `rk = ak + α · G` for some `α` known to the prover AND `ak` belongs to the owner of the spent note.

**Property**: `rk` is unlinkable to `ak` or to other `rk`s from the same user — revealing `rk` on chain leaks nothing about the long-term identity.

### 2.6 Address hierarchy (stealth + diversifiers)

**Key hierarchy** (from a 256-bit seed `sk`). All `PRF` calls are Poseidon2 with distinct domain-separator tags:
```
ask  = PRF_blake2b(sk, "uno-ask") mod q          ∈ Fq      // spend authority scalar
nk   = PRF_blake2b(sk, "uno-nk")  mod q          ∈ Fq      // nullifier key (a scalar)
ovk  = PRF_blake2b(sk, "uno-ovk")                ∈ bits256 // outgoing viewing key (opaque bytes)
ak   = ask · G                                   ∈ Pallas  // public spend key (curve point)
ivk  = Extract(Poseidon2(repr(ak), repr(nk)))    ∈ Fq      // incoming viewing key (scalar)
fvk  = (ak, nk, ovk)                                       // full viewing key
```

Two field conventions are needed here because Pallas curve points live over `Fp` but scalars (used for multiplication) live in `Fq`. The helper functions are:

- `repr(P)` for a Pallas point `P` — serialize as two `Fp` elements `(P.x, P.y)`. Poseidon2 absorbs these as two inputs.
- `repr(s)` for an `Fq` scalar `s` — interpret as an `Fp` element (bitstring reinterpretation; both fields are ~255 bits). The reinterpretation may alias (if `s` ≥ p, it wraps to `s - p` in `Fp`); the aliasing interval `[min(p,q), max(p,q)]` has size < 2⁻²⁵⁰, so the bias is cryptographically negligible at 128-bit security.
- `repr(x)` for an integer-width value `x` (e.g. `bits88`, `uint64`, `uint32`) — zero-extend to one `Fp` element. Fits with room to spare: `Fp` is ~255 bits.
- `Extract(h)` — take a Poseidon2 output `h ∈ Fp` and reduce modulo `q` to get an `Fq` element. Bias analysis same as `repr` for scalars: negligible.

PRF seed material (`ask`, `nk`) uses BLAKE2b rather than Poseidon2 because the seed is off-circuit and byte-oriented; there's no benefit to paying Poseidon2's arithmetic cost here. `ivk`, which must be re-derivable inside the ZK circuit, uses Poseidon2.

**Addresses**:
```
d    ∈ bits88                                  // diversifier; user picks (may rotate)
g_d  = HashToPallas(d)                         // diversified base (Pallas point)
pk_d = ivk · g_d                               // diversified transmission key (Pallas point)
Address = (d, compress(pk_d))                  // published; 88 + 256 = 344 bits ≈ 43 bytes
```

`HashToPallas` is the hash-to-curve construction for Pallas defined in the pasta_curves reference (Shallue-van de Woestijne variant). Input: a domain-separated hash of `d`. Output: a Pallas point with no known discrete log with respect to any other base.

A single seed yields ~2⁸⁸ distinct addresses. An observer cannot link addresses of the same holder.

**Sender encrypts a note to an address**:
- Pick ephemeral `esk ∈ Fq`, compute `epk = esk · g_d` (Pallas point).
- Derive shared secret: `s = esk · pk_d` (Pallas point).
- Derive symmetric key: `k = Poseidon2(repr(s))` truncated to 256 bits.
- Encrypt note plaintext under `k` with ChaCha20-Poly1305 AEAD → `enc_ciphertext`.
- Publish `epk` (compressed) in the `OutputDescription`.

**Receiver decrypts**:
- Hold `ivk`; for each on-chain `OutputDescription`, compute `s' = ivk · epk`.
- By ECDH symmetry: `s' = ivk · (esk · g_d) = esk · (ivk · g_d) = esk · pk_d = s`. Same point.
- Derive `k`, trial-decrypt. AEAD tag check reveals "this note is mine".

The construction follows the Zcash Orchard pattern (ZIP 224) and is compatible with EIP-5564's stealth-address posture. The field-crossing helpers (`repr`, `Extract`) are standard and appear in the Orchard reference in the same roles.

---

## 3. Note, Commitment, Nullifier, Value Commitment

### 3.1 Note (plaintext, off-chain)

```
Note :=
  d       : bits88           // recipient diversifier
  pk_d    : Pallas point     // recipient's diversified transmission key (32 B compressed)
  value   : uint64           // amount in native asset
  rseed   : bits256          // randomness seed; derives both the note-commitment trapdoor
                             // and the value-commitment blinding factor, via Poseidon2 PRF
```

Never transmitted on-chain in plaintext. Transmitted encrypted to the receiver inside `enc_ciphertext` of the tx output description.

From `rseed`, the sender derives two independent blinding factors via Poseidon2 with distinct domain-separator tags:
- `rcm = Poseidon2("uno-rcm", rseed)` ∈ Fp — note-commitment hiding randomness; consumed directly as an `Fp` input to the Poseidon2 note-commitment hash in §3.2. **Not** reduced to Fq (no curve-scalar use).
- `rcv = Extract(Poseidon2("uno-rcv", rseed))` ∈ Fq — value-commitment blinding factor; used as a curve scalar in §3.3 (`rcv · R`).

The two outputs are in different fields because they serve different roles: `rcm` is hash-randomness (must match the field Poseidon2 operates in), and `rcv` is a curve scalar (must live in Fq to multiply a Pallas point). Using the correct field at each site avoids an implicit modular reduction that would otherwise leak a 1-bit bias.

### 3.2 Note commitment (on-chain, in `OutputDescription`)

```
cm = Poseidon2(repr(d), repr(pk_d).x, repr(pk_d).y, value, rcm)
```

- Computed inside the ZK circuit by the prover; the chain takes it as-is and appends to the tree.
- Leaks zero bits about `value` by the pre-image resistance and hiding of Poseidon2, given a 256-bit seed `rseed` feeding `rcm`.

### 3.3 Value commitment (on-chain, in both `SpendDescription` and `OutputDescription`)

A **Pedersen commitment to the value** on a curve; unlike `cm` (which is a hash and thus non-homomorphic), `cv` must support homomorphic addition across spends and outputs so that the binding signature (§4.2 claim 10) can prove balance.

```
cv = value · V + rcv · R    ∈ Pallas
```

- `V`, `R` — two independent Pallas generators, obtained by deterministic `HashToPallas` from the domain tags `"uno-value-V"` and `"uno-value-R"` respectively. Neither discrete log wrt the other is known.
- `value ∈ [0, 2⁶⁴)` — enforced by a range proof inside the ZK circuit.
- `rcv ∈ Fq` — blinding factor (see §3.1).
- 32 bytes compressed on wire.

**Homomorphic balance identity**:
```
Σ_spends cv_i − Σ_outputs cv_j − fee · V
    = (Σ_spends value_i − Σ_outputs value_j − fee) · V
    + (Σ_spends rcv_i − Σ_outputs rcv_j) · R
```

If the value-balance holds (`Σ spend.value = Σ output.value + fee`), the `V` term vanishes and the left-hand side equals `bsk · R` where `bsk := Σ_spends rcv_i − Σ_outputs rcv_j` is the **binding signing key** (known only to the sender).

The sender proves knowledge of `bsk` via a Schnorr signature under `R` as the generator — this is the `binding_sig` in §4.1. Verifier recomputes the LHS from on-chain `cv`s and checks the Schnorr signature under that public key. No ZK proof needed; a classical Schnorr signature proves value conservation.

### 3.4 Nullifier (on-chain, in `SpendDescription`)

When a note is spent:
```
nf = Extract(Poseidon2("uno-nf", repr(nk), cm, pos))
```

where `nk` is the owner's nullifier key (Fq scalar) and `pos` is the leaf index of `cm` in the note commitment tree, set at append time.

**Simplification vs Orchard**: the Zcash Orchard nullifier is `Extract(Hash_nk(ρ) + Commit(ψ, cm))` using Sinsemilla commitments over per-note trapdoors `(ρ, ψ)`. Our construction replaces the `(ρ, ψ)` trapdoors with the public leaf position `pos`. This simplification:
- Reduces the Note struct by 64 bits.
- Removes one Sinsemilla commitment from the spend circuit.
- Relies on `pos` being unique per committed note (true by tree-append semantics).
- Security analysis: `nf` is still computationally binding to the note and hiding under Poseidon2; the simplification trades per-note pseudo-randomness (from `ρ, ψ`) for the chain-provided uniqueness of `pos`. Under Poseidon2 modeled as a random oracle, the scheme is sound.

Published in the `SpendDescription`. Added to the nullifier set. A second appearance of the same `nf` in any future tx is an attempted double-spend and is rejected at §4.3 step 2.

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
  binding_sig       : bits512                    // 64 B Schnorr on Pallas under R
                                                 // as generator (proves value balance)
  zk_proof          : ^Cell                      // Halo2 proof serialized via CellString

SpendDescription :=
  nullifier         : bits256                    // nf = Extract(Poseidon2("uno-nf", nk, cm, pos))
  cv                : bits256                    // value commitment  cv = value·V + rcv·R  (compressed Pallas)
  rk                : bits256                    // randomized public spend key = ak + α·G  (compressed Pallas)
  spend_auth_sig    : bits512                    // 64 B Schnorr on Pallas under rsk over tx hash

OutputDescription :=
  cm                : bits256                    // note commitment (Poseidon2 hash)
  cv                : bits256                    // value commitment  cv = value·V + rcv·R  (compressed Pallas)
  epk               : bits256                    // ephemeral public key  epk = esk·g_d  (compressed Pallas)
  enc_ciphertext    : ^Cell                      // 580 B, ChaCha20-Poly1305 over Note plaintext + memo
  out_ciphertext    : bytes[80]                  // 80 B inline, AEAD-encrypted memo recoverable with ovk
```

Inline field sizes:
- Fixed tx header (everything before `spends`): `1+1+4+32+8+8+1+1 = 56` bytes.
- Each `SpendDescription` inline: `32+32+32+64 = 160` bytes.
- Each `OutputDescription` inline (excluding `enc_ciphertext` ref): `32+32+32+80 = 176` bytes; `enc_ciphertext` held as a ref to a ~5-cell chain.
- `binding_sig` inline: 64 bytes.
- `zk_proof` is a ref to a cell chain (~10 KB raw = ~80 cells; see §17.1).

`enc_ciphertext` layout (580 B total):
- 84 B: `Note` plaintext fields packed and aligned (11 B `d` + 32 B `pk_d` + 8 B `value` + 32 B `rseed` + 1 B padding = 84 B).
- 480 B: encrypted memo (free-form bytes the sender attaches for the receiver; padded to fixed size to prevent length-based metadata leakage).
- 16 B: Poly1305 authentication tag.
- The 12 B ChaCha20 nonce is derived deterministically from `epk` (via BLAKE3 over `"uno-nonce" || compress(epk)`), so it is **not transmitted** — the receiver reconstructs it at decrypt time from the on-chain `epk`.

**Size breakdown** (a typical 1-spend, 2-output tx):
- Inline part of tx body: `56 + 160 + 2×176 + 64 = 632` bytes.
- Ref cells for 2 × `enc_ciphertext` × ~5 cells each × ~128 B raw + ~32 B overhead = ~1.6 KB.
- Ref cell for `zk_proof` (~10 KB raw, ~80 cells): ~12.4 KB with overhead.
- **Total: ~14.6 KB per tx**. Worst-case 4-spend / 4-output with full memos: ~20 KB.

Larger than an account-model tx (1.2 KB), but this size is intrinsic to terminal privacy — the proof carries the entire unlinkability argument. Sendable over standard TOS external-message plumbing (no envelope hardcap).

**Canonical tx hash** (used by both `spend_auth_sig` and `binding_sig` as the message they sign, and by `uno_getTransactionStatus` as the lookup key):

```
tx_hash := BLAKE3(
    version(1) || scheme_id(1) || chain_id(4) || anchor(32) ||
    expiry_block(8) || fee(8) || spend_count(1) || output_count(1) ||
    for each spend in declared order:
        nullifier(32) || cv(32) || rk(32)        // SpendDescription EXCEPT spend_auth_sig
    for each output in declared order:
        cm(32) || cv(32) || epk(32) ||
        cell_hash(enc_ciphertext) || out_ciphertext(80)
)
```

The signature fields (`binding_sig`, `spend_auth_sig[i]`) and the `^zk_proof` cell ref are **excluded** — they are either signing outputs over `tx_hash` (circular otherwise) or derived quantities the ZK proof attests to via its own public-input binding. `enc_ciphertext` is hashed via its cell root, not expanded inline, so the tx hash remains O(inline-size) to compute.

Every signature and every ZK-proof public input binds `tx_hash` (or equivalently, binds the same tuple transitively). Replay across chain_ids, schemes, or block heights is therefore structurally impossible.

### 4.2 What the ZK proof attests

Per `SpendDescription`:
1. **Membership**: the spent `cm` is a leaf of the tree rooted at `anchor`. Proved via a 32-level Merkle path with Poseidon2 nodes inside the circuit.
2. **Opening**: prover knows `(d, pk_d, value, rseed)` such that `cm = Poseidon2(repr(d), repr(pk_d).x, repr(pk_d).y, value, rcm)` where `rcm` is derived from `rseed` (§3.1).
3. **Ownership**: prover knows `(ask, nk)` such that `ak = ask·G`, `ivk = Extract(Poseidon2(repr(ak), repr(nk)))`, and `pk_d = ivk · HashToPallas(d)`. This proves the note was addressed to the prover.
4. **Nullifier correctness**: `nf = Extract(Poseidon2("uno-nf", repr(nk), cm, pos))` where `pos` is the leaf index implied by the Merkle path.
5. **Auth randomization**: `rk = ak + α · G` for a randomizer `α ∈ Fq` known to the prover.
6. **Spend-side value commitment**: `cv_spend = value · V + rcv · R` for the same `value` used in the note opening and `rcv` derived from `rseed`.

Per `OutputDescription`:
7. **Well-formed commitment**: `cm' = Poseidon2(repr(d'), repr(pk_d').x, repr(pk_d').y, value', rcm')` for sender-chosen `(d', pk_d', value', rseed')`.
8. **Range**: `value' ∈ [0, 2⁶⁴)` — proved in-circuit via binary-decomposition constraints.
9. **Output-side value commitment**: `cv_output = value' · V + rcv' · R` for the same `value'`.

Inputs visible to the verifier (circuit public inputs): `anchor`, per-spend `(nf, cv, rk)`, per-output `(cm, cv, epk)`, `expiry_block`, `chain_id`, `scheme_id`, `fee`. Everything else is a private witness held by the prover.

**Balance** (whole tx, proved outside the ZK proof):
10. `Σ spend.value = Σ output.value + fee` — proved by the binding signature mechanism from §3.3. The verifier computes
    ```
    P_bind = Σ_spends cv_i − Σ_outputs cv_j − fee · V
    ```
    and accepts iff `binding_sig` is a valid Schnorr signature under `P_bind` as the public key with `R` as the generator, signed over the tx hash. Correctness: if the value-balance holds, `P_bind = bsk · R` where the prover knows `bsk`; if not, no `bsk` satisfies the equation and the signature is unforgeable.

The Halo2 proof attests claims 1–9 in one shot; the binding sig attests claim 10. Verifier runs one Halo2 verify + one Schnorr verify + per-spend Schnorr verify for `spend_auth_sig`.

### 4.3 Deterministic verification order

`uno_workchain::verify_transfer()` is run during the compute phase and is **consensus-critical**: every validator must agree on accept/reject. Mempool admission is a separate, cheaper filter — see §4.3a. The order below is the full consensus verify; any failure is a deterministic reject:

1. **Cheap syntax**:
   1. `version == 1`, `scheme_id == 0x01`, `chain_id == expected`.
   2. `expiry_block ≥ current_block` AND `expiry_block ≤ current_block + expiry_window_blocks` (ConfigParam 26).
   3. `1 ≤ spend_count ≤ 4`, `1 ≤ output_count ≤ 4`.
   4. `fee ≥ min_fee_nano + fee_per_byte_nano · tx_size_bytes + fee_per_spend_nano · spend_count + fee_per_output_nano · output_count`, where `tx_size_bytes` is the wire-format inline size of the tx (excluding referenced cell chains; those are charged via the per-spend / per-output terms).
   5. `anchor` matches one of the 100 roots in `state.anchor_window`.
   6. All `spend.nullifier` pairwise distinct within tx; all `output.cm` pairwise distinct within tx.
   7. Every 32-byte Pallas point field (`rk`, `cv` on spends and outputs, `epk`) decompresses to a valid group element that is not the identity.
2. **Nullifier not-spent**: for each spend, `nf ∉ nullifier_set` (LRU hit is sufficient to reject on positive lookup; negative LRU result must be followed by a cell-dict lookup per §5.3).
3. **Each `spend_auth_sig`** verifies as Schnorr on Pallas under the corresponding `rk`, signed over the tx hash (BLAKE3 over canonical tx bytes excluding the signatures and the proof).
4. **Binding signature** verifies:
   - Compute `P_bind = (Σ_spends cv_i) − (Σ_outputs cv_j) − fee · V` using on-chain Pallas point arithmetic.
   - Reject if `P_bind` is the identity (degenerate — implies `bsk = 0`, which is a forgery vector).
   - Verify `binding_sig` as a Schnorr signature under `P_bind` with `R` as the generator, over the tx hash.
5. **Halo2 proof** verifies (covers claims 1–9 from §4.2). Public inputs are assembled into a canonical `Fp` vector in exactly the following order (verifier and prover must agree bit-identically; this ordering is pinned by the Transfer circuit spec):
   1. `scheme_id` as one `Fp` (1 byte zero-extended).
   2. `chain_id` as one `Fp` (4 bytes zero-extended).
   3. `expiry_block` as one `Fp`.
   4. `fee` as one `Fp`.
   5. `anchor` as two `Fp`s (256 bits split across two field elements).
   6. For each spend `i` in declared order: `nf_i` (2 `Fp`), `cv_i.x`, `cv_i.y`, `rk_i.x`, `rk_i.y`.
   7. For each output `j` in declared order: `cm_j` (2 `Fp`), `cv_j.x`, `cv_j.y`, `epk_j.x`, `epk_j.y`.

   Total public input count: `4 + 2 + 5·spend_count + 6·output_count` field elements. The verifier rejects proofs whose public input vector has a different length or encoding.
6. **Apply state transition** (only after steps 1–5 all pass):
   - For each output in declared order: `state.commitment_tree.append(output.cm)`; `state.next_position += 1`.
   - For each spend in declared order: `state.nullifier_set.insert(spend.nf)`; update the nullifier LRU.
   - `state.stats.burned_fees += fee`.
   - `state.stats.tx_count += 1`.
   - `state.stats.note_count += output_count`.

**Verify-before-mutate is a hard invariant**: any failure in steps 1–5 produces zero state delta. There is no rollback path, so there is never a partial state.

No randomness, no wall-clock, no HashMap iteration, no floats anywhere in the verify path.

### 4.3a Mempool admission (non-consensus pre-filter)

To prevent DoS from obviously-invalid txs, the JSON-RPC admission path runs a **cheaper** subset of checks before queuing a tx into the mempool:

1. §4.3 step 1 (all cheap syntax checks).
2. Nullifier LRU check only (do NOT touch the cell-dict — that is a tx-per-block cost; the LRU hit is sufficient to reject obvious replays).
3. `spend_auth_sig` verification (cheap: N × ~1 ms).
4. Binding sig verification (cheap: ~1 ms).
5. **Does NOT** run the Halo2 proof verify — that is the expensive step, deferred to the compute phase where at least the block producer is paid to pay for it.

Txs that pass 1–4 are queued for inclusion; the compute phase runs the full §4.3 sequence including Halo2 verify. A tx that passes admission but fails compute (e.g. an invalid proof that nevertheless carried valid signatures) is recorded as `TxRejected` in the block and **costs the mempool its admission slot** — but, since v1 has no way to charge fees for rejected txs (the fee is claimed only on inclusion), such an adversarial tx gives the attacker a free proof-verify consumption. Mitigations:
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
| Balance composition | No per-note values; only `Σ value = fee` via binding sig. |
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

**Implementation requirement (M2) — nullifier LRU cache**: the validator maintains an in-memory LRU of recently-inserted nullifiers, default capacity **1 M entries (~100 MB RAM)**, tunable via ConfigParam 26. Cold-cache dictionary lookups on a 10 M-entry set traverse ~24 cell levels and can exceed the per-tx block-time budget under a 1 s cadence; the LRU makes insert-and-immediately-check paths hot.

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

Wallets hold `(fvk)` or `(ivk)`. They sync by fetching all `OutputDescription`s posted since their last checkpoint and trial-decrypting each with `ivk`.

Trial-decrypt cost per output ≈ **1 ms** (one Pallas scalar multiplication for `s' = ivk · epk`, one Poseidon2 hash, one ChaCha20-Poly1305 AEAD open-attempt with early-rejected authentication tag).

Concrete sync budget:
- **Sustained load** (30 TPS × 2 outputs/tx): ~5.2 M outputs/day → **~24 min/day** of trial-decrypt on one core. A wallet offline for one week needs ~3 hours to catch up.
- **Burst load** (50 TPS × 2 outputs/tx): ~8.6 M outputs/day → ~2.4 h/day.

Three mitigations bracket the scan cost, ordered from "available in v1" to "future":
- **Server-assisted sync** (opt-in, v1 available): wallet sends `ivk` to a trusted server; server returns just the decrypted subset. Privacy-weakening (server sees which notes belong to the user's `ivk`); user-chosen, never default.
- **Parallel scan** (v1, trivial): wallet uses all local cores; on a 4-core laptop the budget drops to ~6 min/day sustained.
- **Compact-filter RPC** (v2): server emits per-block Bloom-like filters over per-output tag bits; wallet discards ~99% of outputs before attempting decrypt. Reduces work by ~100× without revealing which notes belong to which wallet.

No per-wallet on-chain state is ever created. The chain has no idea who the wallets are.

### 5.9 Throughput budget

TOS simplex consensus runs a global block rate (ConfigParam 30); per-workchain block intervals are not configurable in v1. Given the current 1 s block setting and the per-tx verify cost of our scheme, the per-block serial budget breaks down:

| Stage | Typical |
|---|---|
| Consensus overhead (catchain rounds, proposal, propagation) | 400–500 ms |
| Block commit WriteBatch | 20–50 ms |
| Mempool drain + signature routing | 20 ms |
| **Remaining for compute phase** | **~400–500 ms** |

Per-tx compute cost in the compute phase:

| Component | Time |
|---|---|
| Cheap checks (anchor, dedup, point decompression) | 2 ms |
| Nullifier existence check (LRU-hit path) | < 1 ms |
| Binding-sig verify + spend-auth sigs | 5 ms |
| Halo2 proof verify | 10–15 ms |
| State mutation (tree append + nullifier insert + cell writes) | 5–8 ms |
| **Total per tx, single-threaded** | **~25 ms** |

**Serial TPS ceiling: 400 / 25 ≈ 16 TPS.** With M1 (parallel proof verification across N worker threads; §13 P.3 release gate), the ceiling rises to **~50 TPS burst / 30 TPS sustained** on 4-core validator hardware.

This ceiling is **by design**. The trade-off: every user gets terminal privacy with client-side proving, validators run on commodity hardware, the chain does not market throughput. If sustained demand exceeds the ceiling, the response is proof aggregation (v2 roadmap) — not block-rate adjustment and not weakening of privacy properties.

---

## 6. Post-Quantum Migration Path

This section records the PQ story. v1 ships only the `scheme_id` plumbing described in §2.0. The purpose here is to lock in the migration shape so v1 does not close doors.

### 6.1 Why a shielded pool has a cleaner PQ story than account+ElGamal

Per-layer PQ exposure:

| Layer | v1 primitive | Quantum impact | HNDL footprint |
|---|---|---|---|
| Note commitments | Poseidon2 hash | Grover halves; mitigated by ≥256-bit output | None |
| Nullifiers | Poseidon2 | Grover halves | None |
| Merkle tree nodes | Poseidon2 | Grover halves | None |
| Anchor roots | Poseidon2 | Grover halves | None |
| Spend auth sig | Schnorr-on-Pallas | Shor broken | None — each sig is one-time, signed after Q-day trivially migrates |
| Note encryption (ECDH→AEAD) | Pallas ECDH + ChaCha20-Poly1305 | Shor breaks ECDH | **Yes — historical memos decrypt** |
| Halo2 proof | Pallas/IPA | Shor broken | None — a historical proof's public soundness failure doesn't leak secret inputs; the inputs were hashes to begin with |

**Key observation**: the chain stores **only hashes and proofs** — no ciphertexts of secret values. The sole HNDL-vulnerable artifact is the per-note memo ciphertext, and even that only reveals the `(d, value, rseed)` of that one note.

Compare to an account+ElGamal design, where **every historical balance** is a ciphertext and Q-day decrypts the entire historical balance ledger.

**PQ migration for the chain itself**: swap proof system (Phase 2). The note tree, nullifier scheme, spend-auth scheme all lift straight to the new primitives.

**PQ migration for the wallet channel**: swap note-encryption ECDH → ML-KEM hybrid. Independent, wallet-side.

### 6.2 Phased roadmap

Capability-gated (availability of production PQ libraries), not date-gated.

#### Phase 0 — v1 (now)
Only `scheme_id` plumbing. No PQ code.

#### Phase 1 — `scheme_id = 0x02` hybrid spend authorization
**Trigger**: production-grade ML-DSA-65 (Dilithium3) C/C++ library with constant-time verify + credible ≤10 yr CRQC estimate.

- Spend-auth signature = Schnorr-on-Pallas **AND** Dilithium3. Both verify on every spend.
- `rk` field extended to carry both pubkeys (32 + 1952 = 1984 B).
- Tx grows by ~3.3 KB per spend.
- Note encryption and proof system unchanged.
- HNDL still applies to memo encryption and (minimally) to the proof system.

#### Phase 2 — `scheme_id = 0x03` PQ-confidential
**Trigger**: Plonky3/STARK verifier stable in C++ + ML-KEM production-ready + industry PQ momentum.

- Proof system: **Plonky3** (STARK over Goldilocks field), hash-only, PQ-safe.
- Note encryption: **ML-KEM (Kyber)** hybrid with existing ECDH.
- Spend-auth signature: hash-based (SPHINCS+ or a Merkle-signature scheme).
- Tx grows to ~30–80 KB (STARK-dominated).

**Honest note on v1 → Phase 2 note continuity.** The v1 commitment tree uses Poseidon2 parameterized over the Pallas base field `Fp`. Phase 2's STARK proves statements over Goldilocks. Two options, each with a cost:

1. **Non-native field emulation**: prove Poseidon2-over-Fp inside a Goldilocks STARK. v1 notes remain directly spendable; proving is 10–100× slower for the Merkle-path subcircuit. Acceptable if the rest of the circuit dominates.
2. **Forced note migration**: a one-time `priv_migrate` tx type unshields a v1 note and re-shields it into a Goldilocks-parameterized v3 tree. The v3 tree uses Poseidon2-over-Goldilocks natively. Fast proving but users must perform a migration tx per note.

We do not pick between (1) and (2) in v1 — that choice depends on benchmarks of Plonky3-with-field-emulation when the Phase 2 trigger fires. **What we commit to in v1**: the note-commitment content is `Poseidon2(repr(d), repr(pk_d).x, repr(pk_d).y, value, rcm)`, a pure hash — so under either option, the semantic content of a v1 note can be carried forward. The engineering path is the open question; the cryptographic continuity is not.

This replaces the earlier (optimistic) claim that "v1 commitments are directly spendable under Phase 2." They are *convertible*, with either a proving-cost or a migration-tx cost.

#### Phase 3 — freeze legacy schemes
**Trigger**: credible imminent CRQC (≤ 2 yr), or discovered HNDL activity, or governance vote.

- Chain rejects new Transfer with `scheme_id ∈ {0x01, 0x02}`.
- State remains queryable; unmigrated notes become permanently unspendable (owners should have migrated in Phase 2).

### 6.3 Invariants v1 locks in for the PQ roadmap

1. Every on-chain artifact carries `scheme_id`. Phase 2 validators reading a Phase 0 commitment know instantly.
2. Fiat-Shamir transcripts (Poseidon2-sponge based) absorb `scheme_id` as their second field (§2.0). No cross-scheme proof replay is possible under any byte-level collision.
3. Verifier dispatch: `(workchain_id, scheme_id) → handler`. Unknown id = deterministic reject.
4. **Hash-based backbone**: tree, nullifiers, commitments use Poseidon2 in v1 already. These survive Phase 2 unchanged.
5. **Wire format reserves room**: `scheme_id = 0x02` needs +3.3 KB per spend, `0x03` needs +50 KB per tx. v1 wire format does not hard-cap tx size at v1 typical sizes; the TOS external-message envelope supports much larger.

---

## 7. Execution Pipeline

Trace of one `uno_sendTransfer`:

| Step | File | Purpose |
|---|---|---|
| 1 | `validator-engine/json-rpc-server-uno.cpp` | Decode hex / JSON, sanity-check. |
| 2 | `crypto/block/uno-workchain/transaction.cpp::decode_transfer()` | Parse wire → `Transfer` struct. |
| 3 | same | Pre-flight cheap validation (§4.3 step 1) without state. |
| 4 | `json-rpc-server-uno.cpp` | Wrap as external message to `(wc=2, executor)`; submit via `liteServer_sendMessage`. |
| 5 | Collator admission | Standard TOS external-message pool. |
| 6 | `crypto/block/transaction.cpp` (modified) | On the executor account, invoke `uno_workchain::invoke_compute()` via the `case 2:` dispatch branch. Called once per tx in block-order. |
| 7 | `crypto/block/uno-workchain/compute-phase.cpp::run_compute_phase()` | For each tx: `verify_transfer` → if Ok, `apply_transfer`. Verify-before-mutate. In-memory state mutates; nothing written to cells yet. |
| 8 | End-of-block hook (installed by `uno_workchain::init`) | After the last tx: `state.anchor_window.push(state.commitment_tree_root)`. Last in-memory mutation of the block. |
| 9 | `crypto/block/uno-workchain/cell-state.cpp::serialize()` | Serialize the fully-mutated `UnoShardState` into executor `StateInit.data` — one serialization per block, not per tx. |
| 10 | TOS block commit | CellDb `WriteBatch` — atomic across all cells touched this block. |

One serialization per block, one WriteBatch per block. Every `Transfer` contributes to the same final serialization. There is no pending-state concept; the entire block is either persisted or not, atomically.

---

## 8. TOS Core Integration

Following the EVM workchain's dispatch pattern (`crypto/block/evm-workchain-dispatch.{h,cpp}` + routing in `transaction.cpp`).

### 8.1 New dispatch module

`crypto/block/uno-workchain-dispatch.{h,cpp}`:

```cpp
namespace uno_workchain {

using ComputeHandler = std::function<bool(
    block::ComputePhase& cp,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32])>;

void set_compute_handler(ComputeHandler h);
bool has_compute_handler() noexcept;
bool invoke_compute(
    block::ComputePhase& cp, vm::CellSlice& body,
    uint64_t gas_limit, uint64_t seqno, uint64_t ts,
    const uint8_t rand_seed[32]);

}
```

### 8.2 Routing patch

`crypto/block/transaction.cpp::prepare_compute_phase()`:

```cpp
switch (account.workchain) {
  case 1:
    if (evm_workchain::has_evm_compute_handler())
      return evm_workchain::invoke_evm_compute(cp, body, gas_limit, seqno, ts, rand_seed);
    break;
  case 2:
    if (uno_workchain::has_compute_handler())
      return uno_workchain::invoke_compute(cp, body, gas_limit, seqno, ts, rand_seed);
    break;
}
// fallthrough to TVM for wc=0
```

Parallel with evm-workchain dispatch; no shared registry. The rule-of-three trigger to unify into a single `map<WorkchainId, ComputeHandler>` is the arrival of a third non-TVM workchain (wc=3).

### 8.3 Initialization

`validator-engine/validator-engine.cpp`, near the existing EVM init call:

```cpp
uno_workchain::init(db_root);
```

This:
1. Registers the compute handler.
2. Loads (or zero-inits from genesis) the wc=2 executor account's `UnoShardState`.
3. Installs the end-of-block hook that pushes the current commitment-tree root into the anchor window.
4. **Pre-loads the Halo2 verifier key (M3)** into a process-lifetime `static const` structure. The VK for the v1 Transfer circuit is known at compile time; pre-loading avoids per-tx key-parse overhead (~1 ms/tx saved) and guarantees that verify cost is memory-bandwidth bound, not parse-time bound.
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

New `uno_*` namespace, served from `validator-engine/json-rpc-server-uno.cpp`, registered alongside `eth_*` methods.

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

### 10.2 Chain config (ConfigParam 26, new)

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

**After genesis, note plaintexts are never on-chain.** The publication of genesis plaintexts is an intentional transparency trade for v1 — initial distribution is auditable; no other plaintext value is ever on chain.

Zerostate is the **only** source of native tokens in v1. No minting, no Shield, no inflation.

### 10.4 Chain id

- Testnet: e.g. `0x554E4F54` (`"UNOT"`).
- Mainnet: TBD by network ops.
- Bound in every tx's transcript (§2.0) → no cross-network replay possible.

---

## 11. Build and Module Layout

### 11.1 New directory: `crypto/block/uno-workchain/`

```
uno-workchain.h                // wc id, chain id constants, sizes, domain-sep strings
uno-workchain-dispatch.{h,cpp} // callback registry (§8.1)
init.{h,cpp}                   // node-startup entry point (§8.3)
transaction.{h,cpp}            // Transfer / SpendDescription / OutputDescription wire codec
compute-phase.{h,cpp}          // verify_transfer + apply_transfer (§4.3)
state.{h,cpp}                  // in-memory UnoShardState struct
cell-state.{h,cpp}             // State ↔ cell serializer (§5)
cell-codec.{h,cpp}             // raw TLV: Transfer body, note desc encodings
commitment-tree.{h,cpp}        // incremental Merkle tree over Poseidon2 (§5.2)
nullifier-set.{h,cpp}          // vm::Dictionary wrapper (§5.3)
anchor-window.{h,cpp}          // ring buffer (§5.4)
config-param.{h,cpp}           // ConfigParam 12 + 26 builders, build_zerostate
rpc.{h,cpp}                    // `uno_*` method handlers
crypto/
  pallas.{h,cpp}               // Pallas curve ops (port / FFI to pasta_curves)
  poseidon2.{h,cpp}            // Poseidon2 over Fp(Pallas)
  schnorr-pallas.{h,cpp}       // Schnorr on Pallas (spend-auth + binding)
  halo2-verifier.{h,cpp}       // Halo2 IPA verifier (v1: FFI to Rust; v2: native C++)
  stealth-address.{h,cpp}      // EIP-5564-style key derivation
  note-encryption.{h,cpp}      // ECDH + ChaCha20-Poly1305 AEAD for note ciphertexts
CMakeLists.txt
```

### 11.2 External / ported dependencies

- **pasta_curves** (Pallas / Vesta): upstream Zcash implementation. Port critical paths to C++ or FFI into validator.
- **Poseidon2**: reference implementation, ~500 LoC. Port in-house.
- **Halo2 verifier**: extracted from Zcash's `halo2` Rust crate. V1 strategy: validator links a small Rust verifier lib via FFI. V2: pure C++ rewrite scoped to our single circuit.
- **ChaCha20-Poly1305 AEAD**: already in avatar; reuse.
- **BLAKE3**: already in repo, retained for cell hashing and non-circuit content addressing.

### 11.3 CMake

`crypto/block/uno-workchain/CMakeLists.txt`:

```cmake
set(UNO_WORKCHAIN_SRC
  uno-workchain-dispatch.cpp
  init.cpp
  transaction.cpp
  compute-phase.cpp
  state.cpp
  cell-state.cpp
  cell-codec.cpp
  commitment-tree.cpp
  nullifier-set.cpp
  anchor-window.cpp
  config-param.cpp
  rpc.cpp
  crypto/pallas.cpp
  crypto/poseidon2.cpp
  crypto/schnorr-pallas.cpp
  crypto/halo2-verifier.cpp
  crypto/stealth-address.cpp
  crypto/note-encryption.cpp)

add_library(uno_workchain STATIC ${UNO_WORKCHAIN_SRC})
target_link_libraries(uno_workchain PUBLIC tos_crypto tddb ton_block uno_halo2_ffi)
target_include_directories(uno_workchain PUBLIC .)
```

Plus:

```cmake
# validator-engine/CMakeLists.txt
target_link_libraries(validator-engine uno_workchain)
```

### 11.4 TL-B schema

New file `tos/uno-tl.hpp` defining `Transfer`, `SpendDescription`, `OutputDescription`, and the wrappers for `UnoShardState` and its sub-cells.

### 11.5 Modified files (the only in-place edits)

1. `crypto/block/transaction.cpp` — add `case 2:` dispatch.
2. `validator-engine/validator-engine.cpp` — call `uno_workchain::init(db_root)`.
3. `validator-engine/json-rpc-server.cpp` — register `uno_*` method dispatch.
4. `validator-engine/CMakeLists.txt` — link `uno_workchain`.
5. Genesis / zerostate builder — add wc=2 initial shard state with seed notes.

Everything else is additive.

---

## 12. Test Strategy

Mirrors the EVM workchain's gate model.

### P.1 Primitive parity
- **Poseidon2**: test vectors from reference implementation (Grassi et al.).
- **Pallas curve**: cross-verify against `pasta_curves` Rust.
- **Schnorr-on-Pallas**: cross-verify against the Orchard Rust implementation.
- **Nullifier derivation**: cross-verify against Zcash Orchard test vectors (same scheme family).
- **Halo2 verifier**: verify proofs produced by a reference Rust prover; reject tampered proofs.
- **Note encryption**: round-trip encrypt/decrypt with known `ivk` / `ovk` vectors.

### P.2 Transaction codec fuzz
- Round-trip: build Transfer in `tosctl` (Rust), submit, decode back. Byte-identical re-serialization.
- 1 M iterations of random-bytes fuzz: no crashes, no panics, no non-deterministic decode.
- Malformed payloads: truncated proof, swapped nullifier order, invalid Pallas decompress, duplicated nf, duplicated cm, stale anchor, wrong chain_id.

### P.3 State-transition golden tests
- Deterministic fixtures: `state X + tx Y → state X'`. Assert `commitment_tree_root`, `nullifier_set_root`, anchor window post-state byte-identical.
- Include cases: valid 1-spend/1-output, 4/4 max, double-spend attempt, stale anchor, invalid proof, invalid binding sig, over-max spends, fee < min_fee, expiry exceeded.

### P.4 Restart survival
- Two-node mini-net, drive 10 K valid txs + 1 K invalid txs mixed, kill and restart both nodes. Post-restart state roots must equal pre-crash state roots.

### P.5 Cross-validator determinism
- 4-node replay: identical tx stream, randomly permuted mempool order, assert identical state roots at every block.
- Catch HashMap iteration, wall-clock dependence, float, RNG, uninitialized read.

### P.6 Client-side proving performance
- Prover latency on reference hardware: 1-spend/2-output tx ≤ 5 s on M1 MacBook Air; ≤ 3 s on 8-core x86.
- Memory footprint ≤ 2 GB during proving.

### P.7 View-key audit correctness
- Seed wallet, send 100 txs, run audit with:
  - `fvk`: recovers all incoming + outgoing notes with exact amounts.
  - `ivk` only: recovers all incoming, no outgoing.
  - `ovk` only: recovers all outgoing (via `out_ciphertext`), no incoming.
  - None: zero recovery.

### Mandatory negatives
- Replay attack: resubmit an included tx → rejected at nullifier check.
- Cross-chain replay: change `chain_id` but keep proof → rejected at transcript.
- Stale anchor (>100 blocks old) → rejected.
- Inflation attempt: hand-crafted tx with output sum > input sum → rejected at binding sig.
- Sender-linkage attack: given many `rk`s, try to cluster → no statistical advantage.
- Receiver-linkage attack: given many `(cm, epk)` pairs, try to cluster → no statistical advantage.

---

## 13. Phased Roadmap

| Phase | Deliverable | Done-when |
|---|---|---|
| **P.1** Crypto scaffolding | Pallas curve ops, Poseidon2, Schnorr-on-Pallas, stealth-address key derivation, note encryption. Test vectors pass. | Cross-reference against the published Zcash Orchard test suite and the `pasta_curves` reference implementation. |
| **P.2** Circuit + prover (Rust) | Halo2 Transfer circuit: spends 1..4, outputs 1..4, range proofs, Merkle paths, key-derivation, nullifier-correctness. Reference prover CLI in `tosctl`. | Valid proofs produce; invalid inputs fail at proving or at verify. |
| **P.3** Verifier in C++ (FFI, parallel) | Link Rust halo2 verifier into validator via minimal C ABI. **Must support parallel verification across N worker threads (N = num_cores) with deterministic output ordering — this is a release gate, not a later optimization.** Per-tx signatures and proof verifies run concurrently in the pool; state mutations remain serialized by tx order. | Verify ≤ 15 ms per 1-spend/2-output tx single-thread; ≥ 3.5× scaling on 4 cores; byte-identical state root across parallel and serial execution. |
| **P.4** State model + dispatch | `UnoShardState`, commitment-tree cells, nullifier dict, anchor window, init hook, dispatch. | Empty-state boot; no-tx blocks commit cleanly; state roots stable across restart. |
| **P.5** End-to-end compute + RPC | verify_transfer, apply_transfer, block-commit path. `uno_sendTransfer`, `uno_getAnchor`, `uno_getOutputsAtBlock`, `uno_estimateFee`, `uno_getNullifierStatus`. | Two-wallet demo: A sends to B, B scans and detects, B's fvk audit matches. |
| **P.6** Wallet (CLI via tosctl) | Key gen, address derivation, receive/scan, build+prove+send, balance from scan. | A → B → C chained; each recipient detects and spends their note. |
| **P.7** Conformance + audit + docs | Full test matrix green; one external boutique crypto audit (4–6 weeks) scoped to the Transfer circuit, key derivation, transcript composition, verifier FFI, and deterministic-reject ordering. Upstream primitives (pasta_curves, halo2 crate, Poseidon2 reference) out of scope. | Audit clean; `doc/uno-workchain-known-divergences.md` authored; 60-day stable testnet run. |

v1 release gate: all of P.1–P.7 green + 60 days of 5-validator testnet stability.

---

## 14. Explicit v2+ Items (not in v1)

- **Shield / Unshield** between wc=0 and wc=2. An escrow account on wc=0 mints into wc=2 via a one-way note-creation bridge with total-supply invariants. Requires a reserved opcode and strong accounting invariants.
- **Multi-asset**: add `asset_id: bits256` to `Note`; per-asset nullifier scoping; per-asset balance proofs (extends binding sig). Asset registry on masterchain.
- **Programmable privacy (Aleo/Aztec-class)**: user-supplied circuits over notes. Requires a zkVM scoped to our circuit framework.
- **Shielded DEX (batch-auction design)**: periodic batch clearing with concealed amounts and prices; no continuous public order book.
- **Proof aggregation**: one Halo2 recursive proof covers N Transfers; halves bandwidth, enables higher throughput.
- **Compact block filters**: per-block Bloom-like filters to accelerate wallet sync without server trust.
- **Stealth-address discovery (opt-in)**: senders DM recipients asynchronously without exposing sender identity.
- **Post-quantum migration** (§6 phases 1–3).
- **Sharding wc=2**: non-trivial — the commitment tree is global, so sharding requires either multiple independent pools or a recursive cross-shard inclusion proof. Research item.

---

## 15. Design Choices Record

Every non-trivial choice below was made against the alternative space of published shielded-pool constructions. The column "Alternative considered and rejected" is included so a reviewer can see the design was chosen, not inherited.

| Dimension | Our choice | Alternative considered and rejected |
|---|---|---|
| Curve | **Pallas/Vesta** | Decaf377 / BLS12-377: requires per-circuit trusted setup under Groth16. BN254: same. |
| Proof system | **Halo2 (IPA)** | Groth16 (per-circuit ceremony); Varuna (universal ceremony); STARK (too slow at prover side for v1 wallet UX). All ceremony-requiring systems rejected on decentralization grounds. |
| Hash | **Poseidon2** | Poseidon v1 (slower, same security); Keccak/BLAKE3 (non-arithmetic, expensive in-circuit). |
| Tree depth | **32** (≈ 4 B-leaf cap) | Depth 24 tested in other systems; rejected as too tight for long-term growth. |
| Address model | **Orchard-style diversifiers + EIP-5564 compatible stealth posture** | Single-key addresses (Monero-family stealth) rejected as less flexible than diversifier hierarchies. |
| Spend auth | **Randomized Schnorr-on-Pallas** | Direct Schnorr without randomization (leaks owner identity across spends). |
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

---

## 16. Decisions Log

1. **Architecture — decided: shielded note pool.** Terminal privacy properties (sender/receiver/graph unlinkability) require a pool model. Account+ElGamal is rejected as a local optimum with a 2-year shelf life.
2. **Curve — decided: Pallas/Vesta.** No trusted setup; pair-cycle supports future recursive-proof aggregation.
3. **Proof system — decided: Halo2 IPA.** No ceremony; mature tooling; ~2–5 s wallet proving.
4. **Hash — decided: Poseidon2.** Arithmetic-friendly; modern parameterization.
5. **Address hierarchy — decided: Orchard + EIP-5564.** View-key tiers built in.
6. **Single-executor — decided: yes.** TOS AccountBlock invariant; zero per-user state.
7. **No accounts on chain — decided: yes.** Chain tracks notes and nullifiers only. Dust attacks and storage rent vanish.
8. **Crypto-agility — decided: `scheme_id` on every artifact.** 1 byte; no future hardfork for migration.
9. **PQ posture — decided: plumb only, ship nothing.** Phase 1/2/3 in §6.
10. **Trusted setup — decided: never.** Hard requirement.
11. **Max spends/outputs — decided: 4 / 4.** Size/time balance.
12. **Single asset — decided: v1 only.** Multi-asset in v2.
13. **Client-side proving — decided.** No prover server.
14. **Selective disclosure — decided: view keys mandatory in v1.**
15. **Anchor window — decided: 100 blocks.**
16. **No bridges in v1.** Initial supply from zerostate only.
17. **Genesis plaintext publication — decided: exceptional, one-time, zerostate only.**
18. **Dispatch shape — decided: parallel to evm-workchain-dispatch.** Unify to a registry when wc=3 arrives.
19. **Fee model — decided: plaintext fee, burned in v1.** No plaintext currency on wc=2; miner economics are a v2 concern.
20. **Genesis activation — decided: no hardfork.** TOS hasn't launched; wc=2 ships in the zerostate.
21. **Throughput posture — decided: accept low TPS.** TOS simplex consensus uses a global block rate (ConfigParam 30); per-workchain block intervals are not configurable in v1 and we do not propose extending the consensus protocol to support them. Proof aggregation moves to v2+ roadmap. v1 optimization is strictly within-block: parallel verify as a release gate (§13 P.3), nullifier LRU cache (§5.3), verifier-key pre-load (§8.3), and one reserved ref slot on the root state cell (§5.1). Expected ceiling: 15–30 TPS sustained, up to ~50 TPS burst. Intrinsic cost of terminal privacy; we don't fight it.
22. **Cell constraints — decided: we engineer around, not expand.** TOS cell limits (1023 data bits, 4 refs per cell) are Schelling points of the state layer and ecosystem tooling. We never propose increasing them. All over-sized artifacts (Halo2 proofs, ciphertexts, dictionaries, frontiers) are expressed as cell trees. Details in §17.

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
| Halo2 proof | ~10 KB | contiguous byte blob via `CellString` | ~80 | ~4 levels |
| `enc_ciphertext` (per output) | 580 B | `CellString` | ~5 | 1 level |
| Commitment-tree frontier | ~1 KB | linked chain of 32 Poseidon2 siblings | ~8 | 1 level |
| Anchor window (100 roots) | ~3.2 KB | ring buffer in a cell chain | ~25 | 1–2 levels |
| Nullifier `vm::Dictionary` at 10 M | ~500 MB | 256-bit-keyed sparse dict | ~5 M | ~24 levels |

Each cell carries ~32 bytes of representation-hash and depth metadata, so a 10 KB proof pays ~2.4 KB of cell-tree overhead (≈ 24% bloat). This is the fixed cost of persisting non-trivially-sized artifacts in the cell model; we accept it.

### 17.2 Concrete mitigations in v1

- **Nullifier LRU** (§5.3 M2) — short-circuits the 24-level dict lookup for recent entries. The single largest performance lever we have at the 1 s block cadence.
- **Compact proof serialization** — target ~8 KB per proof using Halo2's compact encoding (saves ~20% vs naïve). Concrete format pinned during P.3 (verifier FFI bring-up).
- **Reuse `CellString`** (`crypto/vm/cells/CellString.h`) for contiguous byte arrays (proofs, ciphertexts). Avoids hand-rolling cell-chain code; consistent with the rest of the codebase.
- **Reserved root-cell ref** (§5.1) — one of the four refs on `UnoShardState` is intentionally unused, giving v1.1 / Phase 1 / v2 a single-ref budget to add state without a cell-schema migration.

### 17.3 Implication for future schemes

Phase 2 (`scheme_id = 0x03`, STARK-based) will produce larger proofs — estimated 30–80 KB per tx. At current cell limits that is 240–640 cells per proof. Still tractable, but it shifts the scaling frontier to **cell count per tx**, not inline bit width. Phase 2 circuits should be designed with wide fan-out (use all four refs per internal node) to keep walk depth bounded.

**Cell-tree depth, not cell size, is the scaling axis we design against.** Any future artifact that cannot tolerate a ≥ 5-level walk against very large data must be pre-structured with the 4-ref fan-out in mind, never by requesting larger cells.

---

## 18. References

**Cryptographic primitives we adopt directly (published standards, standard vocabulary):**
- **Zcash Orchard** (ZIP 224, `halo2` Rust crate): the published specification we port for the nullifier scheme, diversified-address hierarchy, randomized spend authorization, and note encryption. We cite this the way a networking document cites TLS 1.3 — a published standard we implement faithfully, not a project we follow.
- **EIP-5564** (stealth addresses): industry-standard stealth-address scheme; our address posture is compatible.
- **Grassi, Khovratovich, Schofnegger (2023)**: Poseidon2 specification.
- **Bowe, Grigg, Hopwood (2019–2023)**: Halo / Halo2 proof system line.
- **`pasta_curves`** (public Rust library): Pallas/Vesta curve constants and arithmetic reference.

**Systems considered and not adopted:**
- Ring-signature-based shielded systems (UTXO + ring CT): rejected as structurally inferior to note-commitment + nullifier for anonymity set growth.
- Hardware-enclave privacy (SGX-family): rejected due to extensive side-channel vulnerability history.

**In-house references:**
- **`~/x`**: prior art within the team; we do not clone its account model.
- **`~/avatar`**: in-house pure-C cryptography base; source for Poseidon2 and Pallas-arithmetic C wrappers.
- **`~/e`**: in-house PQ-signature reference for Phase 1 (Dilithium3, Falcon512, SPHINCS+).
