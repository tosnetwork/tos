# Uno Workchain — Transaction Lifecycle Topology

Complete data flow for a shielded `Transfer` on `wc=2`, from the sender's
wallet through RPC admission, mempool, validator compute phase, end-of-block
persistence, and recipient-side scan. Every stage lists the concrete entry
point, the corresponding source file, and the design-doc section that pins
its invariants.

See [`doc/uno-workchain.md`](uno-workchain.md) for the underlying protocol
(referred to as "§x.y" throughout).

## Topology Diagram

```
┌──────────────────────────────────────────────────────────────┐
│  Sender Wallet / Client                                      │
│  tosctl uno send         (tosctl/uno/src/send.rs)            │
│                                                              │
│  [1] Select input notes (coin-selection on wallet index)     │
│  [2] Fetch current anchor + tree frontier + per-output       │
│      sibling hashes via uno_getAnchor / uno_getFrontier      │
│  [3] Build witness (SpendWitness per input):                 │
│        • note opening   (d, pk_d, ivk_commitment, value, rcm)│
│        • 32-level Merkle path + position                     │
│        • nullifier pre-image (nk, cm, pos)                   │
│        • outputs: (d, pk_d, ivk_commitment, value, rcm)      │
│      See §4.2 claims 1–8 for what the AIR proves.            │
│  [4] Run Plonky3 prover LOCALLY                              │
│      uno_plonky3_ffi::prove (uno/plonky3-ffi/src/prover.rs)  │
│      Production FRI params: log_blowup=2, num_queries=128,   │
│      query_pow_bits=16 (§2.1, K-FRI-production).             │
│  [5] Per-spend Schnorr spend-auth:                           │
│      rsk ← random; rk = rsk·G; sig = Schnorr(rsk, tx_hash)   │
│      — fresh per-spend key, no long-term ak (§2.5, #31)      │
│  [6] Serialize Transfer (TLV: header + spends + outputs +    │
│      zk_proof cell)                                          │
│      encode_transfer (uno/core/transaction.cpp + Rust codec) │
└──────────────────────────────────┬───────────────────────────┘
                                   │
                                   │  Transfer TLV over JSON-RPC
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────┐
│  RPC Node / Full Node                                        │
│  validator-engine/json-rpc-server.cpp                        │
│                                                              │
│  [7]  Method dispatch: uno_sendTransfer                      │
│       uno::rpc::handle_send_transfer                         │
│       (uno/rpc/handlers.cpp)                                 │
│  [8]  Decode wire: decode_transfer()                         │
│       (uno/core/transaction.cpp)                             │
│       — rejects malformed TLV, over-large S/O counts         │
│  [9]  Admission pre-filter (§4.3a, cheapest-first):          │
│         a. Byte-shape envelope                               │
│            • len(zk_proof) ∈ [PROOF_MIN, PROOF_MAX]          │
│            • len(PI) == 64 + 64·S + 72·O (§4.3 step 4)       │
│            • expiry_block > now, ≤ EXPIRY_MAX                │
│         b. Cheap syntax (version, scheme_id, chain_id, fee)  │
│         c. Nullifier LRU read-only check                     │
│         d. spend_auth_sig verify (~1 ms × S)                 │
│         (!) Plonky3 proof verify is DEFERRED to compute      │
│             phase — admission never pays that cost.          │
│  [10] Wrap as external message addressed to the wc=2         │
│       executor account (workchain=2, account=0x…0001, §5.0)  │
│       uno_workchain_dispatch namespace, marker cell 0x55 'U' │
└──────────────────────────────────┬───────────────────────────┘
                                   │
                                   │  external_message cell → mempool
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────┐
│  Collator / Validator                                        │
│  validator-engine + crypto/block/                            │
│                                                              │
│  [11] Mempool → block candidate assembly (collator selects   │
│       txs for inclusion; per-IP rate limit, §4.3a)           │
│  [12] Compute-phase dispatch:                                │
│       prepare_compute_phase()                                │
│         → workchain_id == 2 branch                           │
│         → invoke_uno_compute()                               │
│         (crypto/block/uno-workchain-dispatch.{h,cpp})        │
└──────────────────────────────────┬───────────────────────────┘
                                   │
                                   │  (UnoState&, const Transfer&)
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────┐
│  wc=2 Compute Phase / Uno Logic                              │
│  uno/core/compute-phase.cpp                                  │
│                                                              │
│  [13] run_compute_phase(state, txs):                         │
│         — per-tx verify delegated to ParallelVerifyPool      │
│           (uno/core/parallel-verify.cpp, §13 P.3)            │
│         — results returned in input order; apply loop        │
│           runs serially in declared tx order                 │
│                                                              │
│  [14] verify_transfer(state, tx)  — §4.3 full order:         │
│         a. Cheap syntax checks                               │
│            (version, scheme_id, chain_id, fee, expiry,       │
│             distinct nf within tx, nf/cm well-formed)        │
│         b. Anchor in window (§2.3, 100-block ring)           │
│         c. For each spend:                                   │
│              • Ristretto rk decompression                    │
│              • nullifier NOT in cell-dict (full check,       │
│                unlike the admission-side LRU-only read)      │
│              • Schnorr spend_auth_sig verify under rk        │
│         d. Plonky3 proof verify                              │
│            (uno::crypto::Plonky3Verifier::verify via FFI     │
│             — uno_plonky3_verify in                          │
│             uno/plonky3-ffi/src/verifier.rs; corrosion-rs    │
│             wires the .a into uno_workchain PUBLIC)          │
│         Any failure → deterministic reject; zero state delta.│
│                                                              │
│  [15] If verify_transfer == Ok:                              │
│         apply_transfer(state, tx)                            │
│           • append each output.cm as a new leaf of the       │
│             commitment tree (§3.2, commitment-tree.cpp)      │
│           • insert each spend.nf into nullifier-set dict     │
│             and update nullifier LRU (§3.4,                  │
│             nullifier-set.cpp)                               │
│           • record each output.filter_tag into the block     │
│             filter accumulator (§2.8, block-filter.cpp)      │
│           • stats.burned_fees += fee                         │
│           • stats.tx_count += 1                              │
│           • stats.note_count += output_count                 │
│                                                              │
│  [16] If verify_transfer != Ok:                              │
│         record TxRejected with the specific reject reason;   │
│         do NOT touch state. Verify-before-mutate is a hard   │
│         invariant (§4.3 step 5, §5.7).                       │
└──────────────────────────────────┬───────────────────────────┘
                                   │
                                   │  end-of-block commit
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────┐
│  Block Close / Persistence                                   │
│  uno/core/compute-phase.cpp + uno/core/cell-state.cpp        │
│                                                              │
│  [17] Push new commitment-tree root into 100-block           │
│       anchor_window ring (§2.3, anchor-window.cpp)           │
│  [18] Compile block filter:                                  │
│         dedup + sort 16-bit filter_tags from all outputs     │
│         in the block, Golomb-Coded Set encoding (§2.8)       │
│         emit via uno_getBlockFilter                          │
│  [19] serialize_state(UnoShardState) → cell tree             │
│       (uno/core/cell-state.cpp)                              │
│  [20] CellDb WriteBatch atomic commit (masterchain           │
│       picks up the new state root in its next round)         │
│                                                              │
│  [21] End-of-block subscription hooks fire:                  │
│         uno_transfer_included (per-tx)                       │
│         uno_new_anchor       (once per block)                │
│         uno_block_filter     (GCS payload)                   │
│       subscribers receive live events via json-rpc           │
│       eventstream (ws)                                       │
└──────────────────────────────────┬───────────────────────────┘
                                   │
                                   │  new anchor + filter available
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────┐
│  Recipient Wallet / Receiver                                 │
│  tosctl uno scan              (tosctl/uno/src/scan.rs)       │
│                                                              │
│  [22] Poll uno_getBlockFilter for every new block            │
│       (or subscribe to uno_block_filter eventstream)         │
│  [23] Compact-filter match: compute the wallet's 16-bit      │
│       filter_tag for each diversifier it owns; check         │
│       against the block's GCS. Hits are trial-decrypt        │
│       candidates — no false negatives, ~2⁻¹⁶ false-positive  │
│       rate per tag (§2.8).                                   │
│  [24] For each hit: fetch the OutputDescription via          │
│       uno_getOutputsAtBlock; run hybrid-KEM decap:           │
│         • ECDH(ivk, epk) on Ristretto255                     │
│         • ML-KEM-768 decap with sk_mlkem                     │
│         • split-KDF combiner (§2.7, eprint 2025/1444)        │
│         • ChaCha20-Poly1305 AEAD open over enc_ciphertext    │
│  [25] On successful decrypt: recover Note plaintext          │
│       (d, value, rseed, memo); recompute cm and match        │
│       against cm published on-chain (consistency check);     │
│       index the note as "spendable" with (pos, rseed,        │
│       ivk_commitment) — ready for future spends.             │
│  [26] Update local balance view; emit wallet event to UI.    │
└──────────────────────────────────┬───────────────────────────┘
                                   │
                                   ▼
                               Complete
```

## What the on-chain observer sees at each stage

The design intent is that each stage leaks a minimum of metadata. Everything
not listed below is private to the sender–recipient pair (§4.4).

| Stage           | Public (on-chain / over-wire)                                    | Private (never leaves sender)                     |
|-----------------|-------------------------------------------------------------------|----------------------------------------------------|
| [1]–[6] wallet  | —                                                                 | notes, ivk, nk, ovk, sk_mlkem, witness, prover RNG |
| [7]–[10] RPC    | `Transfer` wire bytes to admitting node only                      | —                                                  |
| [11]–[16] compute | `scheme_id, chain_id, expiry, fee, anchor, per-spend (nf, rk), per-output (cm, epk, filter_tag), zk_proof`; tx size / S / O counts | amounts, sender identity, receiver identity, tx graph |
| [17]–[21] commit | new `commitment_tree_root`, `nullifier_set` delta, block filter   | —                                                  |
| [22]–[26] scan  | —                                                                 | recipient diversifier match, decrypted note        |

## File / symbol index

| Stage | Primary file(s)                                           | Key symbol(s)                                     |
|-------|-----------------------------------------------------------|---------------------------------------------------|
| 1–6   | `tosctl/uno/src/send.rs`                                  | `TransferWitness::build`, `plonky3_prove`         |
| 1–6   | `uno/plonky3-ffi/src/{prover,transfer_air,permute}.rs`    | `uno_plonky3_prove`                               |
| 1–6   | `uno/core/transaction.cpp`                                | `encode_transfer`                                 |
| 7–9   | `validator-engine/json-rpc-server.cpp`, `uno/rpc/handlers.cpp` | `uno_sendTransfer` dispatch                  |
| 8     | `uno/core/transaction.cpp`                                | `decode_transfer`                                 |
| 9     | `uno/core/compute-phase.cpp`                              | `admission_precheck` (cheapest-first, §4.3a)      |
| 10–12 | `crypto/block/uno-workchain-dispatch.{h,cpp}`             | `invoke_uno_compute` (wc==2 branch)               |
| 13    | `uno/core/compute-phase.cpp`, `uno/core/parallel-verify.cpp` | `run_compute_phase`, `ParallelVerifyPool`     |
| 14    | `uno/core/compute-phase.cpp`                              | `verify_transfer` (full §4.3 order)               |
| 14d   | `uno/plonky3-ffi/src/verifier.rs`, `uno/crypto/plonky3-verifier.h` | `uno_plonky3_verify`, `Plonky3Verifier`   |
| 15    | `uno/core/{compute-phase,commitment-tree,nullifier-set,block-filter}.cpp` | `apply_transfer`                  |
| 17    | `uno/core/anchor-window.cpp`                              | `AnchorWindow::push_root`                         |
| 18    | `uno/core/block-filter.cpp`                               | `BlockFilter::finalize`                           |
| 19–20 | `uno/core/cell-state.cpp`                                 | `serialize_state`                                 |
| 21    | `uno/core/compute-phase.cpp`                              | `notify_transfer_included`, `notify_new_anchor`   |
| 22–26 | `tosctl/uno/src/scan.rs`                                  | `Wallet::scan_block`, `hybrid_kem_decap`          |

## Determinism invariants preserved along this path

- No wall-clock reads on any consensus-critical step (14, 15).
- No OS RNG reads inside `verify_transfer` / `apply_transfer`.
- No HashMap iteration order dependence; all ordered maps / sorted containers only.
- No floats anywhere in the verify or apply path.
- `ParallelVerifyPool` output is byte-identical to serial reference verify
  regardless of worker count (§13 P.3, `test-uno-parallel-verify`).
- Cross-validator state roots are byte-identical under any mempool-order
  permutation (`test-uno-determinism`, §12 P.5).
- Restart survival: serialize + deserialize state round-trip yields
  byte-identical `commitment_tree_root`, `nullifier_set_root`,
  `anchor_window` (`test-uno-restart-survival`, §12 P.4).

## Related documents

- [`doc/uno-workchain.md`](uno-workchain.md) — full protocol design (45 locked decisions)
- [`doc/evm-workchain-topology.md`](evm-workchain-topology.md) — parallel document for wc=1 EVM flow
- [`doc/openapi.yaml`](openapi.yaml) — `uno_*` JSON-RPC surface
