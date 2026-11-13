# Consensus conformance

Two parts: the `consensus` harness, for the parts of consensus that are pure functions of explicit inputs,
and the network scenario runner, for the behaviour that is not.

## The `consensus` harness

`ref/harness-consensus.cpp` calls the node's own functions; the context field `op` selects one operation.
Every effect is one outcome, or `{"outcome": "refused", "reason": <class>}` when node code refused the
input. The class comes from a fixed table over the node's messages (`kReasonRules`), so two
implementations must agree on the class of a refusal, not on its wording; a message no rule matches is
`unclassified`, which shows up as a fixture diff the day a message changes.

| Op | Context | Effect | C++ behind it |
|---|---|---|---|
| `quorum` | `total_weight`, `signed_weight` (u64 decimals) | `threshold`, `has_quorum` | `tos::quorum_threshold` (checked equal to the portable form), `tos::has_quorum` |
| `weight_total` | `weights` | `total`, or refused `weight_refused` | `tos::checked_add_validator_weight` |
| `protocol_version` | `protocol_version` | the five Simplex version predicates, `max_supported` | `tos::NewConsensusConfig` |
| `validator_set` | `validators`, `catchain_seqno`, `shard` | `validator_set_hash` (the short hash block headers carry), `total_weight`, `threshold` | `block::ValidatorSet` |
| `session` | `global_id`, ConfigParam 29 `options`, `simplex_config_hash`, `shard`, `catchain_seqno`, `vertical_seqno`, `last_key_block_seqno`, `validators` | `options_hash`, `session_config_hash`, `session_id` | `block::validator_session_options_hash`, `block::derive_validator_session_identity` |
| `vote` | `session_id`, `slot`, `candidate` (TL `consensus.CandidateHashData`), `final`, `block`, optional `public_key` + `signature` | `candidate_hash`, `data_to_sign`, `signature_check` (`valid`/`invalid`/`malformed`/null) | `BlockSignatureSet::build_simplex_data_to_sign`, ML-DSA-44 under the Simplex signing context |
| `finality` | trusted `validators`, `catchain_seqno`, `block`, `expected_session_id`, `role`; the signatures of a `block_proof`, or an explicit `signature_set` (+ optional `claimed_weight`) | `weight`, `total_weight`, `threshold` | `BlockSignatureSet::fetch` / `create_simplex_pq_*`, `tos::validator::verify_pq_proof_signatures`, `block::verify_pq_finality` |
| `decode_proof` | `block_proof` | block id, `state_old_hash`, `state_hash`, decoded `signature_set`, `claimed_weight` | `BlockProof` parse, Merkle header as `CheckProof` reads it, `BlockSignatureSet::fetch` |
| `key_block_context` | `key_block` + `key_block_proof`, `block` + `block_proof` | governing context: global ids, options, selected ConfigParam 30, header fields, computed validator set and its hash, `session_id` (lite proof path), `validator_path_session_id` (validator path), decoded signatures | `block::Config::extract_from_key_block`, `compute_validator_set`, `derive_validator_session_identity`, `tos::validator::detail::derive_pq_finality_context` |
| `proof_link` | `key_block` + `key_block_proof`, `block` + `block_proof`, `is_key` | `gen_utime`, `expected_session_id`, `verified_weight`, `total_weight` | `block::BlockProofLink::validate` (forward link) |

Validators are descriptors as the node holds them after decoding a set: post-quantum
`{validator_id, key_id, algorithm_id, public_key, weight, adnl}` or classical `{ed25519, weight, adnl}`.
A list the decoder would refuse (zero weight, total above the protocol cap, a repeated identity) is a
harness error, because `block::ValidatorSet` aborts on it.

### Families (`vectors/consensus/fixtures/`)

| Family | Fixtures | Source |
|---|---|---|
| `quorum` | 59 | authored boundaries (0..10 equal validators, 100..102, the protocol cap, 2^64-1, signed above total) |
| `weight-total` | 7 | authored (empty, zero weight, exactly the cap, above it) |
| `protocol-version` | 6 | RTOS `simplex-protocol-predicates.tsv` (versions 0-4, values as expectations) + 2^32-1 |
| `validator-set` | 8 | real: the validator sets the epoch-5 proofs were checked against |
| `session` | 27 | 8 real + 19 authored variants (each constructor and options-hash branch, other network, config, catchain seqno, key block, member order, classical members) |
| `vote` | 84 | 24 real signatures (every signer of the 8 real certificates), 8 authored mutations, 52 converted RTOS rows (`pq-finality`, `live-pq`, `live-pq-chain` notarize/finalize rows) |
| `finality` | 47 | 16 real (each block through its proof and as an explicit set), 22 authored mutations of a real certificate, 9 on the RTOS two-validator set |
| `decode-proof` | 11 | real: 8 block proofs and 3 key-block proofs |
| `key-block-context` | 8 | real |
| `proof-link` | 13 | 8 real + 5 authored refusals |

Real material: `migrate/consensus_contexts.py contexts` reads masterchain block proofs and key-block
proofs from a validator's package directory of the public-testnet epoch-5 archive (blocks 117750, 117751,
117900 and 118200 of the REL-02 replay window, key block 119620 and 119621, key block 124028 and 124029;
governed by key blocks 88656, 119620 and 124028). The archive is read only and is not needed afterwards:
the fixtures carry the proofs (as blobs).

Authored mutations of the real certificate: a signer dropped one at a time down to the empty set (the
fixtures show weight falling below the threshold), a duplicate signer, a claimed weight off by one, no
claimed weight, a tampered and a truncated signature, an unknown signer, an unadmitted algorithm, a wrong
expected session, signatures made in another session, a wrong catchain seqno, a wrong set hash, a changed
validator weight or key id (the set commitment covers both), a wrong block, the approve role for final
signatures, the set of a later election, a mixed classical/PQ set. On the RTOS two-validator set, whose
commitment can be recomputed: a rotated (expired) key, a key id not derived from the key, unequal weights.

Every authored or converted fixture carries its expectation in `metadata.note` (`{"expect": {...}}`, a
partial effect). The effects come from the reference; `consensus_contexts.py check` (ctest
`conformance-consensus-crosscheck`) requires every expectation to hold and the families to agree with
each other: the lite and validator session derivations, the raw `session` derivation and the session the
chain's certificate carries are one value; the computed validator set hash is the header's; the header's
global id is ConfigParam 19; `decode_proof` and `key_block_context` decode the same certificate; no two
authored session variants collide with each other or with a real session.

Regenerating (from a clean, committed reference build):

```
python3 test/conformance/migrate/consensus_contexts.py contexts --reference build/test/conformance/conformance-ref-cli \
    --archive <epoch-5 node package directory> --rtos <dir with the five RTOS files> --out <scratch>
for f in <scratch>/*.contexts.jsonl; do family=$(basename $f .contexts.jsonl)
  python3 test/conformance/runner/conformance.py create --reference build/test/conformance/conformance-ref-cli \
      --harness consensus --family $family --source authored $f test/conformance/vectors/consensus/fixtures/$family.jsonl
done
```

(`--source` is per family: `replay` for the real families, `migrated:rtos/...` for converted ones; the
script prints the counts.)

### Not a pure function, so not in the harness

- Leader schedule (`SimplexCollatorSchedule`: `slot / slots_per_leader_window % validators`) and skip-vote
  and candidate signing data: pure, but they live in the consensus library behind the actor bus; reaching
  them needs that library or a restatement. The RTOS `live-pq` skip and candidate rows are therefore not
  converted.
- Vote pool state, certificate formation, notarization/finalization timing, skip on timeout, leader
  windows under desync, standstill, rate limits, bans: they depend on arrival order and time.
- Catchain/overlay delivery, block sync, state download, restart recovery from the signing ledger, key
  rotation in a running group, observer behaviour.
- Collation and block validation (block layer, a separate harness).
- `live-pq-node.json` (needs a config-to-set path over its own config BOC) and
  `finality-broadcast-vector.tsv` (a full-node overlay wire encoding: TL/network, not consensus).

These belong to scenarios.

## Network scenarios (`scenarios/run_scenarios.py`)

A Hive-style runner over the repository's local-network tooling (`test/tostester`). Each node's
implementation is a parameter: `--node cpp:<validator-engine>` or `--node adapter:<launcher>`, once for all
nodes or once per node. An adapter is any executable that accepts the validator-engine command line
(`--global-config`, `--local-config`, `--db`, `-v`, the engine flags) and speaks the same lite-server, DHT
and validator protocols; that command line is the whole contract.

Scenarios, each on a fresh network: `bootstrap` (all nodes from Genesis), `restart` (node 2 stopped after
K/2 blocks, the rest go on, it is started again), `late-join` (the last node started only after K/2
blocks). The runner asserts hashes for masterchain blocks 1..K:

- the block id every node's lite-server serves is the same on every node;
- the state root each node applied (the new-state hash of the Merkle update in the proof it stored) is the
  same on every node;
- every node stored a finality certificate naming the same session, slot and candidate; its signatures
  verify (through `conformance-ref-cli`, `vote` op) and its signers reach the quorum threshold.

`--expect-block <seqno>=<root hash>` and `--expect-state <seqno>=<state root>` pin values (a control: a
wrong pin must fail the run). Each run goes to a new `<work-dir>/run-<n>` with a JSON report. Node
databases must be on an SSD (the runner refuses a rotational disk).

```
uv run python test/conformance/scenarios/run_scenarios.py --build-dir build --source-dir . \
    --work-dir build/conformance-network --node cpp:build/validator-engine/validator-engine --nodes 4
```

ctest: `conformance-network-scenarios`, label `conformance-network` (not run by `-L conformance`).
Binaries needed: `validator-engine dht-server create-state generate-random-id tos-pq-consensus-key
toslibjson gen_fif conformance-ref-cli`, and `uv run test/tostester/generate_tl.py` once.
