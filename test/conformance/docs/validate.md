## validate harness

`ref/harness-validate.cpp` runs the node's block-candidate validation, `ValidateQuery`
(`validator/impl/validate-query.cpp`, started by `run_validate_query` of `validator/fabric.h`), on one
candidate, offline. `ref/validate-offline.cpp` holds a test-only `ValidatorManager` that serves the
inputs from the context and runs the node's actor machinery in-process on a `td::actor::Scheduler` with
no worker threads, so every actor runs on the calling thread in message order; the call returns when
`ValidateQuery` reports.

What the manager serves (everything `ValidateQuery` asks for):

| Manager request | Answer |
|---|---|
| `get_top_masterchain_state_block` | the supplied state of `top_masterchain` |
| `get_block_handle` | a handle with an initialized proof, for a block whose state is supplied (else refused) |
| `wait_block_state`, `wait_block_state_short` | the supplied state of the block (previous states, the referenced masterchain state, auxiliary masterchain states) |
| `wait_block_message_queue_short` | the message queue of the supplied state of a neighbour |
| `get_out_msg_queue_size` | the entries of that queue, counted as `validator/queue-size-counter.cpp` does |
| `wait_verify_shard_blocks` | accepted (the interface default; the manager's own shard-block verification is not part of `ValidateQuery`) |
| `get_storage_stat_cache` | refused (the interface default: no cache, storage statistics are computed from the state) |
| anything else | refused and recorded, so a missing input is never answered with an invented one |

The validator set is computed from the masterchain state `validator_set_from` with
`MasterchainStateQ::get_validator_set`, as the manager computes a validator group's set; candidates are
not stored (`skip_store_candidate`) and accounts are validated in sequence (`parallel_validation` off).
Rejections go to the node's error log, which `ValidateQuery` requires: a private directory
(`CONFORMANCE_VALIDATE_ERRORLOG`, else a fresh one under the temporary directory, removed at exit).

| Context | Meaning |
|---|---|
| `block_id`, `block` | the candidate id and the block exactly as received (its file hash is checked) |
| `collated_data` | the collated data: `TopBlockDescrSet` (masterchain blocks registering shard blocks) and `ConsensusExtraData` |
| `created_by` | the candidate producer |
| `prev`, `min_masterchain` | `ValidateParams` |
| `top_masterchain`, `validator_set_from` | which supplied state answers the manager's last masterchain state, and the one the validator set comes from |
| `skip_shard_signatures` | `ValidateParams::is_fake`: shard top description signatures are not checked |
| `states` | every state the manager serves: `{block, state}`, the state a complete one or a Merkle proof of it |

Bounds (a `harness_error`, as in the other harnesses): at most 32 states; the block and the collated data
at most 4 MiB each (the node's own candidate limits, `FullNode::max_block_size` and the consensus
`max_collated_data_size`); a state at most 4 MiB and all states at most 8 MiB together. Every bound is
checked on the base64 length before anything is decoded (a context is at most 16 MiB of JSON, so it
cannot carry more than 12 MiB of decoded bytes). A larger state is served as a Merkle proof of what the
validation reads, as every frozen context does. `conformance-validate-bounds`
(`migrate/validate_bounds.py`) sends one context one byte over each bound, one at the block bound, and
then a frozen context, which must still get its frozen effect.

Effects: `accepted` with `ok_from_utime_ms` (`CandidateAccept::ok_from_utime`); `rejected` (a
`CandidateReject`) or `error` (the validation stopped without a verdict) with a `reason` class from the
fixed table in `validate-offline.cpp`: `input_unavailable`, `candidate_id_mismatch`, `shard_mismatch`,
`prev_block_mismatch`, `creator_mismatch`, `validator_set_mismatch`, `prev_state_mismatch`,
`new_state_mismatch`, `limit_exceeded`, `utime_lt_invalid`, `value_flow_invalid`,
`account_update_invalid`, `transaction_invalid`, `message_invalid`, `pruned_input`; any other message is
`unclassified`, so a new failure path is visible. Only the class is compared. Rules are tried in order;
`pruned_input` (a read of a cell missing from a supplied Merkle proof, reported as "prunned branch")
comes first because the validation wraps that text in messages a content rule would match.
`runner/test_validate.py` checks that the C++ table, the validator's `REASONS` and the schema enum name
the same classes, and that every class but `unclassified` is reached by a frozen fixture.

### Contexts from archived history

`conformance-validate-export` (`migrate/validate-export.cpp`) applies the archived blocks from the zero
states (each state update must start from the state reached so far and end at its declared hash), so the
complete states are in memory. Each target is validated with every kept state wrapped in a usage tree;
the context keeps, for each state the validation asked for, a Merkle proof of the cells the validations
read (one proof per state over all contexts of a run, so a state shared by several contexts is one blob),
and the context is validated again from the proofs: the outcome must be identical. The archive does not
keep collated data, so the exporter supplies what a collator attaches:

- `ConsensusExtraData` with `gen_utime_ms = gen_utime * 1000` (`ValidateQuery` requires
  `gen_utime_ms / 1000 = gen_utime`; the millisecond part is not archived);
- for a masterchain block registering new shard blocks, their `ShardTopBlockDescr`, assembled as
  `AcceptBlockQuery` does from the header proofs in the archived proof links. The shard blocks' signatures
  are not archived: the description carries an empty signature set with the top's validator list hash and
  catchain seqno, and such a context sets `skip_shard_signatures`. Everything else of the description is
  checked (`ShardTopBlockDescrQ::prevalidate`: the proof chain, the governing masterchain state, the
  shard configuration update).

| Family | Fixtures | Source |
|---|---|---|
| `rel02-chain` | 364 | every REL-02 corpus block with complete history (epoch-5 packages from genesis); all accepted, the block bytes equal the corpus files |
| `epoch6-slice` | 246 | epoch-6 masterchain 1..100 and 250,001..250,020 with every shard block referencing them; all accepted |
| `rel02-negative` | 28 | authored defects of corpus blocks mc 117,752, basechain 118,284 and mc 151,331 (one with an outbound message); `runner/test_validate.py` checks each outcome and class |
| `rel02-negative-input` | 5 | authored defects of what the validation is given, on mc 117,752 and basechain 118,284: the validator-set and served-state classes; checked the same way |

The four families take 14.9 MB, 11.9 MB of it in the blob files (mostly Merkle proofs of states).
`rel02-negative-input` is exported in a run of its own: the proofs of a family are the union of what its
contexts read, so adding contexts to `rel02-negative` would change its existing contexts.

The defects: another previous state (same header block id, another root hash); another previous block;
the referenced masterchain state withheld; `ValueFlow` fees + 1; a transaction's fees + 1; an account block
removed; a transaction repeated at the next logical time; `gen_utime` one hour earlier (header, new state
and `ConsensusExtraData`, and the header alone); `gen_utime_ms` one second off; `start_lt` not aligned;
`end_lt` 2^40 after `start_lt` (header and new state: the logical-time hard limit); a state update that
leaves the state unchanged; another candidate file hash, shard or producer; an `OutMsgDescr` entry
removed. In `rel02-negative-input`: a header that declares catchain seqno + 1 or a validator list hash
with its lowest bit flipped, so neither matches the set computed from `validator_set_from`
(`validator_set_mismatch`, both blocks); and the previous state of the masterchain block served as a
Merkle proof of exactly what validating the archived block reads of it, with the accounts dictionary
cut off as well (`pruned_input`: the validation stops with an error when it reads the configuration
account). The same cut of a shard block's previous state fails the Merkle state update first (a message
no rule classifies), and a cut of the referenced masterchain state's configuration or shard description
is read by the validator set computation before `ValidateQuery` starts, so neither is a fixture.

`ctest` label `history-replay`: `conformance-validate-epoch6-slice` exports every block of epoch-6
masterchain 1..`CONFORMANCE_ARCHIVE_SLICE` (and the shard blocks referencing them) after checking the
packages against their SHA-256 list, runs the reference on them and requires all to be accepted (not
frozen; the chain is the oracle). It exits 77 (ctest `Skipped`) when the archives are not on the host.

Regenerate the frozen families from a clean-tree build (archives read-only):

```
python3 test/conformance/migrate/validate_families.py families build/test/conformance/conformance-validate-export \
    build/test/conformance/conformance-ref-cli test/conformance/vectors \
    --epoch5 EPOCH5_ARCHIVE/node-a-genesis-packages=INPUTS/epoch-5/node-a-genesis-packages.SHA256SUMS \
    --epoch6 EPOCH6_ARCHIVE=INPUTS/epoch-6/archive-packs.SHA256SUMS --inputs INPUTS --corpus test/rel02/corpus
```

### Not covered

- Shard block signatures in `ShardTopBlockDescr` (not archived; `skip_shard_signatures`). The signature
  checks themselves are pinned by the `consensus` harness.
- The two REL-02 blocks past epoch-5 masterchain 242,333 (mc 259,207 and 259,307): the packages that hold
  them start without a state, so no complete previous state exists offline.
- Split and merge blocks (neither network split), full collated data (`capFullCollatedData`: no validator
  path reads it; it is never set) and parallel account validation.
- The wall-clock bound (`gen_utime` more than 30 s in the future of the local clock): a local predicate,
  never reached by history.
- `wait_verify_shard_blocks` is answered by the interface default (accepted).
- Neighbour outbound queues are served from the neighbours' archived states; no defect alters a
  neighbour queue (a substituted state is refused by the node's own state loader, which checks the
  block id in the state header, before `ValidateQuery` sees it).
- The transaction re-execution comparison is reached by every accepted block, but no defect makes a
  re-executed transaction differ while every earlier check still passes (`transaction_fees_plus_one`
  is caught by the account's transaction chain and last-transaction checks first).
