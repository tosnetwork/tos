# BCT vs GST Fixture Divergence Spike

## Purpose

Our Phase G.1 walker (`test_state_test_runner_walk_curated` in
`crypto/block/evm-workchain/test-evm-executor.cpp`) runs the upstream
**GeneralStateTests** (GST) format against CellEvmState. As of worktree HEAD
`9964cc39` the walker scores **1427 pass / 29 fail / 4 upstream_skip**.

Silkworm's own conformance runner (`cmd/test/ethereum.cpp`) consumes the
**BlockchainTests** (BCT) format instead. Its `kFailingTests` list contains
8 entries; we match 4 as `upstream_skip`. The remaining 29 failures do **not**
appear in Silkworm's list — i.e. Silkworm claims to pass them in BCT format.

**Hypothesis under test**: the 29 failures are *format artifacts*. Because
BCT wraps each GST test into a full block execution, BCT runs additional
per-block hooks (EIP-4788 beacon-roots system call, block rewards, block-hash
chain) that touch extra state. So the BCT *expected post-state* may differ
from the GST *expected post-state* — our walker compares against the GST
post-state, which (hypothesis) is the "wrong" one after Cancun's system calls.

If true, porting to BCT format would likely clear most of the 29.

## Method

For each of three failing fixtures we loaded, with pure Python:

- `test/conformance/ethereum-tests/GeneralStateTests/<path>` (GST format)
- `test/conformance/ethereum-tests/BlockchainTests/GeneralStateTests/<path>`
  (BCT format — the repo nests GST as a subdir of BlockchainTests)

For each pair we matched the d0g0v0 Cancun entry and compared:

- `pre` accounts: address set, per-address `balance` / `nonce` / `code` /
  `storage`.
- `post.Cancun[0].state` (GST) vs `postState` (BCT): address set,
  per-address fields.
- The transaction params (`gasLimit`, `value`, `data`, `to`, `nonce`,
  `gasPrice`).
- The environment: GST `env.*` vs BCT `blocks[0].blockHeader.*`.
- The EIP-4788 beacon-roots predeploy (`0x000f3df6d732807ef1319fb7b8bb8522d0beac02`) in pre and in post.

No code was modified, no tests run, no rebuild performed.

## Fixture 1: stExtCodeHash/extCodeHashDeletedAccount.json

### Pre-state

| Address | GST | BCT | Delta |
| --- | --- | --- | --- |
| `0x000f3df6d732807ef1319fb7b8bb8522d0beac02` | absent | present, nonce=1, balance=0, 4788 code, storage={} | BCT-only (beacon-roots predeploy) |
| `0x095e7baea6...552d87`, `0xa94f5374...ebf0b`, `0xaaaaaaaa...`, `0xdeadbeef...0000`, `...0001`, `...0002` | present | present | **byte-identical** (balance, nonce, code, storage) |

### Post-state

| Address | GST | BCT | Delta |
| --- | --- | --- | --- |
| `0x000f3df6...beac02` | absent | nonce=1, storage `0x03e8 → 0x03e8` | BCT-only, beacon-roots ring-buffer slot |
| all 6 shared accounts | present | present | **byte-identical** (balance, nonce, code, storage all match) |

Transaction params match byte-for-byte (gasLimit=0x061a80, value=1, data=0x,
to=0x095e7..., gasPrice=0xa). Coinbase matches. Block gasLimit matches.
BCT has an extra `blocks[0].blockHeader.parentBeaconBlockRoot = 0x00..00` and
`excessBlobGas=0x060000` in the genesis (not an execution input for this tx).

**Conclusion**: GST and BCT post-states are byte-identical modulo the
beacon-roots predeploy's own storage. No coinbase reward delta (post-merge).
This fixture does **not** support the hypothesis.

## Fixture 2: stCreate2/Create2OnDepth1024.json

### Pre-state

| Address | GST | BCT | Delta |
| --- | --- | --- | --- |
| `0x000f3df6...beac02` | absent | present (same canonical beacon-roots predeploy) | BCT-only |
| all other accounts | present | present | **byte-identical** |

### Post-state

| Address | GST | BCT | Delta |
| --- | --- | --- | --- |
| `0x000f3df6...beac02` | absent | storage `0x03e8 → 0x03e8` | BCT-only, beacon-roots |
| all shared accounts | present | present | **byte-identical** on balance, nonce, code, storage |

Transaction params match (gasLimit=0x7effffffffffffff, value=0, data=0x,
to=0xb94f5374..., gasPrice=0xa). Coinbase matches
`0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba`. Block gasLimit matches
`0x7fffffffffffffff`.

**Conclusion**: Same pattern — beacon-roots is the only BCT addition.
Shared state is byte-identical in both directions. Does **not** support the
hypothesis.

## Fixture 3: stRandom/randomStatetest100.json

### Pre-state

| Address | GST | BCT | Delta |
| --- | --- | --- | --- |
| `0x000f3df6...beac02` | absent | present (canonical beacon-roots predeploy) | BCT-only |
| all other accounts | present | present | **byte-identical** |

### Post-state

| Address | GST | BCT | Delta |
| --- | --- | --- | --- |
| `0x000f3df6...beac02` | absent | storage `0x03e8 → 0x03e8` | BCT-only, beacon-roots |
| all shared accounts | present | present | **byte-identical** on balance, nonce, code, storage |

Transaction params match (gasLimit=0x061a80, value=0x0186a0, data=0x42,
to=0x095e7baea..., gasPrice=0xa). Coinbase matches
`0x945304eb96065b2a98b57a48a06ae28d285a71b5`. Block gasLimit matches
`0x7fffffffffffffff`.

**Conclusion**: Identical pattern. Does **not** support the hypothesis.

## Synthesis

- **How many of the 3 show GST vs BCT post-state divergence?** **Zero, on
  shared accounts.** All three pairs are byte-identical for every account
  present in both post-states (balance, nonce, code, storage).
- **What kinds of differences dominate?** Only the EIP-4788 beacon-roots
  predeploy at `0x000f3df6d732807ef1319fb7b8bb8522d0beac02`. In BCT it is
  - added to `pre` with nonce=1, balance=0, the standard 4788 bytecode,
    empty storage;
  - added to `post` with the same nonce/balance/code plus the ring-buffer
    slot `0x03e8 → 0x03e8` (timestamp-modulo write from the block header
    system call).
- **No other differences observed**: no coinbase-reward delta (post-merge so
  block reward is 0), no block-hash chain state, no sender nonce drift, no
  gas refund delta on the caller.
- The expected `post.Cancun[0].hash` in GST is the trie root of the
  GST-format post-state (without beacon-roots). This hash is produced by the
  test-fillers *knowing* GST format excludes beacon-roots — it is **not** the
  same trie root a full BCT block execution would produce.

### Does this validate the hypothesis?

**No.** The hypothesis — "BCT expected post-state diverges materially from
GST expected post-state on these fixtures" — is **not validated** on the 3
sampled fixtures. BCT adds one predeploy and its ring-buffer write; all
other account state is identical.

The practical implication: if our walker's CellEvmState *correctly* executed
the transaction in isolation, it would match the GST post-state. That it
does **not** match for these 3 fixtures strongly suggests the 29 failures
are **genuine executor bugs in CellEvmState**, not format artifacts.

Caveat: 3 out of 29 is a 10% sample. Some of the 29 may involve fixtures
where coinbase activity (e.g. coinbase as transaction target or self-destruct
beneficiary) or the beacon-roots call touching a tested slot does cause GST
vs BCT to diverge. But the three fixtures we sampled — from three different
stTest categories (stExtCodeHash, stCreate2, stRandom) — showed zero such
divergence, which is strong evidence.

## Recommendation

**Do not invest in a BCT format port as a workaround.** On this evidence,
it would not resolve the 29 failures. Instead:

1. **Pivot to root-causing the executor failures.** Pick 2-3 of the 29
   fixtures (e.g. the same three we looked at here), run them through the
   walker with verbose per-step tracing, diff the CellEvmState post-state
   against the GST expected post-state, and find the first diverging
   account/field.
2. **Consider an evmone-based differential**. evmone ships a state-test
   runner (`evmone-statetest`) that consumes the same GST fixtures. If
   evmone passes a fixture we fail, the divergence is in our executor, full
   stop. That gives a second oracle (in addition to silkworm's BCT runner)
   and removes any residual doubt about fixture-format artifacts.
3. **Longer-term**, still add a BCT runner as a second conformance gate —
   it validates beacon-roots system-call plumbing, block rewards (pre-merge
   forks), and block-hash chain — but it is **not** the right vehicle to
   chase down the 29.

### Short summary

| Fixture | GST vs BCT post-state on shared accounts | BCT-only additions | Verdict |
| --- | --- | --- | --- |
| stExtCodeHash/extCodeHashDeletedAccount | identical | beacon-roots predeploy + ring-buffer slot | format-identical |
| stCreate2/Create2OnDepth1024 | identical | beacon-roots predeploy + ring-buffer slot | format-identical |
| stRandom/randomStatetest100 | identical | beacon-roots predeploy + ring-buffer slot | format-identical |

3/3 format-identical → hypothesis rejected on this sample → pursue executor
bugs, not a format port.
