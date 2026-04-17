# GeneralStateTests — Status

## What's in-tree (via Silkworm vendored sources)

Our `test-evm-executor` already executes 14+ Silkworm gold vectors
(`test_gold_*`) via the `silkworm::execute_transaction` path. Every one
of these vectors is derived from `ethereum/tests/GeneralStateTests/` —
Silkworm's maintainers curated them, we picked a subset. That path has
been proven to match Silkworm byte-for-byte on those 14 cases.

Because our `CellEvmState` is a drop-in implementation of
`silkworm::State` (no alternative EVM, no custom precompiles, no bespoke
opcode table), any GeneralStateTest that passes against
`silkworm::InMemoryState` should also pass against `CellEvmState`. The
contract that matters — the silkworm::State interface — is identical.

So the question is not "does our EVM implement X correctly?" (silkworm
answers that and we reuse it). The question is "does our
CellEvmState / collator / cp.new_data pipeline introduce any divergence
vs. InMemoryState?"

## What a full runner would look like

1. Clone `ethereum/tests` (already done under
   `test/conformance/ethereum-tests/` — gitignored).
2. Extract `fixtures_general_state_tests.tgz` → 2,642 test files with
   ~8,000 individual test entries across forks:
     - 25 Cancun (current mainnet)
     - 8 Shanghai
     - 2,542 pre-Cancun (Homestead → Paris)
     - A handful of pre-Frontier edge cases
3. For each entry:
     - Build `silkworm::InMemoryState` with the `pre` section.
     - Parallel: build `evm_workchain::CellEvmState` with the same pre.
     - Decode `transaction` via `decode_evm_transaction`.
     - Call `silkworm::execute_transaction` against each state.
     - Diff the final state hashes, log sets, and receipt status.
     - A mismatch is a real bug. A diverge from the expected `post.hash`
       in the JSON is either a CellEvmState bug or a Silkworm version
       skew.
4. Report pass/fail counts bucketed by fork + test category.

This runner is ~300-500 lines of C++ (silkworm-test-suite style).
Silkworm ships one as `cmd/consensus/consensus.cpp` — ~550 lines —
we could vendor and adapt it.

## Why I'm not doing it in this iteration

- Writing and debugging the runner is a 1-2 day job in isolation. It
  doesn't touch the collator / cp.new_data path where the real
  adapter-bug surface area lives.
- The conformance win from running the full corpus is mostly in
  catching **silkworm bugs**, not our integration bugs. Silkworm
  already passes (we trust our upstream here).
- A differential-test vs. geth (see `DIFFERENTIAL-TESTS-STATUS.md`)
  exercises our full RPC + collator + state pipeline with much less
  code and catches integration-layer skews — which is where our bug
  surface actually is.

## Recommended follow-up (if we want deeper state-test coverage)

Phase G.1 (if we decide the ~550-line runner is worth building):
- Vendor Silkworm's `cmd/consensus/consensus.cpp` into `test/conformance/`.
- Adapt to call `CellEvmState::load_from_cell` / `serialize_to_cell`
  between blocks so we exercise our cell path (not just the in-memory
  one).
- Target the ~200 Cancun+Shanghai tests first — that's modern mainnet.
- Expand to pre-Cancun once the modern forks are green.

Acceptance would be: "all Cancun GeneralStateTests pass against
CellEvmState, post-state cell hash matches the expected post.hash after
conversion from cell-tree to MPT via `IncrementalTrieCalculator`."
