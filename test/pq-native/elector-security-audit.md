# Elector security audit: native acceptance

This branch closes the applicable audit matrix with the current native compiler,
real ML-DSA-44 signatures, and the transaction executor's compute, action and
bounce phases. The result index is `elector-security-results.json` in this
directory. It identifies exact source bytes, commands, exits and retained raw
artifacts. The Chinese item-by-item ruling is in the memo repository under
`elector-security-audit-2026-10-01/NATIVE-ACCEPTANCE-CLOSEOUT.md`.

These controls concern a fresh compatible contract set. They do not deploy a
network, migrate live funds, certify every future fee configuration, or establish
that replacing the signature algorithm requires this particular relay protocol.

## Necessary properties and implementation choices

- H1 preserves original principal: frozen principal plus this round's new
  credits equals each owner's full original contribution, including surplus.
- M1 retries a failed selection when its decisive inputs change. Configurations
  16, 17 and 47, the registration books and admission rules participate in the
  fingerprint. Identical failed inputs skip expensive work; the deadline still
  cancels and refunds exactly once.
- H2 binds business results to the real sender, request, exact forward amount
  and full payload commitment. A copied query from another elector refusal
  cannot consume a pool request.
- H3 preserves third-party ownership through forwarding, real bounce, payment
  action failure and recipient computation failure. Public caller-funded retry
  does not require the controller root to decide where money goes.
- R1 admits at most 256 registration identities per election. Existing entries
  can top up. An imported oversized book is explicitly refused before a costly
  selection; this is not an automatic migration of that book.
- C1 refuses incompatible classic nonempty election state. Installation and
  rollback require no active election, credits, frozen past rounds or outstanding
  paid-recovery receipts. A drained boundary is tested against real classic code.

The relay's extra signature verification protects its newly persistent slot;
it is not a cryptographic requirement to verify a PQ stake twice. This design
uses one request identifier and one unfinished slot per controller. It adds no
ACKED exchange, relay queue, maintenance bond, revenue-sharing policy or new
nominator population limit. Existing nominator policies are retained.

## Relay wire and trust boundary

`crypto/smartcont/stake-relay.fc` is the shared wire and checked coin arithmetic.
All three contracts use the same uint64 request ID in the high-bit domain.
Root-owned legacy requests remain in the low-bit domain. Accepted relay IDs
increase strictly and are never reused.

| Message | Opcode | Binding |
| --- | --- | --- |
| Pool to controller | `0x50517232` | query, 160-bit commitment, forwarded coins, pinned elector, terms reference |
| Controller to elector | `0x50517332` | query, 160-bit payload commitment, actual owner and complete PQ payload |
| Elector success / refusal to controller | `0x50516f32` / `0x50516532` | query, reason, accepted and received coins, full request hash |
| Controller business result to pool | `0x50516232` | query, full hash, exact forwarded and accepted coins, reason, success |
| Pool cleanup to controller | `0x50516132` | query, full hash, actual paid owner |
| Public retry | `0x50516632` | query; destination remains the recorded owner |

The commitment covers references and owner identity. Its first 160 bits, query
and opcode fill the executor's 256-bit bounced-body prefix. The actual bounce
sender and saved entire prefix must match; a bounce cannot supply an untrusted
new refund address. The full request hash additionally binds the controller.

Normal results travel elector -> controller -> pool. Controller states are
WAIT -> READY -> PAID -> empty. Recording READY precedes an optional self-wakeup.
Payment to the owner uses nonbounce value without ignoring action errors.
A failed payment action rolls back PAID and keeps READY. Recipient abort keeps
the value physically at the owner; PAID retries send only the new caller's fee
value with the old balance reserved. Pool business accounting consumes the
result once; repeats only repair the lost cleanup ACK.

Controller root sends are refused while a third-party request is unfinished.
Root and consensus-key rotations preserve its original creditor and elector.
Even without a pending request, raw root sends cannot forge reserved callbacks
or the high-bit query namespace. Root authority over its own low-domain funds
and single-pool owner authority are not changed into shared custody.

## Mature-stake recovery

The multi pool uses request/reply/ACK `0x47657432` / `0xf96f7332` /
`0x47656132`, with the elector retained from its accepted stake and the same query.
A later Config1 replacement cannot redirect the mature credit to the new elector. Elector records the
gross credit and deletes that credit atomically with a successful nonbounce
payment action. A recipient abort can be repaired using a fee-only repeated
receipt. Gross business credit, rather than remaining message fees, determines
principal and reward allocation. An acknowledged old query cannot consume a
later credit.

Elector keeps one replay tombstone per distinct recovery owner. It does not
keep one record per call or per round. ACK clears the amount and outstanding
status, while retaining the last ID. Storage therefore grows with distinct
historical creditors; it is not globally constant or TTL-pruned. Native controls
measure 256 owners and repeated rounds, verify point-operation gas and record
the measured cell count. Only a tested debt-free installation boundary drops
the book. No live deletion or inferred garbage collection is claimed.

## Fees, artifacts and cutover

Caller budgets are calculated from live VM gas and forwarding fees and checked
coin operations. The measured native profile uses 200,000 gas for relay signature
verification, 50,000 for controller controls and 200,000 for the callback.
The pool caller envelope is 20 TOS; it is not protocol revenue. The original
controller capital is reserved and unused relay budget returns to the pool.
Fee changes or storage debt can make a payment fail; its recorded READY debt
remains fundable. The native suite includes actual action failures and long
storage age, not an assumed gas tolerance.

The multi pool source, pinned build hashes, Rust embedded bytecode and node
recognition table must match. The single-pool checked-in hex and Rust embedded
copy must match its current source. Both locks are executed in the closeout.
Generated elector Fift depends on the shared relay include in CMake.

The controller's code changes its immutable birth identity. Deploy and admit
fresh controllers and matching pools; do not assert that old deployed controller
addresses automatically receive this logic. Existing birth-witness generation
uses immutable StateInit, including after authority changes. Existing unrelated
liquid-staking profiles are outside this relay cutover. Classic nonempty state
is refused with original code/data and creditors preserved; no live old-state
conversion is supplied or claimed.

## Reproduction and gates

Run from the existing TOS checkout; `TOS_ROOT` must be explicit. PQ key tools
and real FunC/Fift/create-state binaries must exist. No live chain is contacted.

```sh
cmake --build build --target gen_fif tos-pq-controller tos-pq-vote -j64
export TOS_ROOT="$PWD"
export TMPDIR="$PWD/.git/elector-security-audit-artifacts"
export CARGO_TARGET_DIR="$TMPDIR/cargo-target"
mkdir -p "$TMPDIR/reproduction"
cargo test --manifest-path tosctl/src/Cargo.toml -p contracts --locked --no-fail-fast -j64
cargo test --manifest-path tosctl/src/Cargo.toml -p elections --locked -j64
python3 test/pq-native/elector-relay-mutations.py --out "$TMPDIR/reproduction/relay" --jobs 64
python3 test/pq-native/elector-selection-mutations.py --out "$TMPDIR/reproduction/selection" --jobs 64
python3 test/pq-native/contract-guard-mutations.py --out "$TMPDIR/reproduction/guards.json"
scripts/check-nominator-pool-code-lock.sh
scripts/check-single-nominator-code-lock.sh
```

The relay and selection runners regenerate actual artifacts, require a named
assertion after successful native compilation, and restore exact original source.
The original guard runner also requires passing baseline and restored controls,
with a compiled failed test rather than a compile/tool error or zero-test filter.
Additional relevant executor, vector, tooling and Python gates are enumerated in
the result index. Bulky raw output remains under `.git` for at least 90 days after
audit-branch integration; hashes without access to that retained location are
not independent proof. Historical weak survivors, fixture failures and old
out-of-gas controls remain separately indexed rather than being overwritten.
