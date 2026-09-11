# Statement guard callee probe and scope comparison

Specification SHA256 prefix `4f80cceb2f287885`.
Guard and crypto source baseline: A commit `28b4e3001435ab1900227811ec7293cf5193147e`.
All mutated source files and execution fixtures remained under
`/tmp/uno-withdrawal-callee-probe`; neither A's guard nor shared production
source was modified. No accounting prediction inputs or observations were read.

## Observed result: the declared blind spot is real

The unchanged statement constructor calls `relation::validate_limits` at
`uno/crypto/src/withdrawal_statement.rs:81` in the reviewed tree. The callee is
`uno/crypto/src/relation.rs:45`. Only the latter's body was changed in the
isolated copy: a filesystem copy replaced a serialized account fixture before
normal limit validation. Its signature remained unchanged. The statement's
fields, signatures, call targets and entire bytes remained unchanged.

The account-state file initially held the committed SEND vector's `alice.boc`;
the replacement was its committed `bob.boc`, also a complete formal account
record. These are explicitly synthetic account fixtures, not real chain data.
The operation wrote an actual file containing account-state bytes, not merely
a log or a flag named "account written". It did NOT install an authenticated
ShardAccounts root or write to a node database. The extra filesystem capability
was introduced inside the callee by the mutation; it is not present in baseline.

The isolated Rust example invokes the real `WithdrawalStatement::new`, with
explicit limits and an identity point that eventually yields DECODE=2. That
same result occurs in both runs. The account file changes only with the callee
mutation, showing that identical statement error output does not imply absence
of indirect side effects.

| Run | AST guard process exit | Statement result | Serialized account file |
| --- | --- | --- | --- |
| Baseline | 0 | DECODE=2 | unchanged Alice bytes |
| Callee body mutation | 0 | DECODE=2 | replaced by Bob bytes |

Statement SHA256, identical before and after:
`f67aae4f29810f221e59a0089ee0712e31dc95e565a917bab5020a7b2f1bb2ed`.
Account file SHA256 before:
`0e0b486aedbd4a5f6498ed96631485ced1a1befb8be9050af20ece7219f9e87d`.
After:
`d8ccd152e9158ceba8b24cd9f7ed5de6f19bcfb601f31e527b35c52414b37a2e`.

The guard's own three structural red controls still execute successfully in
both runs. Thus they do not cover this body-only dependency change. This is
outcome 2 for indirect filesystem/account-fixture effects, not outcome 1 or a
claim that the current Native account publication path was exercised.

## Reproduction and retained local evidence

The isolated setup script is `/tmp/probe-withdrawal-callee.py`; it copies
committed inputs with `git show 28b4e3001:path`, preserves the statement hash,
builds/runs both versions offline, and verifies exact account-file bytes.
It is intentionally not installed on the shared branch as a mutation.

Commands used by that script, with P=/tmp/uno-withdrawal-callee-probe:

    cargo run --locked --offline --manifest-path "$P/guard/Cargo.toml" --target-dir "$P/guard-target" -- "$P/crypto/src/withdrawal_statement.rs"
    cargo run --locked --offline --manifest-path "$P/crypto/Cargo.toml" --target-dir /home/tomi/tos-m2/uno/crypto/target --example callee-probe

Logs: `baseline-guard.log`, `mutated-guard.log`, `baseline-execution.log`,
`mutated-execution.log`, and machine-readable `result.json` under P. Both Rust
executions compiled successfully. Shared-tree source status remained clean
before writing this report. The shared Cargo target contains build artifacts,
not source modifications; later normal builds must use their normal manifest.

## Scope comparison of the two new guards

Reachability and AST parsing are separate axes: the former chooses files;
the latter chooses what facts to inspect within them. One does not replace the
other.

| Guard | File selection | Within-file predicate | Reason and limit |
| --- | --- | --- | --- |
| Existing key-epoch / closure-expiry | Explicit roots and static include/module traversal | Syntax units / tokens plus selected representation identities | Finds newly referenced files; does not resolve aliases or runtime coupling |
| B system-sequence-expiry, d37fb5a82 | Same traversal helper; five property-specific roots, 221 files, cap 442 | Counter/allocator syntax units using the tested epoch extractor | Same mechanism, different roots for a different property; named test Native adapter is an explicit integration root |
| A statement-expiry, 28b4e3001 | One supplied statement source file | Parsed fields, signatures and call-target names | Intentionally bounded interface inventory; does not traverse or inspect existing callee bodies |

B's mechanism is already consistent with the older guards; its count differs
because the root set concerns counter installation, not rotation or closure.
A documented its one-module boundary before this probe, so it is not an
unexplained accidental difference. However, that boundary establishes an
unchanged statement interface, NOT unchanged effects of the full execution
path. The probe demonstrates the practical distinction.

A can decide whether to extend file selection to relevant dependency bodies
(with separately specified within-file predicates) or retain and explicitly
accept this bounded interface guarantee. Merely traversing more files without
checking callee bodies would not close this example. Extending to local modules
would still not prove absence of effects in external callees or resolved aliases.
Per task ownership, this report changes neither A's guard nor its accepted
scope. No general no-side-effect, no-pending host enforcement, or complete
coverage claim follows from this single probe.
