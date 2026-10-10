# Working on tos

## Instruments lie by staying silent

A measurement that returns nothing is not an answer. Before trusting silence,
prove the instrument speaks.

This is the single most expensive failure mode in this repository, because the
things we build here — a VM, a consensus engine, contracts that hold other
people's money — all fail quietly by default. A contract that was never
deployed reports no bugs. A test that was never compiled prints no failures.

### A test that cannot fail is not evidence

Before believing a new test, **remove the thing it tests and watch it go red.**
If it stays green, it is measuring nothing, and you have learned nothing.

This applies with full force to negative tests — "malformed input is rejected",
"the unauthorized caller fails", "the overflow is caught". Those are the tests
most likely to pass for the wrong reason, because *any* error makes them pass,
including an error in the test setup that means the code under test never ran.

### Local traps that have already cost someone an hour

**A frozen BOC does not track its source.** Editing
`crypto/smartcont/*.fc` does not update the compiled artifact. For the
prediction market the chain is:

```
crypto/smartcont/prediction-market-code.fc          # source you edited
scripts/update-prediction-market-code.py            # regenerates
crypto/smartcont/prediction-market-v1.boc.base64    # frozen artifact
tosctl/src/node-control/contracts/tests/prediction_market_sandbox.rs   # runs the artifact
```

Run the sandbox without regenerating and it exercises the **previous** contract
while reporting on your new one. Every other frozen-artifact contract has the
same shape. Regenerate, then check the artifact's diff is only what you meant.

**An unreachable `throw_unless` looks exactly like a working one.** A phase gate
whose condition is already guaranteed by a different function's invariant never
fires, never fails a test, and silently stops protecting anything the day that
other invariant moves. When you add a guard, construct the input that trips it.
If you cannot, the guard is decoration — either it is redundant, or the
condition is wrong.

**Compiling a contract is not running it.** FunC accepts a great deal of code
whose first execution throws. Compute-phase unit tests are not enough for
anything that emits actions: action-phase failures roll back state in ways that
only a sandbox with a real action phase will show.

**Gas numbers in comments rot.** A comment claiming a path costs N gas is a
claim about a build that may no longer exist. Re-measure before relying on it;
if you rely on it, say which commit measured it.

**A doc line can be stale and backwards at the same time.** `800e6d1a2` corrected
a README that framed a shipped component as future work and understated proof
sizes by 10×. It had been wrong for weeks and nothing failed. Verify docs
against source, not against memory.

## Conventions

- Keep documentation in this repository in English. Store Chinese plans,
  design notes, and audit reports in the `memo` repository.
- For node-health-monitor work, use the existing `node-health-monitor` branch
  when the shared tree is available. If concurrent changes require an isolated
  worktree, make one short-lived branch, merge only reviewed changes into
  `node-health-monitor`, then remove its local and remote branch and worktree.
  Reuse an active isolation branch instead of creating successors for each
  test or receipt. Never merge a withdrawn or unreviewed candidate just to
  reduce branch count.
- Financial arithmetic uses `checked_*`, never raw `+ - * /`. A bound that
  holds "because of a limit declared elsewhere" is not a checked operation —
  it is a dependency on a constant nobody will remember to re-check.
- Every `Result`/`Option` is handled explicitly. No `.unwrap()` in production
  paths.
- Verification and execution stay separate: `verify` is read-only and predicts
  nothing; all state change happens in `apply`.
- Do not reference external project names or issue trackers in comments or
  commit messages. Comments explain intent, not history.

## Static analysis gates new C++, not old debt

The tree carries hundreds of inherited analyzer findings. Fixing them is
tracked work; it is not a reason to let a change add more. Before opening or
updating a PR that touches C/C++, run the gate from the checkout that owns the
build:

```
uv tool install codechecker==6.29.1    # once; LLVM 21 comes from install-llvm-toolchain.sh
scripts/static-analysis.py --build-dir build
```

Exit 0 means no new blocking finding, 1 lists the new blocking findings, and 2
means the gate could not establish a result. A new finding in a blocking check
fails the change.

- The tier tables in the script are the rule set. `.clang-tidy` at the
  repository root is what clangd reads while you edit, and the script refuses
  to run if its checks or options disagree with the tables. Change the rule set
  in its own reviewed commit, with the measurement that justifies the change.
- A check blocks only when its findings on this tree are mostly real.
  Advisory checks are printed and do not fail. Checks whose findings here were
  all false are not run at all. Promote a check with evidence, not by default.
- "New" means new against a fresh analysis of the merge base, run in the same
  invocation with the same tools and options. There is no stored baseline to
  go stale, and no allowance to spend: a defect fixed on main and brought back
  is new again.
- A false positive is suppressed in the source, naming the exact check and the
  reason. A suppression without a reason, or one that silences a whole file or
  every check, is refused. The reviewer sees every suppression the change adds.
- `td::Status` and `td::Result` returned from a call are handled or discarded
  explicitly with `(void)` and a comment. A dropped status is how a failed
  database write or a failed validation goes unnoticed.
- The script must prove it ran: it reports how many compilations it analysed
  and fails if any failed to parse, if the enabled checks differ from the rule
  set, if a positive control in `test/static-analysis/gate/` stops reporting
  its marked line, or if a changed file is missing from the compilation
  database. "No new findings" from an analysis that did not run is not a
  result. A new blocking check comes with a control the check must flag.

## Keep evidence reviewable without filling Git with run output

Commit the smallest durable set that lets another person check a claim and
reproduce the relevant control: the test or runner, required frozen fixtures or
schemas, the exact source/commit and command, and a concise result index with
exit status and hashes. Preserve a targeted red/green sensitivity result when
it is needed to show that the test can fail.

Do not commit every build log, repeated successful run, temporary binary,
database snapshot, or continuous sampling stream. Keep bulky raw output in a
separate retained artifact location and put its path, SHA-256, size, and
retention period in the committed index. If raw output is essential and no
durable external location exists, commit only the bounded excerpt or minimal
raw file needed to audit the claim, and explain why it cannot be regenerated.
Never commit credentials, private runtime data, or unredacted live payloads.

Review new evidence files before staging them. A passing summary must not
replace a required failure receipt, and a hash without access to the retained
raw artifact is not independent proof. Do not rewrite published Git history
merely to remove old evidence; handle any such cleanup as a coordinated task.

## Wait for relevant CI, not every CI job

CI is evidence only when it exercises the change under review. Do not hold a
small, independently tested change hostage to an unrelated full CLI/native
build merely because that repository-wide job happens to run on every PR.

Before merging, identify the **smallest sufficient set** of checks from the
paths and execution boundary actually changed:

- Changes to Rust/C++/FunC code, Cargo manifests or lockfiles, CMake/build
  wiring, generated contract artifacts, protocol codecs, or the `tosctl` CLI
  execution boundary must wait for their relevant build and test gates.
- A Python-only local harness must wait for its own Python tests and any
  directly used Vault/CLI smoke test. Documentation-only changes need a
  whitespace/rendering check, not a native rebuild.
- A job made mandatory by GitHub branch protection always remains a hard gate.
  An otherwise unrelated repository-wide job may be bypassed only with the
  owner's explicit instruction; record that its result was still pending, and
  never cancel it or represent it as passing.

This rule is not permission to skip validation. It requires a written mapping
from each changed boundary to the test that can fail because of that boundary.
If a change affects more than one boundary, wait for the union of their
relevant gates.

`CLAUDE.md` is a symlink to this file, so Codex and Claude Code read the same
instructions.
