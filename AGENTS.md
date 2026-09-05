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

- Financial arithmetic uses `checked_*`, never raw `+ - * /`. A bound that
  holds "because of a limit declared elsewhere" is not a checked operation —
  it is a dependency on a constant nobody will remember to re-check.
- Every `Result`/`Option` is handled explicitly. No `.unwrap()` in production
  paths.
- Verification and execution stay separate: `verify` is read-only and predicts
  nothing; all state change happens in `apply`.
- Do not reference external project names or issue trackers in comments or
  commit messages. Comments explain intent, not history.

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
