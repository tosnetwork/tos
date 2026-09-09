# Convenience-runner null-context regression

The test-first control's complete output and exact source replacement are in
`uno-v2-runner-null-context-control.json`. The production fix adds only the
early local-context check; no prototype or live actor path was edited.

After the final source was rebuilt with `-j48`, the command
`ctest --test-dir build --output-on-failure -R '^test-workchain-(block|admission)$'`
passed both full suites: block 3.08 seconds, admission 0.01 seconds, total 3.09
seconds. These are regression observations, not performance budgets.

Final SHA-256 values:

| Object | SHA-256 |
| --- | --- |
| `crypto/block/workchain-account-engine.h` | `198f5092d4b459cae38230e5cc9e4ecbf263eb64aee5f21d7b53ca771a49913e` |
| `crypto/test/test-workchain-block.cpp` | `1e4e43e11763afedd2fb1efcd492eb3d1552083df9e595acba98cbc9bbee8b00` |
| `build/test-workchain-block` | `89dbe215eacc4fcc3c55319434d01f29445f499c7ebecfff5f8124c6c681d486` |
| `build/test-workchain-admission` | `64d8d42d60ea2c56c82eeb7b35ba960e0fdfe2098c35545b7678cc4a4055b4e7` |

Removing the recorded six-line block reconstructs the measured pre-fix header
hash `936c11875caa4c4e83a00f3f246c1d3e979f40d24d4ca7c2b9bab34b9a967eb4`.
The test-source bytes do not change between red and green. The positive direct
call precedes the null call, proving both counters are live. A later failure
cannot turn work_calls from one back to zero.

The domain scan passed with the control JSON included (5,332 text files).
This final Markdown record is also included before the final pre-commit scan.
D31, C1/C2/C3 and live I13 acceptance remain incomplete.

Independent read-only review passed with no blockers. It reconstructed the
source hashes and confirmed that the later null-state read returns the same
error category: that category alone is not the ordering evidence. The zero
work count is the discriminating assertion. An additional empty-declaration
fixture was suggested but is not claimed here; the unconditional early null
check also rejects that case, while the measured control uses declared reads.
