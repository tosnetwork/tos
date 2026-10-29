# Wallet transaction sensitivity selector repair

Code repair: `871d82a97`, after simulation candidate `ca81877ba`.
Applicable review areas: TE, BC, DC and RH. No runtime source, public ABI,
resource limit, signature rule, message format or caller is changed.

The typed BOC preflight refactor separated the cell-count resource refusal into
its own conditional. The sensitivity runner still selected the preceding
compound-condition text and consequently stopped before its fourth control.
The first three runtime failures in CI were intended guard-removal results;
the missing-selector exception was the actual job failure. Later missing RPC
artifacts followed from steps skipped after that failure.

The repaired selector matches the comparison itself exactly once and replaces
it with `false`. It preserves the cell-count-16385 refusal assertion and all
eight compiled controls. It neither skips a control nor changes an expected
failure. The existing source/clean-checkout tests still apply. The standalone
runner and the Python/native workflow caller retain their argument order and
build-directory validation; the other seven mutation selectors are unchanged.

On the actual native build, all eight guards were removed individually, rebuilt
and produced their designated runtime assertion failures. Original engine/ABI
source bytes were restored, the library rebuilt, and the normal transaction
regression passed. The five runner source/checkout tests, pinned Python lint and
format checks also passed. The exact commands, CI failure log, independent
diagnosis and full red/green transcript are retained in the mobile memo index.

This is a test-harness repair to a project-specific proof interface, with no
upstream runtime counterpart or added persistent state/resources. Hosted CI on
the repaired head and final third-party gates remain separate from these local
results. Mobile fee-coordinator development does not alter this native repair.
