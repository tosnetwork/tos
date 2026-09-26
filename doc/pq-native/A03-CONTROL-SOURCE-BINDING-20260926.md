# A03 independent control-source binding (candidate)

The ledger no longer inherits the main run commit for old-red, new-green or
mutant-red. Each control must name its own executed commit and nonempty source
blob list; its original receipt must bind that control commit, role, argv,
exit and raw SHA. A predecessor old-red can therefore be represented honestly,
without relabelling it as the later main source.

This is a schema correction, not historical evidence reconstruction. No missing
receipt is written for E16, F01 or X01; their retained first-batch source/raw/
binary/review/CI inventory remains valid but incomplete. In particular original
launch argv and complete source-applicability mapping of prior red controls
remain gaps. F02 is an independent audit delivery, not a second runtime run;
it must not borrow F01 runtime controls to manufacture an acceptance record.

Unique mutant attribution still requires baseline plus exact patch/source
identity and independent review. Merely naming the clean commit does not prove
that a mutable working tree or mutated binary executed that commit. This patch
does not close that remaining requirement or A03. All accepted flags stay false.

New tests cover predecessor-source receipt binding, wrong-source receipt
rejection, and missing per-control commit/blob rejection. At candidate commit
time they are unexecuted; results are attributed separately below, not to that
candidate-time prose.

## Exact e61 finite schema execution

On tracked-clean `e61f8accd7e16709f5cf2175e3099d1ea601cd3b`, one-use ticket
`A03-control-source-v1.json` ran the `LedgerTest` class only. Resource unit
`n6-heavy-1790398491-77935` naturally exited0, with 23 tests/OK in53.293s;
the outer service reports53.526s. This excludes the committed-artifact class
and does not rerun the production ledger gate or any historical route.

Original directory: `/datax/n6-unit-agents/A03/control-source-v1/`.
The ticketed wrapper generated these SHA values while recording actual source,
argv, cwd, exit and unchanged after-HEAD/tracked state:

| File | SHA-256 |
| --- | --- |
| `stderr.raw` (original unittest output) | `724621cdb7b6cd25eb9247b5b8e6851594f1091fc4c773c236961e91548c18db` |
| `stdout.raw` (empty) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `exit.raw` (0) | `9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa` |
| `context.json` | `5c8ab29712315702a0106cc6bd2704dbbf90d19b2a78b262067a9474cd0a38ef` |

Outer stdout/stderr/exit are retained as
`/datax/n6-unit-agents/A03/control-source-v1.outer.*.raw`; original cgroup
record is `/datax/n6-control/runs/n6-heavy-1790398491-77935.json`.
No new outside-ticket full evidence hash scan is claimed for those outer files.
Source blobs executed have SHA respectively
`3c095daded8d55b0c508854383593762db72e8f663b16ba6b202ac82c146407d`
(checker) and
`ae890222cb97c8b9bc6f21f6743c55f52c505c72beec453670754c31912a038e`
(test file). The tests use synthetic AGENTS.md blobs and receipts to exercise
schema semantics; they do not establish real control execution or substitute
for a unique source mutation/patch provenance proof.

The separately committed `a03-known-unproven-state.json` is a typed pointer to
immutable first-batch inventory and explicit gaps. It is not an accepted
production evidence row. Prior c027 production gate exit1/accepted0 remains
its own source's observation; it is not relabelled as an e61 gate result.
