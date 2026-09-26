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
time they are unexecuted; results will be retained separately under a one-use
resource ticket and attributed to the resulting fixed source, not this prose.
