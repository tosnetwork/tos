# Shared-call routing follow-up

The first complete-regression attempt found numerical setup failure 952: the
unserved routing fixture still looked for the retired inline x{e000} encoding.
The source now changes the explicit shared-word argument 0xe000 to 0xc000 for
workchain 2. No transaction or queue expectation changed.

The independent driver copy deliberately retains the serving argument instead.
The serving half completes both real source transactions. The unserved half
reaches the first action-result check and fails at structured identity 957,
rather than a setup failure. The source copy is restored byte for byte and the
archived mutation hash is reproduced from the restored bytes. Original sources
never carried the mutation. Real candidate BOCs and result sidecars are retained;
node databases are excluded. Both actual native executables are recorded here
before any subsequent rebuild; neither contains the interpreted driver change.
The final regression follow-up archives their explicit rebuild and restored run.
