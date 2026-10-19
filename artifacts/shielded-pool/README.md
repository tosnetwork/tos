# Shielded pool frozen inputs

`PROFILE.md` is the byte-frozen V1 implementation profile. The 2026-10-19
revision replaces its superseded V17 matrix with the shipped unified V16:
ML-DSA and Poseidon2 PERM8/HASH7/PATH7 are available at V16 on every network.
The recovery execution summary also follows the existing charge rule in §15.4.
These corrections are not a testnet-only exception and change no circuit relation
or wire encoding. It changes the profile hash and all derived deployment identities.

`genesis-manifest.json` is the generated **development** fixture, never a
production deployment. `CEREMONY.md` describes the ceremony procedure. The
finished second ceremony and its independent verification are in
[`../phase2-ceremony-2/`](../phase2-ceremony-2/README.md); a deployment must use
that audited final key and pass every acceptance gate before activation.

The [offline V16 candidate](deployments/README.md) freezes the final ceremony-2
VK, revised profile, code/data/StateInit identities and captured fee cells.
Its section-19 ledger records local evidence and the separate live GO that
has not been granted by that preparation.
