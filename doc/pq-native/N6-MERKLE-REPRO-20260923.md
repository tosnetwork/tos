# N6 Merkle exact-ancestor investigation — component reproduction

Status: **component mechanism reproduced; historical actor ordering remains unproved**.

The investigation branch `n6/merkle-repro-investigation` adds
`test-consensus-simplex2-merkle-skipped-exact-ancestor-repro`. It calls the
production `select_skipped_slot_resolution()` with an exact requested
`CandidateId`, an installed slot-level SkipCert indication, and no locally
installed NotarCert. The current policy selects `UseAvailableBase`. The test
then constructs the consensus fixture's real Merkle update from state height
`N` to `N+1` and applies it both to the exact state `N` and to the
skip-selected older state `N-1`.

The correct application succeeds. The older base fails with the same complete
hashes as both retained September errors:

| Expected parent | Selected base | Expected old hash | Applied-to hash |
| --- | --- | --- | --- |
| 5 | 4 | `C8D1E14FE26D8983DA2383CF719AFF88B3F9EFA8A5B09C625AB12EFFC2926932` | `92345EFB21EC9E506E9FDB654AC3E84E46282531698C7F6AF88877245121DD54` |
| 23 | 22 | `69A2DC37E67A1D7398E4D188E1468DD4CEB1181358C0CAB56BAE28BF661F8FAA` | `19088211A6DB566029368CE0D6F45C68DF030896091F186C070725F49A43CB57` |

Run the component test with:

```sh
cmake --build build --target test-consensus -j2
ctest --test-dir build -R '^test-consensus-simplex2-merkle-skipped-exact-ancestor-repro$' -V
```

The local raw logs are retained under
`/home/tomi/tos-carrier/merkle-repro-artifacts/`. The first green log has
SHA-256 `276c4f6c4bab0c9c4c386474a6b85fb43b8cc1385ea7f685fd0e6d5dd3c81d07`.
Changing only the no-installed-notar branch of
`select_skipped_slot_resolution()` to `ResolveCandidate` made this test fail
at its decision assertion; the red log has SHA-256
`39bafe854ada03dced3d40c2d89f9f67a393d113ae4210d1d446ad387d0794`.
Restoring the production branch made it pass again; that log has SHA-256
`8b7f067c41da2ffb4113951109505e77f8f1c6ff767db4b2ca409f43debb3e8b`.
The mutation was removed from the investigation branch.

This is an executable counterexample to the local skip decision plus Merkle
state transition. It does **not** run `StateResolverImpl`, prove that a
descendant actually names this candidate under a particular certificate
arrival order, or reconstruct either original failure's lost CandidateId and
stack. The next required result is a deterministic actor or integration test
that holds `SaveCertificate(NotarCert(P))` while SkipCert(P.slot) is installed,
drives resolution of a descendant that explicitly names P, and records a red
N/N-1 result with the shortcut versus a green exact-ancestor result without
it. Keep `merkle-base-state-mismatch` OPEN until that result and the required
consensus regressions exist.
