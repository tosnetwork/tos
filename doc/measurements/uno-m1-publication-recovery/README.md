# Private generation publication measurements

The final report binds all 26 isolated controls to source commit `898b86953`.
Twelve baseline scenarios and all 312 restored baseline runs passed. The directly
registered CTest gate passed. This is private mechanism evidence, not I13e
acceptance or live integration. No activation, finality or sending gate changed.

`initial-ad4ff21eb` preserves the first completed 18-control run before review.
`diagnostic-78fab252a` preserves the later failed expectation: cases 10/11 shared
status and execution identity 211. `restoration-78fab252a` records the explicit
real-source rebuild and 12 passing baseline cases after that diagnostic stop.
`intermediate-6c14be889` is the completed 24-control intermediate version.
`final-898b86953` is the current 26-control evidence; earlier versions do not
stand in for it. `registration-control` and `missing-current-oracle` preserve
physical fixture deletion and the resulting CTest failure, followed by a fresh
successful final run. They are dependency-failure evidence, not guard evidence.

All output is complete. Empty stderr captures exist as named empty tar members.
Logs are stored in `logs.tar.zst`; other artifacts are ordinary files. Each
`artifact-manifest.json` maps original names to members/files and records their
uncompressed size and SHA-256. For example:

```
tar --zstd -xOf final-898b86953/logs.tar.zst bypass-normal-persistent-read-case-0.stderr.log
python3 reproduce-audit.py
```

The audit checks every archived byte, every event digest, committed Git blob
identities, unique mutation offsets and all restored/reapplied hashes. The
standard WorkchainBlock regression is not claimed green: fixture repair
`879e5878a` remains outside this worktree. The 54 separately rebuilt private
regression cases are recorded in `private-regressions`.

Count 220 detects the omitted normal read observation in cases 0/7/8/9; it does
not establish event ordering or exclude a forged read event. Subsequent byte
assertions are not counted as passed when 220 has already failed. Persistent
byte provenance requires a separate calibration and is not claimed by this run.
