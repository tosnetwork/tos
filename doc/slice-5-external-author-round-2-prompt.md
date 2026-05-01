# Slice 5 External Author Trial - Round 2 Prompt

You are performing the second external author trial for TOS Slice 5
second-wave stdlib, focusing on the post-trial oracle hardening.

Use `/home/tomi/tos` on branch `actor-layer`.

Read first:

- `doc/slice-5-author-guide.md`
- `doc/slice-5-external-author-trials.md`
- `crypto/smartcont/tol-stdlib/oracle.tol`
- `examples/slice5/dex-price-oracle/src/dex-price-oracle.tol`

Trial goals:

1. Rebuild or extend a production-intent price oracle using
   `@stdlib/oracle`.
2. Use `Slice5OracleConfig.roundStarter` and pass `in.senderAddress` to
   `slice5OracleStartRound`.
3. Use a fixed-at-deploy reporter set with at least 5 reporters and
   verify deterministic median finalization.
4. Verify a compromised first reporter no longer anchors all later
   outlier checks.
5. Verify the two-report median truncation convention.
6. Import the production contract source from a tol-tester test file and
   confirm it no longer collides with generated entrypoints.

Run:

```sh
cmake --build /home/tomi/tos/build --target tol -j 32
cd /home/tomi/tos/examples/slice5/dex-price-oracle
FIFTPATH=/home/tomi/tos/crypto/fift/lib \
FIFT_EXECUTABLE=/home/tomi/tos/build/crypto/fift \
TOL_EXECUTABLE=/home/tomi/tos/build/tol/tol \
  python3 /home/tomi/tos/tol-tester/tol-tester.py tests dex-price-oracle
cd /home/tomi/tos
python3 scripts/check-slice-5-abi-manifests.py
python3 scripts/check-slice-5-release-package.py
```

Report:

- whether the updated API is sufficient for production intent;
- any remaining API friction;
- exact files created or modified;
- exact test commands and pass counts;
- whether the contract can count as external candidate 1/3 after the
  second-round fixes.
