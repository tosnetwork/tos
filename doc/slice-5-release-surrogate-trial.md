# Slice 5 Release Surrogate Trial

Stage 6 surrogate:

1. Generate four projects with `tol new --pattern auction`,
   `governance`, `oracle`, and `payment-channel`.
2. Run `tol --check-only src/main.tol` in each generated project.
3. Run each generated smoke test with `tol-tester`.
4. Validate every generated JSON artifact.
5. Validate behaviour and ABI manifest pointers.

Result: the repo-side surrogate is automated by
`scripts/check-slice-5-release-package.py`. It proves the release package
shape, not external production adoption.
