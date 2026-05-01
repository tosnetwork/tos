# Slice 5 Release Checklist

Repo-side release-candidate checklist:

- [x] ABI schema exists and is hashed in `doc/slice-5-abi-freeze-record.json`.
- [x] ABI manifests exist for auction, governance, oracle, and payment-channel.
- [x] `tol new --pattern` generates all four second-wave scaffolds.
- [x] Generated scaffolds include source, smoke tests, deploy stubs,
  replay stubs, opcode maps, method-id maps, error-code maps, ABI
  pointers, and behaviour pointers.
- [x] `scripts/check-slice-5-abi-manifests.py` is green.
- [x] `scripts/check-slice-5-release-package.py` is green.
- [x] Receive-handler emulator coverage exists for security-critical
  `in.senderAddress` / `blockchain.now()` context injection.
- [x] ABI manifests annotate inbound wire fields with
  `caller_controlled: true`.
- [x] First external trial findings are closed in repo-side code/docs and
  the second-round oracle trial is recorded as passed.
- [x] At least three external production contracts using the second-wave
  stdlib are recorded with evidence. Current status: 5 production-intent
  candidates (`DexPriceOracle`, `TosStreamChannel`, `TosCouncilFund`,
  `TosEscrowedAuction`, `TosReportBondOracle`).

Release status: repo-side release-candidate complete; external adoption
gate complete.
