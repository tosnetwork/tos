# Slice 5 Compatibility Matrix

| Pattern | ABI manifest | Behaviour manifest | Generated scaffold | Focused tests | External adoption |
|---|---|---|---|---|---|
| Auction | `doc/slice5-abi-manifests/auction.json` | `doc/slice4-behaviours/slice5_auction.json` | `examples/slice5/auction-scaffold/` | `slice5-auction-stdlib-positive.tol` | Pending |
| Governance | `doc/slice5-abi-manifests/governance.json` | `doc/slice4-behaviours/slice5_governance.json` | `examples/slice5/governance-scaffold/` | `slice5-governance-stdlib-positive.tol` | Pending |
| Oracle | `doc/slice5-abi-manifests/oracle.json` | `doc/slice4-behaviours/slice5_oracle.json` | `examples/slice5/oracle-scaffold/` | `slice5-oracle-stdlib-positive.tol` | 1 candidate: `DexPriceOracle` |
| Payment channel | `doc/slice5-abi-manifests/payment_channel.json` | `doc/slice4-behaviours/slice5_payment_channel.json` | `examples/slice5/payment-channel-scaffold/` | `slice5-payment-channel-stdlib-positive.tol` | Pending |

Repo-side compatibility gates are green when:

- `scripts/check-slice-5-abi-manifests.py` validates all ABI manifests.
- `scripts/check-slice-5-release-package.py` validates all generated
  projects and artifacts.
- Existing Slice 1-4 gates remain green.

Slice 5 is not production-complete until three external production
contracts adopt the second-wave stdlib and are recorded in
`doc/slice-5-abi-freeze-record.json`. Current external adoption status:
1/3 production-intent candidates recorded; the first oracle candidate
passed its second-round trial after repo-side hardening.
