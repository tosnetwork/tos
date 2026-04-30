# Slice 5 Author Guide

Slice 5 adds four second-wave stdlib patterns:

- `@stdlib/auction`
- `@stdlib/governance`
- `@stdlib/oracle`
- `@stdlib/payment-channel`

Start a project with:

```sh
tol new --pattern auction --output my-auction
tol new --pattern governance --output my-governance
tol new --pattern oracle --output my-oracle
tol new --pattern payment-channel --output my-channel
```

Each generated project includes source, a smoke test, deploy skeleton,
replay stub, opcode map, method-id map, error-code map, ABI manifest
pointer, and behaviour-conformance pointer. The generated source is a
small scaffold; production contracts should import the relevant stdlib
package and then follow the focused examples under `examples/slice5/`.

Compatibility rules:

- Keep opcode-bearing messages at 32-bit opcodes with `queryId`
  immediately after the opcode when request/reply correlation applies.
- Do not emit `ErrorClass.BackPressure` from new Slice 5 code.
- Payment-channel signed states use Ed25519 over
  `Slice5PaymentSignedState.toCell().hash()`, not raw source bytes.
- Governance action lists are policy-typed. `SetCode`, `SetData`,
  reserve, and library actions are rejected by default.
- Oracle examples use fixed-at-deploy reporter sets; each round records
  the reporter-set hash snapshot.
- Oracle round starts are ordinary contract messages, not protocol
  wakeups. Production contracts must gate the receive handler before
  calling `slice5OracleStartRound`, typically with an address allowlist
  or a signature checked by the contract.
- Slice 5 oracle helpers intentionally cap inline aggregation at three
  reports. Larger reporter sets need a later dict-only aggregation path
  or a contract-specific fork.
- The two-value oracle median uses integer truncation:
  `(value1 + value2) / 2`.

Testing note: importing a `.tol` file that contains a `contract` block
into a tol-tester unit can collide with the generated entrypoint. For
contract-level receive-handler behavior, either test the helper logic
directly or use an emulator/replay fixture instead of importing the
contract source into another Tol file.
