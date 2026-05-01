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
  wakeups. `Slice5OracleConfig.roundStarter` is enforced by
  `slice5OracleStartRound`; pass `in.senderAddress` to the helper.
- Slice 5 oracle helpers support bounded reporter sets up to 255
  reporters. Median and outlier-anchor calculations iterate over the
  report map deterministically, so larger fixed-at-deploy reporter sets
  do not require a contract fork.
- Oracle `maxDeviation` outlier protection needs quorum `>= 3` when it
  is intended to resist a compromised first reporter. With quorum `2`,
  the second accepted report can only be checked against the single
  first report because no majority anchor exists yet; use quorum `2`
  only when that trust tradeoff is acceptable.
- Oracle median for an even number of accepted reports uses integer
  truncation of the average of the two middle sorted values. For the
  two-value case this is `(value1 + value2) / 2`.

Testing note: importing a `.tol` file that contains a `contract` block
into a tol-tester unit is supported for constants, types, and helper
logic. The compiler lowers only the entrypoint file's contract block, so
imported contract entrypoints do not collide with the test runner.
