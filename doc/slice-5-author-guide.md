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
