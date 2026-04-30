# Slice 3 Jetton Walkthrough

Generate a project:

```sh
tol new --pattern jetton --name MyJetton --output my-jetton
```

The scaffold imports `@stdlib/jetton`, declares a mint receiver, and
uses Jetton constants/error codes from the stdlib. The generated
`artifacts/opcodes.json` is the indexer-facing opcode map; update it
when adding custom Jetton operations.

Keep TEP-74 bodies raw when preserving `any_address` fields or exact
inline/ref body placement matters.
