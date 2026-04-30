# Writing TOS Contracts in Tol

Slice 3 projects start from stdlib patterns instead of hand-written
opcode tables.

```sh
tol new --pattern jetton --name MyJetton --output my-jetton
tol --check-only my-jetton/src/main.tol
```

The generated project contains source, a smoke test, replay/deploy
stubs, a manifest, and observability JSON files. Treat generated opcode,
method-id, and error-code maps as the contract's off-chain interface
surface.

The generator supports `jetton`, `nft`, `wallet`, and `multisig`.
