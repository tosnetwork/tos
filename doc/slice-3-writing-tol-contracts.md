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

## ErrorClass Reference

`ErrorClass` is an enum defined in `@stdlib/slice3-common`. Valid members:

| Member | Meaning |
| --- | --- |
| `Ok` | No error |
| `Transient` | Retry may succeed (e.g. insufficient gas) |
| `Permanent` | Will never succeed (e.g. supply cap exceeded, wrong state) |
| `Authorization` | Sender not permitted |
| `Protocol` | Malformed message or unknown opcode |
| `BackPressure` | Insufficient attached value |

## Custom Error Codes

Define project-specific throw codes as top-level constants and pass them
as the third argument to `require`:

```tol
const MY_CONTRACT_THROW_SUPPLY_EXCEEDED = 76

require(storage.totalSupply + msg.amount <= MAX_SUPPLY,
        ErrorClass.Permanent, MY_CONTRACT_THROW_SUPPLY_EXCEEDED);
```

For the generated Jetton scaffold, existing minter throw codes use the
73–75 range, so start local minter-specific codes at 76 unless your ABI
reserves a different range. Your custom codes appear in
`artifacts/error-codes.json` once generated.
