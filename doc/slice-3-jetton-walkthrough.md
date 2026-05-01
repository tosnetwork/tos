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

The reference minter rejects `addr_none` in `ChangeAdmin`. Treat admin
renouncement as a separate explicit operation in custom contracts; do not
reuse `ChangeAdmin(addr_none)` as an accidental one-way lock.

`MintRequest.queryId` is a correlation id, not a built-in replay nonce.
The reference minter preserves the TEP-74 storage layout and therefore
does not store consumed mint query ids. If production mint retries must
be idempotent, add an explicit storage-backed mint nonce in the custom
contract or enforce monotonic admin sequence numbers off-chain.

`jettonMinterErrorForThrow` and `jettonWalletErrorForThrow` are mapping
helpers for tests, off-chain decoding, and custom reply paths. The
reference contracts keep legacy throw/bounce behavior for compatibility;
`@unknown_throw` does not emit `OP_ERROR` automatically.

## Adding Custom Constraints

To add a supply cap, define a local error code constant (stdlib uses 73–75)
and guard the mint receiver:

```tol
const MAX_SUPPLY: coins = 1000000000000000000
const MY_JETTON_THROW_SUPPLY_EXCEEDED = 76

receive(msg: MyJettonMint) {
    require(jettonSameInternalAndAnyAddressBits(in.senderAddress, storage.adminAddress),
            ErrorClass.Authorization, JETTON_MINTER_FUNC_THROW_ADMIN_REQUIRED);
    require(storage.totalSupply + msg.amount <= MAX_SUPPLY,
            ErrorClass.Permanent, MY_JETTON_THROW_SUPPLY_EXCEEDED);
    msg.masterMsg;
    save(storage);
}
```
