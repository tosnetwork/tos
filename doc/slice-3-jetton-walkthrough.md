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
