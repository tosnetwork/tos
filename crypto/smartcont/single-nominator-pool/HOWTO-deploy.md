# Deploy single-nominator-pool

A pool has two roles. Their initial values are its storage at deployment and therefore
determine its address:

- the **owner** holds the funds and can take them home;
- the **validator** is the masterchain wallet that may spend them on a stake and on
  nothing else (the contract refuses a stake request from any other workchain).

The pool itself stands in the election: the elector names a member by the account that
sent its stake, so the pool's address is the member's identity and the post-quantum
consensus key travels in the stake request it relays. The owner can later replace the
validator address (`CHANGE_VALIDATOR_ADDRESS`, for example after the validator wallet is
compromised); the pool's address does not change when it does. The rest of the validator
path is described in [doc/validator-operator-guide.md](../../../doc/validator-operator-guide.md).

`tosctl deploy pool --node NODE --owner OWNER --amount TOS` performs the steps below from
a node's configured validator wallet. To do it by hand:

### 1. Generate the state-init

Command:
```
./init.fif <code.boc | code.hex> <owner-address> <validator-address> <file-base>
```

Example:
```
./init.fif single-nominator-code.hex <OWNER_ADDRESS> <VALIDATOR_WALLET_ADDRESS> snominator
```

The pool is always in the masterchain. The script prints the StateInit and the pool's
address, saves the address in `<file-base>.addr` and the StateInit in
`<file-base>-query.boc` (`snominator-query.boc` in the example).

### 2. Sign and send the deployment message

Command:
```
./wallet-v3.fif <filename-base> <pool-address> <subwallet-id> <seqno> <amount> -n -I <file-base>-query.boc
```

Example:
```
./wallet-v3.fif mywallet <POOL_ADDRESS> 698983191 7 1 -n -I snominator-query.boc
```

Expects `mywallet.addr` and `mywallet.pk` files. `-n` sends the message non-bounceable,
because the pool does not exist yet. The script saves the signed message to
`wallet-query.boc`; send it with a lite client (`sendfile wallet-query.boc`).

### 3. Before the first stake

Record the pool in tosctl with `tosctl config pool add --name POOL --address
POOL_ADDRESS --owner OWNER_ADDRESS` and bind it to the node with `tosctl config bind add
--node NODE --wallet WALLET --pool POOL`. A raw masterchain address can be given as
`--owner -1:<hex>` or `--owner=-1:<hex>` (likewise `--address`).
