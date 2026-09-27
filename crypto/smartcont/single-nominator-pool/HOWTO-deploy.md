# Deploy single-nominator-pool

### 1. Generate state-init
Command:
```
./init.fif <code.boc | code.hex> <owner-address-EQ> <validator-address-Ef> <controller-address-Ef>
```

Example:
```
./init.fif snominator-code.hex EQDYDK1NivLsfSVxYE1aUt5xU-behhWSin29vgE7M6wzLMjN Ef8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAU Ef8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAU
```

The three roles: the owner holds the funds and can take them home, the validator may
spend them on a stake and on nothing else, and the controller is the account that stands
in the election. The controller is a deployed Validator Controller in the masterchain,
authorised by a post-quantum root key kept off the validator's machine; the elector takes
a stake from such an account and from nowhere else.

### 2. Sign and send a message

Command:
```
./wallet-v3.fif <filename-base> <nominator-address-Ef> <subwallet-id> <seqno> 2 -n -I snominator-init.boc
```

Example:
```
./wallet-v3.fif mywallet Ef9rfl-0S4wuAs6-rwl6RgjXznkhQaZNvlq9jMDHBlDpMe8h 698983191 7 1 -n -I snominator-init.boc
```
Expects to have `mywallet.addr` `mywallet.pk` files.
