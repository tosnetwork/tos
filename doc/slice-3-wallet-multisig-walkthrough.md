# Slice 3 Wallet and Multisig Walkthrough

Wallet scaffolds preserve wallet-v5's raw signed body model:

```sh
tol new --pattern wallet --name MyWallet --output my-wallet
```

The generated wallet imports `@stdlib/wallet` for signed-body parsing,
extension-action bodies, C5 action validation, and error mapping.

Multisig scaffolds use signer/threshold/replay helpers:

```sh
tol new --pattern multisig --name MyMultisig --output my-multisig
```

The generated multisig project validates signer membership, threshold
shape, proposal replay, expiry, and action-list form before saving the
pending proposal.
