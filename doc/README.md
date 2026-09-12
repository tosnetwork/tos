# TOS Documentation

This directory contains the base-layer specifications, the formal papers, and
the manuals for running and testing a node. Design proposals, implementation
plans, use-case explorations and draft RFCs live in the separate documentation
repository at <https://github.com/tosnetwork/doc>; source comments that cite
them link there directly.

## Specifications

- [ConfigParam.md](ConfigParam.md) - configuration parameters
- [Currency.md](Currency.md) - currency units
- [DNS.md](DNS.md) - TOS DNS
- [GlobalVersions.md](GlobalVersions.md) - global versions and the capabilities each enables
- [TosSites.md](TosSites.md) - TOS sites and the RLDP HTTP proxy
- [Zerostate.md](Zerostate.md) - zerostate format
- [openapi.yaml](openapi.yaml) - the REST surface; a running node advertises this path from `/api-info`

## Post-quantum authentication

- [tvm-mldsa44.md](tvm-mldsa44.md) - the native ML-DSA-44 verification instruction: opcode, ABI, canonical operand encoding, gas, version gating and the vendored backend
- [tvm-mldsa44-validation.md](tvm-mldsa44-validation.md) - acceptance matrix, calibration method and the limits of what the public vectors prove
- [mldsa44-auth-module.md](mldsa44-auth-module.md) - the immutable authentication module, exact signed bytes, funding failure classes and deployment boundary

## Running and testing a node

- [FullNode.md](FullNode.md) - running a full node
- [LiteClient.md](LiteClient.md) - using the lite client
- [Validator.md](Validator.md) - running a validator
- [Validator-Local.md](Validator-Local.md) - a local four-node testnet
- [validator-genesis-bootstrap.md](validator-genesis-bootstrap.md) - genesis validator bootstrap
- [macos-local-node.md](macos-local-node.md) - running a local chain on macOS, where the systemd setup script does not apply

## Release process

- [tos-release-policy.md](tos-release-policy.md)
- [tos-upgrade-process.md](tos-upgrade-process.md)

## Papers

`The-TOS-Protocol` states the protocol; `tblkch` and `tvm` describe the block
chain and the virtual machine; `catchain` and `simplex` describe consensus;
`fiftbase`, `func_v0.4.6` and `tol` describe the languages. Each is kept with
its TeX source where one exists.
