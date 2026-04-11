# Testing TOS

This repository includes unit and integration-style binaries covering core crypto, VM, networking, storage, validator, and toslib behavior.

## Build

Use the verified build flow in [BUILD.md](../BUILD.md).

If the tree is already configured:

```bash
cd build
ninja -j128
```

## Discover Tests

List the registered tests:

```bash
cd build
ctest -N
```

## Run the Full Suite

```bash
cd build
ctest --output-on-failure -j128
```

To size parallelism dynamically:

```bash
JOBS=$(( $(nproc) * 2 / 3 ))
ctest --output-on-failure -j"${JOBS}"
```

## Verified Result

The current tree has been verified with:

- `ninja -j128`
- `ctest --output-on-failure -j128`

Observed result:

- `31/31` tests passed

## Coverage Areas

The suite includes tests for:

- cryptography and bigint
- TVM and Fift
- cells and smart contracts
- tdactor and tdutils
- ADNL, DHT, RLDP, catchain
- validator-session
- database and storage
- toslib offline and FFI helpers

## CI Guidance

Prefer `ctest --output-on-failure` in automation so failures are visible immediately.
