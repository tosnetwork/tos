# Authenticated public-pool pin fixture

`epoch6-public-pool.json` contains only public code/configuration cells and a public
1248-byte ceremony verifying key, extracted from the Epoch-6 account state proved
at the full masterchain block named in `provenance`. The native verifier checked
the account from the full approved zerostate. This is not a live/activation receipt.

The code cell's representation hash is
`ce3b21bc64e392e14065e68665228bcb10e40dd83836ef00574dd90e5ce057cd`.
It is identical to the code cell used by the retained ceremony-key local end-to-end
run. All fifteen contract source hashes in that run match base `d8e8f46c8`.
The config carries the known profile, Poseidon manifest and ceremony-key hashes;
the fixture records the original proof-receipt digest and full chain/block identity.
It contains no wallet identity, seed, descriptor, transaction or proving witness.

The full native receipt/material and code comparison are retained on the build
host under `/tos/build/e6-public-relayer-d8e8f46c8`, through 2027-02-01 UTC,
accessible using the existing authorized build-host access. The initial acquisition
before the SSH tunnel was ready was refused; it is retained separately. The accepted
proof is `public-pool-proof-r2.json` and its `public-pool-material-r2` bundle.
Regenerate with the native verifier and extract only these immutable public inputs;
never substitute an RPC-only account or a changed code hash merely to satisfy a test.
