# Poseidon2 t=8 parameter provenance

Every generated file below is produced by `manifest-gen`, which executes the
pinned upstream reference rather than re-deriving anything.

    upstream        https://github.com/HorizenLabs/poseidon2
    commit          055bde3f4782731ba5f5ce5888a440a94327eaf3

Upstream source files the constants and the permutation come from:

    plain_implementations/src/poseidon2/poseidon2_instance_bls12.rs
    plain_implementations/src/poseidon2/poseidon2.rs
    plain_implementations/src/poseidon2/poseidon2_params.rs
    plain_implementations/src/fields/bls12.rs

Their SHA-256 digests are recorded in `upstream-sources.sha256`. That file is
a record, not a check the generator performs: verify it against the pin with

    git -C <clone of the upstream> show 055bde3f4782731ba5f5ce5888a440a94327eaf3:<path> | sha256sum

## Manifest

The manifest is the byte stream defined by the work order, not a formatted
document: the tag with its NUL, the modulus, the four parameters, then every
constant as 32-byte big-endian, in order.

    bytes           19007
    sha256          57ed3c8ac13652a1bdeced6b82a53f20db32d4b02338354178ec160a68e6804c

Both VMs rebuild this stream from their own vendored tables and compare the
digest, so a constant that differs between them cannot pass unnoticed.

## Generated files

    crypto/vm/poseidon2-params.h
    crypto/vm/poseidon2-kat.h
    tosctl/src/block/src/poseidon2_params.rs
    tosctl/src/block/src/poseidon2_kat.rs
    crypto/poseidon2/manifest.bin

## Regenerating

    cd crypto/poseidon2/manifest-gen
    cargo run --release -- ../../..

The generator fails on any wrong table shape, a non-canonical constant or a
domain constant that reduces to zero. A regenerated tree that differs from the
committed one means the pin moved, and that is a consensus-visible change.
