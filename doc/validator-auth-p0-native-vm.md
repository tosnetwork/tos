# Native P0 signature execution

This document specifies the native execution entry used to integrate the frozen
P0 profile. It does not change the canonical wire/API schema, select a PQ suite,
activate a network, or grant owner, administration, consensus or service authority.

## Why a separate instruction is necessary

The frozen C0 signature covers the complete raw VAS1 or administration statement.
Existing `CHKSIGNS` accepts the bits of one cell, which cannot contain every such
statement. `CHKSIGNU` verifies a digest and therefore signs different bytes.
Changing either historical instruction would change existing contract behavior.

`VAUTH_CHKSIGN` uses opcode `0xf917` and stack `(message:Cell signature:Slice
public_key:Integer -- valid:Integer)`. The returned integer is -1 or 0. The public
FunC binding is `crypto/smartcont/validator-auth.fc`; native Fift and Rust
assembler/disassembler mappings use the same two bytes.

Execution requires global VM version at least 16 **and** Config8 capability
`capValidatorAuth = 1024` (`CapValidatorAuth` in Rust). The capability is immutable
VM execution metadata. Transaction execution receives it from the native compute
configuration; the SmartContract adapter receives it from its supplied native
configuration. Nested RUNVM execution inherits it. A contract cannot enable the
instruction by replacing C7. An emulator caller remains responsible for supplying
the independently trusted configuration; emulation does not authenticate a chain.

The instruction table and both native capability inventories were checked before
assignment. The allocation checker permits exactly the registered capability owner
and rejects substitution, renumbering and duplicate ownership. Removing the exact
inventoried insertion from the C++ capability header recovers its original frozen
historical hash. No historical verifier or constructor bytes were replaced.

## Carrier, signature and errors

`message` is the frozen canonical AuthBytes cell: tag `0x76616231`, version 1,
u32 length, SHA256 payload hash and exactly one canonical byte-tree reference.
This instruction admits 1 through 65536 payload bytes. Leaves contain 1 through
120 bytes; branch fanout and partition sizes must be canonical. Only ordinary
level-zero cells are admitted. The independently decoded root length bounds tree
depth, cell occurrences and allocation; a branch cannot choose the recursion
budget. Referenced cell occurrences are charged even when they repeat.

`signature` contains exactly 512 bits and no references. `public_key` must be a
nonnegative integer fitting 256 bits and is exported in big-endian byte order.
NaN and out-of-range integers raise range-check error 5; wrong operand types raise
7; stack underflow raises 2. Malformed carriers and signature shapes raise
cell-underflow error 9. Disabled instructions raise invalid-opcode error 6 under
the historical version-dependent gas/exception rules. Backend failures raise a
fatal VM error. Out of gas produces no verification result.

After structural admission, C0 uses the same owning admitted-key primitive as the
production protocol libraries. Admission requires canonical, non-identity,
prime-subgroup public keys. Verification requires canonical R and S and the
noncofactored Ed25519 equation. A valid signature with R=identity is accepted.
Invalid cryptographic material returns 0. No test bypass or classical free-signature
allowance can return authorization from this instruction.

## Metering and verification

Every admitted invocation pays 50000 base gas, one gas per decoded payload byte,
and the existing instruction, cell-load and continuation costs. The base charge
precedes payload allocation and cryptographic work. Type and arity failures retain
their specified position relative to this charge. The byte charge precedes each
leaf copy. This is a deterministic execution budget; it does not establish block,
committee or signer throughput on production hardware.

The native test driver exports actual cell BOCs, stack inputs, versions,
capabilities, limits and measured outcomes for the independent Rust VM. Tests
cover frozen real signatures for all five roles, identity R, noncanonical scalars,
key admission, exact gas exhaustion, repeated calls, malformed partitions,
operand errors, disabled versions and nested execution. Guard removals must
compile and fail an assertion; a panic or compiler failure is not a killed guard.

A separate FunC probe is compiled through the public binding and executed as a
whole transaction in both engines. It must successfully send a message, refuse an
invalid signature, refuse execution with the capability absent, and roll back
storage when the action phase cannot fund its send. The comparison includes
compute exit, action result, out-message hashes, balance and final contract data.
The probe is test code, not a deployable owner or elector authorization contract.

Native owner/elector admission, committee/session derivation, consensus routing,
public RPC and multinode acceptance remain separate implementation work. Enabling
the capability or compiling this instruction does not satisfy those boundaries.
