# Avata rt.jar Design From OpenZeppelin Requirements

Status: working design
Date: 2026-05-05

This document defines how the Avata `rt.jar` should evolve from a slim Java 8
runtime into a deterministic smart-contract runtime. OpenZeppelin Contracts is
used as the requirements corpus, not as a Solidity/EVM implementation that must
be copied literally.

The design goal is:

> Avata executes normal Java 8 class files and ships a deterministic contract
> runtime that lets Java contracts express the business patterns proven by
> OpenZeppelin.

The goal is not full OpenJDK class-library compatibility, and it is not full EVM
semantic compatibility. Java 8 bytecode/opcode compatibility remains the hard VM
commitment. `rt.jar` is the TOS contract API surface.

## Inputs

The local reference checkout is `~/openzeppelin-contracts`.

Observed source state:

- Package: `openzeppelin-solidity`
- Version: `5.6.1`
- Commit: `6dd405a0`
- Contract files under `contracts/`: 349 Solidity files

The local web3j reference checkout is `~/web3j`. web3j is used as the Java API
reference for Ethereum-compatible typed values, ABI function/event signatures,
and selector calculation. Its off-chain RPC `Contract` abstraction is not a
runtime model for Avata contracts; Avata contracts execute on-chain and need
native deterministic `java.lang` APIs for context, storage, events, calls, and
reverts.

Top-level source distribution:

| Area | Solidity Files | Runtime Signal |
|---|---:|---|
| `utils` | 73 | math, cryptography, ABI-like bytes utilities, structs, guards |
| `token` | 50 | ERC20, ERC721, ERC1155, ERC6909, metadata, permits, votes |
| `interfaces` | 43 | standards and interface IDs |
| `governance` | 23 | proposals, votes, timelocks, signatures, checkpoints |
| `access` | 14 | ownership, roles, authorities |
| `proxy` | 11 | upgradeability, code indirection, storage slots |
| `crosschain` | 10 | bridge message formats and authorization |
| `account` | 7 | account abstraction patterns |
| `metatx` | 2 | trusted forwarders and meta-transactions |
| `finance` | 2 | vesting and token release schedules |

High-frequency EVM/Solidity primitives found in the corpus:

| Primitive | Count | Avata Meaning |
|---|---:|---|
| `call` | 295 | cross-contract call or EVM-only low-level call |
| `keccak256` | 146 | deterministic crypto primitive |
| `msg.sender` | 96 | caller context |
| `abi.encode` | 37 | canonical byte encoding |
| `msg.value` | 36 | value attached to a call |
| `abi.encodePacked` | 34 | compact byte encoding |
| `msg.data` | 25 | raw call payload |
| `tstore` / `tload` | 25 / 19 | transaction-scoped temporary storage |
| `delegatecall` | 21 | EVM-specific code execution in caller storage |
| `block.timestamp` | 21 | deterministic block context |
| `staticcall` | 19 | read-only cross-contract call |
| `abi.decode` | 16 | canonical byte decoding |
| `abi.encodeCall` | 13 | typed call encoding |
| `block.chainid` | 11 | chain context |
| `create2` | 9 | deterministic EVM deployment address |
| `block.number` | 9 | deterministic block context |
| `sstore` | 8 | persistent storage write |
| `ecrecover` | 7 | signature recovery |

These primitives show that the important work is not adding more OpenJDK APIs.
The important work is defining deterministic contract primitives for caller
context, storage, events, crypto, ABI encoding, typed values, and cross-contract
interaction.

## Runtime Layering

`rt.jar` should be organized into four layers.

| Layer | Package Area | Purpose |
|---|---|---|
| 0 | standard-shaped `java.lang`, VM-required internals | Java language and class-file execution support |
| 1 | admitted `java.io`, `java.util` | deterministic Java conveniences for transient computation |
| 2 | Avata extensions in `java.lang` | chain context, storage, ABI, events, crypto, calls, fixed numeric types |
| 3 | OpenZeppelin-inspired contract libraries in `java.lang` | reusable contract business patterns |

All new contract-facing Java classes should live directly in the `java.lang`
package, not under `tos.*`. This is a deliberate Avata/TOS runtime extension:
the shipped `rt.jar` is our own contract runtime, so it may define classes that
do not exist in OpenJDK's `java.lang`. The benefit is that core contract types
such as `Address`, `Uint256`, `Bytes32`, and `Context` are automatically visible
to Java source without imports.

These classes are still TOS-specific APIs. Their package placement does not make
them Java SE APIs, and the verifier/toolchain must reject contracts that assume
they exist on a general-purpose OpenJDK runtime.

## Java Package Policy

### `java.lang`

`java.lang` is for Java language semantics and VM linkage. It should remain
small and deterministic.

Admit:

- `Object`, `Class`, `String`, `StringBuilder`
- primitive wrappers and `Number`
- core exceptions, errors, and stack-trace structures
- `Enum`, `Iterable`, `Comparable`, `CharSequence`, `Appendable`
- Java 8 lambda linkage classes under `java.lang.invoke`
- VM-required reflection, annotation, and reference classes
- `Storage` and `Mapping` as deterministic primitives for contract state
- `Math`, only when every operation is backed by bit-exact deterministic
  algorithms. The v1 profile keeps arithmetic helpers such as min/max/abs,
  signum, round, floor, and ceil; it does not admit host-native randomness or
  libm-backed transcendental functions such as sqrt, pow, sin, cos, log, or exp.
  Float/double string parsing and formatting are also omitted until they have a
  pinned software implementation.

Restrict or reject:

- `Thread`, `ThreadGroup`, `ThreadLocal`, `InheritableThreadLocal`, wait/notify,
  and scheduling APIs
- `Runtime`; contract code must not reach a host runtime facade
- `System` host APIs such as wall-clock time, environment, properties, native
  library loading, and host IO
- identity behavior derived from native object addresses

`java.lang.System` may expose only deterministic VM-managed streams and strictly
specified helpers. It must not expose a mutable `Properties` object or
host-derived property map. Chain data belongs in Avata's `java.lang.Context`,
not in host-style `System` APIs. `System.in` is deterministic EOF, because a
contract must not read host stdin.

### `java.io`

`java.io` is not a filesystem API in the consensus profile.

Admit:

- byte-array streams
- string readers and writers
- basic `InputStream`, `OutputStream`, `Reader`, `Writer`
- `PrintStream` and `PrintWriter` for deterministic VM-managed output
- `IOException` for stream failures
- `Serializable` only as a marker if the verifier/profile admits it

Reject or remove:

- path-based host filesystem access
- file metadata, directory traversal, permissions, locking, and host path
  normalization
- public native file descriptors and file streams; `System.in/out/err` must use
  VM-private standard-stream implementations instead of exposing
  `FileDescriptor`, `FileInputStream`, or `FileOutputStream`
- file-specific exceptions such as `FileNotFoundException`, because the profile
  has no host filesystem API

OpenZeppelin requirements do not need host files. Contract persistence must use
Avata's `java.lang.Storage` and related persistent types.

### `java.util`

`java.util` is for transient deterministic computation, not persistent contract
state. Contract state must not depend on `HashMap` or `HashSet` bucket order,
identity hash behavior, implementation resize policy, or iteration order.

Admit first:

- `List`, `Map`, `Set`, `Collection`, `Iterator`
- `ArrayList`, `TreeMap`, `TreeSet` if their behavior is pinned and tested for
  transient use
- `Arrays`, `Collections`, `Objects`, `Optional`, `Comparator`
- `ArrayDeque`, `Queue`, `Deque`
- `java.util.function.*` for Java 8 source compatibility

Reject or remove:

- `HashMap`, `HashSet`, `LinkedHashMap`, and `LinkedHashSet`, because contract
  behavior must not depend on hash bucket order, resize policy, or
  implementation-defined hash behavior
- `Hashtable` and `Properties`, because they combine hash iteration with
  host-style mutable property state
- `IdentityHashMap`, because object identity must be consensus-safe
- `WeakHashMap`, because weak-reference clearing depends on GC timing

- `Vector`, `Stack`, `StringTokenizer`, and `Enumeration`, because the contract
  profile uses explicit list/deque/iterator APIs instead of legacy synchronized
  or pre-collection surfaces
- `Collections.synchronizedMap`, `synchronizedSet`, `synchronizedList`, and the
  generated synchronized wrapper classes, because the profile is single-threaded
  and must not expose concurrency-oriented collection APIs
- `StringBuffer`, because the profile uses `StringBuilder` and does not expose
  legacy synchronized string builders

Do not use `java.util` collections as implicit persistent storage. Persistent
state needs explicit `java.lang` storage types so serialization, gas, iteration,
and cell layout are specified.

## Avata `java.lang` Contract Extensions

The OpenZeppelin corpus implies these Avata-specific `java.lang` classes. The
names below are design names; final naming should be frozen in the admitted API
profile before implementation.

### `java.lang.Context`

Required APIs:

- `Context.caller()`
- `Context.value()`
- `Context.data()`
- `Context.contractAddress()`
- `Context.chainId()`
- `Context.blockNumber()`
- `Context.blockTimestamp()`
- `Context.isStaticCall()`
- deterministic revert and requirement helpers

This class replaces Solidity's `msg.*`, `block.*`, and `tx.*` model with a TOS
model. The names should not pretend to be Ethereum if the semantics are
different.

### `java.lang` Value Types

Required value types:

- `Address`
- `Uint256`
- `Int256` if signed 256-bit arithmetic is admitted
- `Bytes32`
- `Bytes4`
- bounded immutable byte strings
- fixed-point numeric types if contracts need decimal arithmetic

OpenZeppelin token and governance code assumes `uint256`, `bytes32`, `bytes4`,
and `address` are first-class. Java `long` is not enough, and `java.math` is not
currently part of the slim runtime. Avata should provide narrow, audited
`java.lang` value types rather than importing broad OpenJDK `BigInteger`
behavior by default.

### `java.lang.Storage`

Required APIs:

- scalar slots
- typed mappings
- nested mappings
- persistent arrays or vectors
- enumerable sets and maps when explicitly admitted
- transaction-scoped temporary storage if Avata chooses to support a `tload` /
  `tstore` equivalent

Storage must be cell-native. Every persistent type must define:

- canonical key encoding
- canonical value encoding
- default value behavior
- deletion behavior
- iteration order, or state that iteration is not supported
- gas cost for read, write, delete, allocation, and iteration
- snapshot/rollback semantics for failed calls

The admitted Java API starts with a slot-addressed `Storage` abstraction:

- `load(Bytes32 slot)`
- `store(Bytes32 slot, byte[] value)`
- `clear(Bytes32 slot)`
- `contains(Bytes32 slot)`

Every `Contract` owns a `Storage` instance. The current runtime has an in-memory
storage backend for tests and local execution, plus a native-host storage shape
that calls `nativeLoad`, `nativeStore`, and `nativeClear` with raw slot/value
bytes. The VM backend should bind those native methods to account-state
database access while preserving the slot API.

The current C++ native bridge is intentionally narrow: it stores and returns
raw byte values by 32-byte slot and performs defensive copying at the Java
boundary. The checked-in backend exposes `avata_set_storage_host()` in
`include/avata/storage.h`. Production consensus execution must install that
host before invoking Java contract code. The host callbacks map exactly to
`load`, `store`, and `clear` and receive raw 32-byte slots plus raw byte values.
`load` returns a nullable byte buffer: `null` means the slot is absent, while a
non-null buffer must be released through the optional host `freeValue` callback
or through `free()` if no callback is installed.

The native bridge now charges storage helper gas before host/fallback access
from the VM helper-cost table: `load` has a fixed cost, `clear` has a fixed
cost, and `store` charges a fixed base plus a per-byte cost. The checked-in
table values are standalone defaults for the current Avata profile; the final
workchain adapter should source the schedule from the consensus gas
configuration through `avata_set_contract_helper_gas_costs()`.

The execution adapter should bracket each Java contract invocation with
`avata_storage_execute_transaction()`. That wrapper calls
`avata_storage_begin_transaction()`, runs the supplied invocation callback, then
commits only when the callback returns `AVATA_STORAGE_OK`; all other callback
results roll the storage transaction back and are returned to the caller.
Adapters that need lower-level control may call
`avata_storage_begin_transaction()`, `avata_storage_commit_transaction()`, and
`avata_storage_rollback_transaction()` directly. Installed hosts may provide
optional transaction callbacks for their own write-set journal. If no host is
installed, Avata uses a deterministic process-local reference implementation
with nested snapshots for tests. The production blockchain backend must replace
that fallback with the execution host's account-state overlay, including write
journaling and rollback on failed calls. Storage helper gas is charged by the
Avata native bridge before callbacks reach that host.

The checked-in `StorageHostReferenceAdapter` unit test models the expected host
adapter behavior: every load/store/clear charges deterministic gas, writes are
journaled before mutation, nested transaction commits merge their journal into
the parent transaction, and rolling back the parent restores the pre-call state.
The production adapter should preserve those semantics while persisting the
committed write set into the TOS account-state database.

OpenZeppelin's `mapping(address => uint256)` and
`mapping(bytes32 => mapping(address => bool))` patterns should be directly
expressible through this API.

The first admitted container for these patterns is `java.lang.Mapping<K,V>`.
It is modeled after Ethereum mappings:

- keys are converted to canonical bytes, then hashed with Keccak-256
- each mapping has a stable namespace, and nested mappings derive their
  namespace from the parent slot
- supported key types are explicitly whitelisted, such as `Address`,
  `Uint256`, `Bytes32`, `Bytes4`, `Bytes`, `String`, and primitive wrappers
- no iteration API is exposed; enumerable state must use a separately specified
  deterministic ordered container
- `Mapping` does not own data; `get`, `put`, and `remove` derive a `Bytes32`
  slot and delegate to `Storage.load`, `Storage.store`, and `Storage.clear`
- values are encoded and decoded through `StorageCodec<T>`; Java objects are not
  written directly to storage

`Mapping` is the correct primitive for ERC20 balances and allowances, ERC721
ownership and approvals, ERC1155 balances, ERC6909 accounting, role membership,
and nonce state. A host-backed `Storage` implementation must preserve the same
key and namespace derivation rules.

### `java.lang.Event`

Required APIs:

- event declaration helpers
- indexed topics
- canonical event payload encoding
- event emission
- deterministic log ordering

ERC20, ERC721, ERC1155, Ownable, AccessControl, Governor, and Timelock all rely
on events as part of their external behavior. Events must be part of the
committed execution result, not best-effort stdout text.

### `java.lang.ABI`

Required APIs:

- canonical encoding and decoding for admitted TOS types
- method selectors or entry identifiers
- interface identifiers
- packed encoding when the profile admits it
- structured error encoding

This class is inspired by Solidity ABI needs but should be specified as the TOS
JVM ABI. If Ethereum ABI compatibility is desired for a subset, document it as
an explicit compatibility mode.

### `java.lang.Crypto`

Required APIs:

- Keccak-256
- SHA-256 if admitted by contract standards
- secp256k1 ECDSA verification and recovery if account/signature compatibility
  requires Ethereum-style signatures
- TOS-native signature verification primitives
- Merkle proof helpers
- EIP-712-like typed-data hashing only if the TOS ABI and domain model are
  specified

Do not expose `java.security` as a broad provider framework in v1. Crypto used
by consensus must be narrow, deterministic, audited, and gas-metered. A compact
`java.lang.Crypto` facade may delegate internally to smaller audited helper
classes, but the public contract surface should remain in `java.lang`.

### `java.lang.ContractCall`

Required APIs:

- typed cross-contract call
- read-only/static call
- value transfer
- return-data and revert-data propagation
- reentrancy behavior
- gas forwarding policy

Defer or reject in v1 unless explicitly specified:

- `delegatecall`
- arbitrary low-level byte call
- EVM `create2`
- proxy code execution in caller storage

These are EVM execution-model features, not generic smart-contract business
requirements. Java contracts can support upgrade and factory patterns, but the
mechanism should be native to TOS rather than copied blindly.

### `java.lang` Contract Libraries

This is the Java contract library layer inspired by OpenZeppelin.

Initial classes or class families:

- `Ownable`
- `Ownable2Step`
- `AccessControl`
- `Pausable`
- `ReentrancyGuard`
- `ERC20`
- `ERC721`
- `ERC721Holder`
- `ERC1155`
- `ERC1155Holder`
- `ERC2981`
- `ERC6909`
- `MerkleProof`
- `SafeCast`
- `Governor`

These classes should be normal Java source compiled against `rt.jar`. They
should not be VM magic unless they need privileged access to Avata VM
primitives.

### OpenZeppelin Interface Policy

OpenZeppelin interfaces are requirements signals, not a mandate to copy every
Solidity interface into `rt.jar` immediately. Avata should admit an interface
only when one of these is true:

- the corresponding Java contract/library is implemented in the admitted Avata
  profile
- the interface is needed for typed cross-contract calls in that profile
- the interface identifies a standard that Avata deliberately chooses to expose
  to external callers

The first admitted interface set is:

- `IERC165`
- `IAccessControl`
- `IERC20`
- `IERC20Metadata`
- `IERC20Errors`
- `IERC721`
- `IERC721Metadata`
- `IERC721Receiver`
- `IERC721Errors`
- `IERC1155`
- `IERC1155MetadataURI`
- `IERC1155Receiver`
- `IERC1155Errors`
- `IERC5313`
- `IERC2981`
- `IERC2981Errors`
- `IERC6909`
- `IERC6909Metadata`
- `IERC6909ContentURI`
- `IERC6909TokenSupply`
- `IERC6909Errors`

This matches the first implemented Java libraries: `AccessControl`, `ERC20`,
the core `ERC721` ownership and approval model, and the core `ERC1155`
multi-token balance and approval model, plus the `Ownable` ownership getter and
ERC2981 royalty signaling. ERC6909 is admitted as the compact multi-token
accounting model with per-id allowances, operators, metadata, content URI, and
token supply extensions. ERC721 and ERC1155 receiver interfaces are admitted
with holder implementations for typed callback boundaries; transfer-time
receiver enforcement still waits for `ContractCall` semantics. Later interfaces
such as `IERC2612`, `IERC4626`, governance interfaces, and proxy/account
interfaces should be added when the corresponding storage, event, signature,
call, and token semantics are implemented and tested. Empty interface shells
should be avoided unless they are explicitly part of a typed call boundary.

## OpenZeppelin Capability Mapping

| OpenZeppelin Area | Required Avata Runtime Surface | v1 Policy |
|---|---|---|
| `Ownable`, `Ownable2Step` | `Context`, `Address`, storage slot, events, custom errors | Admit early |
| `AccessControl` | `Bytes32`, nested mappings, events, role admin storage | Admit early |
| `ERC20` | `Uint256`, `Address`, mappings, events, custom errors | Admit early |
| `ERC721` | token ID mappings, approvals, receiver callback, metadata strings | Admit core ownership/approval early; admit receiver holder now; enforce receiver callback after `ContractCall` |
| `ERC1155` | batch arrays, nested balances, receiver callback, URI events | Admit core balance/approval early; admit receiver holder now; enforce receiver callback after `ContractCall`; URI events after `Event` |
| `ERC2981` | royalty receiver and sale-price fraction calculation | Admit early; signaling only, no payment enforcement |
| `ERC6909` | multi-token ID accounting, per-id allowances, operators, metadata, content URI, token supply | Admit core and simple extensions early |
| `Pausable`, `ReentrancyGuard`, `Nonces` | context, storage, call-depth/reentrancy policy | Admit early |
| `Math`, `SafeCast`, `SignedMath` | `Uint256`, signed arithmetic, overflow rules | Admit early |
| `MerkleProof`, `Hashes` | `Bytes32`, Keccak/SHA helpers | Admit early |
| `ECDSA`, `MessageHashUtils` | secp256k1 recover/verify, canonical signatures | Admit if TOS account model needs it |
| `EIP712`, permits, votes by signature | ABI/domain model, nonces, signature verification | Admit after ABI and crypto |
| `Governor`, `Timelock`, `Votes` | checkpoints, block/time abstraction, signatures, proposal storage | Defer until token layer is stable |
| `Proxy`, `ERC1967`, `UUPS`, `Clones` | code indirection, deterministic deployment, storage slot policy | Defer; do not clone EVM mechanism blindly |
| `Account`, ERC4337/7579/7702 | account abstraction, validation flow, paymaster model | Defer; TOS-specific design needed |
| `metatx` | trusted forwarder and caller override model | Defer; conflicts with simple caller semantics |
| `crosschain` | bridge message verification and remote identity | Defer to TOS bridge design |
| `finance` vesting | timestamp, token transfer, arithmetic | Admit after ERC20 |

## Error and Revert Model

OpenZeppelin uses custom errors and reverts as part of public behavior. Avata
needs a deterministic equivalent.

Required behavior:

- contract assertions and requirements produce deterministic errors
- errors have stable selectors or identifiers
- error payloads are ABI-encoded through `java.lang.ABI`
- failed calls roll back persistent storage writes and emitted events from the
  failed scope
- `OutOfGasError` and `ContractViolationError` are consensus traps, not
  catchable business errors unless explicitly specified

Java exceptions may be the implementation mechanism, but the contract ABI must
define what external callers observe.

## Gas Model Requirements

Every admitted API must have deterministic gas costs.

Required metering areas:

- bytecode execution (implemented with a 256-entry opcode table and flat
  standalone defaults)
- object allocation (dynamic word-count surcharge implemented for Java `new`
  bytecode; fixed base cost belongs in the opcode table)
- array allocation (dynamic base/element surcharge implemented for Java array
  allocation bytecodes; fixed base cost belongs in the opcode table)
- array copy (baseline metering implemented for `System.arraycopy()`)
- native method calls (fixed native-call surcharge implemented at the VM native
  invocation boundary; dynamic helpers add input-size costs where needed)
- string operations when backed by native/VM helpers; pure Java string logic is
  covered by opcode gas and `System.arraycopy()` when it copies arrays
- `Uint256` arithmetic
- hashing and signature verification
- storage reads and writes (baseline native helper metering implemented)
- storage iteration
- ABI encode/decode
- event emission
- cross-contract calls

APIs with unbounded work, such as enumerable map clearing or returning all keys,
must either be gas-metered precisely, require explicit bounds, or be forbidden in
state-changing calls.

## Determinism Rules

The runtime must not expose validator-local state.

Forbidden unless explicitly admitted with deterministic semantics:

- host filesystem
- host network
- process APIs
- native library loading
- wall-clock time
- entropy
- locale-sensitive formatting
- timezone-sensitive formatting
- host classpath/classloader access
- host thread scheduling
- object-address-derived identity

All floating-point opcodes and math helpers must use the TOS fixed
floating-point implementation so results are identical across operating systems
and CPU architectures.

## rt.jar Reshaping Plan

The current `rt.jar` should be reshaped in this order.

1. Freeze a machine-readable admitted API profile for Avata's extended
   `java.lang`, admitted `java.io`, and admitted `java.util`.
2. Keep VM-required `java.lang` classes, but reject host-observing behavior.
3. Keep only deterministic transient `java.io` and `java.util` APIs.
4. Remove legacy Java APIs that are neither VM-required nor admitted contract
   conveniences.
5. Add `java.lang.Address`, `Uint256`, `Bytes32`, and `Bytes4`.
6. Add `java.lang.Context` and deterministic revert helpers.
7. Add `java.lang.Storage` scalar slots and mappings.
8. Add `java.lang.Event` and `java.lang.ABI`.
9. Add `java.lang.Crypto` primitives needed by token/access/governance
   libraries.
10. Build `java.lang.Ownable`, `AccessControl`, and `ERC20` as the first
    OpenZeppelin-inspired Java libraries.

The first Java contract library milestone should be:

- `Ownable`
- `Ownable2Step`
- `AccessControl`
- `Pausable`
- `ReentrancyGuard`
- `ERC20`
- `SafeERC20` equivalent for TOS calls
- `MerkleProof`
- `Math` / `SafeCast` equivalents for `Uint256`

## Testing Strategy

Tests must prove both Java compatibility and contract semantics.

Required test families:

- Java 8 bytecode/opcode conformance for the admitted profile
- negative verifier tests for forbidden APIs
- deterministic cross-platform fixed floating-point tests
- `java.lang` value-type arithmetic and encoding tests
- `java.lang.Storage` serialization, rollback, deletion, and iteration tests
- native storage host ABI tests for callback forwarding, transaction begin,
  commit, rollback, invocation-wrapper commit/rollback, and fallback snapshots
- `java.lang.Event` log ordering and encoding tests
- crypto known-answer tests
- Java ports of OpenZeppelin behavior tests for `Ownable`, `AccessControl`, and
  `ERC20`
- gas snapshot tests for storage, hashing, signature verification, and ABI
  encode/decode

Where Solidity behavior is intentionally not copied, the Java test must document
the TOS behavior instead of silently diverging.

## Design Principles

- Keep Java language support in `java.lang`.
- Keep transient deterministic helpers in `java.io` and `java.util`.
- Put chain semantics in Avata extensions to `java.lang`.
- Put reusable business contracts in Avata extensions to `java.lang`.
- Prefer absent classes over empty shells when no VM/linkage need exists.
- Use deterministic traps only for classes or methods that must exist for Java
  linkage but cannot be allowed to observe host state.
- Do not add OpenJDK breadth as a substitute for contract primitives.
- Do not clone EVM mechanisms unless they are explicitly useful and compatible
  with the TOS execution model.
- Treat OpenZeppelin as a business-requirement map: access control, token
  accounting, signatures, governance, upgrade patterns, and defensive utilities.
