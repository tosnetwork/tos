# Tola Language

Tola is the proposed high-level smart contract language direction for TOS.

## Goals

- modern contract syntax
- actor-native semantics
- strong typing
- TVM-targeted compilation
- safer developer ergonomics than raw low-level contract code

## Design Principles

Tola is intended to reflect the TOS execution model directly:

- `actor` is the primary unit
- communication is asynchronous
- state is isolated
- reentrancy-style assumptions are avoided by design

## Positioning

Think of Tola as:

- more ergonomic than raw FunC
- more actor-native than Solidity-style contract models
- aligned with TOS message-driven execution

## Current Role

At this stage, Tola should be read as a language direction and design document, not as an assertion that every part of the toolchain is production-default today.

## Related Docs

- [actor.md](actor-v3.md)
- [smc-guidelines.md](smc-guidelines.md)

All cross-actor communication is asynchronous. There are no synchronous calls.
This eliminates reentrancy attacks by design.

```tola
// Solidity (synchronous — reentrancy risk):
IERC20(token).transfer(recipient, amount);       // blocks, waits for return
bool success = IERC20(token).approve(spender, amount);  // gets return value

// Tola (asynchronous — no reentrancy possible):
tokenActor.send("transfer", abi.encode(recipient, amount));  // fire and forget
// result comes back as a separate message to this actor
```

The `.send()` method:

```tola
// Basic send
actorId.send(string kind, bytes payload);
actorId.send(string kind, bytes payload, uint128 value);  // with coins attached

// Send with mode flags (covers FunC's send_raw_message mode parameter)
actorId.send(string kind, bytes payload, SendOptions {
    value: 1000,              // coins to attach
    mode: SendMode.PAY_FEES_SEPARATELY | SendMode.IGNORE_ERRORS,
    bounce: true              // default true
});

// Shorthand for typed messages (see Section 5: Interfaces)
IToken(actorId).transfer(recipient, amount);  // compiler generates send("transfer", ...)
```

Send mode flags (mapped from FunC's `send_raw_message` mode bits):

```tola
enum SendMode {
    DEFAULT             = 0,    // ordinary message
    PAY_FEES_SEPARATELY = 1,    // sender pays transfer fees separately
    IGNORE_ERRORS       = 2,    // ignore errors during action phase
    DESTROY_IF_ZERO     = 32,   // destroy actor if resulting balance is zero
    CARRY_ALL_BALANCE   = 128,  // carry all remaining balance
    CARRY_INBOUND_VALUE = 64,   // carry all remaining value of inbound message
}
```

### 2.4 State Model

State variables in Tola are syntactically identical to Solidity but internally
compiled to STATEGET/STATESET operations on the actor's HashmapE.

```tola
actor Vault {
    uint128 balance;          // stored as HashmapE entry: sha256("balance") → value
    ActorId owner;            // stored as HashmapE entry: sha256("owner") → value
    mapping(ActorId => uint64) approvals;  // stored with composite keys
    bool locked;

    function deposit() external payable {
        balance += msg.value;   // → STATEGET("balance") + ADD + STATESET("balance")
    }
}
```

**What happens under the hood:**

| Tola code | Compiles to |
|-----------|-------------|
| `uint128 balance;` | State key `sha256("balance")` in HashmapE |
| `balance += amount` | `STATEGET(sha256("balance"))` → `ADD` → `STATESET(sha256("balance"))` |
| `mapping(K => V) m;` | Composite key: `sha256("m" ++ serialize(key))` |
| `m[actorId] = val;` | `STATESET(sha256("m" ++ actorId), val)` |
| `delete m[actorId];` | `STATEDEL(sha256("m" ++ actorId))` |

Developers never see Cell, Slice, or Builder. The compiler handles all serialization.

## 3. Type System

### 3.1 Value Types

```tola
// Integers (unsigned)
uint8, uint16, uint32, uint64, uint128, uint256

// Integers (signed)
int8, int16, int32, int64, int128, int256

// Boolean
bool

// Actor identity (256-bit)
ActorId

// Byte arrays
bytes       // dynamic length
bytes32     // fixed 32 bytes

// String
string      // UTF-8, dynamic length

// Enum (from Solidity — useful for state machines)
enum OrderStatus { Open, Filled, Cancelled }

// Type alias
type TokenId = uint256;
type Coins = uint128;

// Tuple (from FunC — multiple return values)
(uint64, bool) result = getAmountAndStatus();

// Optional (from FunC's null semantics)
uint64? maybeBalance;       // can be null
ActorId? maybeOwner;        // can be null
if (maybeBalance != null) { ... }

// Constants and immutables (from Solidity — must be declared inside an actor)
//   constant uint64 MAX_SUPPLY = 1_000_000_000;
//   immutable ActorId deployer;
```

### 3.2 Reference Types

```tola
// Fixed-size array
uint64[10] values;

// Dynamic array (with push/pop/length)
uint64[] items;
items.push(42);             // append
uint64 last = items.pop();  // remove and return last
uint64 len = items.length;  // current length

// Mapping (key-value, stored in HashmapE)
mapping(ActorId => uint64) balances;
mapping(uint256 => mapping(ActorId => bool)) nestedMap;

// Struct
struct Order {
    ActorId maker;
    uint64 amount;
    uint64 price;
    bool filled;
}

// Struct with tuple destructuring
(ActorId maker, uint64 amount) = (order.maker, order.amount);
```

### 3.3 Special Types and Built-in Globals

```tola
// Message context (read-only, available in external functions)
msg.sender      // ActorId — message sender
msg.value       // uint128 — coins attached to message
msg.kind        // string — message operation name
msg.payload     // bytes — raw message payload
msg.isExternal  // bool — true if message is from outside the chain
msg.isInternal  // bool — true if message is from another actor
msg.isBounced   // bool — true if this is a bounced message

// Actor context
self            // ActorId — this actor's identity
self.balance    // uint128 — this actor's coin balance (Account-level)

// Block context
block.time      // uint32 — current block unix timestamp
block.lt        // uint64 — current logical time

// Cryptographic built-ins (from FunC: check_signature, cell_hash, etc.)
crypto.checkSignature(hash, signature, publicKey)  // → bool (Ed25519)
crypto.sha256(data)                                // → uint256
crypto.keccak256(data)                             // → uint256
// crypto.cellHash(c), crypto.sliceHash(s) — available inside unsafe cell blocks

// Random number generation (from FunC: random, randomize_lt)
random.uint256()               // → uint256 (pseudo-random 256-bit)
random.range(uint256 max)      // → uint256 (0..max-1)
random.seed(uint256 seed)      // set seed
random.addSeed(uint256 entropy)// mix entropy into seed
random.seedWithLt()            // equivalent to FunC randomize_lt()

// Blockchain configuration (from FunC: config_param)
config.param(int32 index)      // → bytes? (raw config cell data, null if absent)
config.electorAddress()        // → ActorId (shortcut for common params)

// Gas management (from FunC: accept_message, set_gas_limit, buy_gas, commit)
gas.accept()                    // accept external message, pay for gas (FunC: accept_message)
gas.setLimit(uint64 limit)      // set gas limit (FunC: set_gas_limit)
gas.buy(uint128 amount)         // buy gas with coins (FunC: buy_gas)
gas.left()                      // → uint64 remaining gas
gas.commit()                    // commit current state mid-execution (FunC: commit)

// Balance reservation (from FunC: raw_reserve)
reserve(uint128 amount, ReserveMode mode)

enum ReserveMode {
    EXACT           = 0,   // reserve exactly amount
    ALL_BUT         = 1,   // reserve all except amount
    AT_MOST         = 2,   // reserve at most amount
    PLUS_ORIGINAL   = 4,   // add original balance before check
    NEGATE          = 8,   // negate amount before action
}
```

## 4. Language Constructs

### 4.1 Actor Declaration

```tola
actor TokenBalance {
    // State variables
    uint64 balance;
    ActorId owner;

    // Constants and immutables
    constant uint64 MIN_TRANSFER = 1;
    immutable ActorId deployer;

    // Constructor — called when actor is created
    constructor(ActorId _owner) {
        owner = _owner;
        deployer = msg.sender;  // immutable: set once, never changes
    }

    // External function — callable via internal messages from other actors
    function transfer(ActorId recipient, uint64 amount) external {
        require(msg.sender == owner, "not owner");
        require(balance >= amount, "insufficient");
        balance -= amount;
        recipient.send("credit", abi.encode(amount));
    }

    // Payable function — can receive coins
    function deposit() external payable {
        balance += uint64(msg.value);
    }

    // View function — read-only, no state changes
    function getBalance() external view returns (uint64) {
        return balance;
    }

    // Multiple return values (from FunC tuple support)
    function getInfo() external view returns (uint64, ActorId) {
        return (balance, owner);
    }

    // Internal function — only callable within this actor
    function _validateAmount(uint64 amount) internal view returns (bool) {
        return amount > 0 && amount <= balance;
    }
}
```

### 4.1.1 External Message Handling (from FunC recv_external)

External messages come from outside the blockchain (wallets, dApps). They carry
no gas, so the actor must explicitly accept and pay. This maps to FunC's
`recv_external()` + `accept_message()` pattern.

```tola
actor Wallet {
    uint256 publicKey;
    uint32 seqno;

    // receive_external — handles messages from outside the chain
    // Equivalent to FunC's recv_external()
    receive_external(bytes body) {
        // Verify signature BEFORE accepting (no gas spent until accept)
        (bytes signature, uint32 msgSeqno, ActorId dest, uint64 amount) =
            abi.decode(body, (bytes, uint32, ActorId, uint64));

        require(msgSeqno == seqno, "wrong seqno");
        // Hash the payload (everything after signature) and verify
        bytes payload = abi.encode(msgSeqno, dest, amount);
        require(crypto.checkSignature(
            crypto.sha256(payload),
            signature,
            publicKey
        ), "bad signature");

        // Accept the message — from this point, the actor pays for gas
        gas.accept();

        // Now safe to do state changes and send messages
        seqno += 1;
        dest.send("credit", abi.encode(amount), SendOptions { value: amount });
    }
}
```

### 4.1.2 Tick/Tock Handlers (from FunC run_ticktock)

System actors can register tick and tock handlers, called by the scheduler
at the beginning (tick) and end (tock) of each block.

```tola
actor EpochClock {
    uint64 epoch;
    uint32 lastBlockTime;

    // Called at the beginning of each block (tick phase)
    tick() {
        lastBlockTime = block.time;
    }

    // Called at the end of each block (tock phase)
    tock() {
        if (block.time > lastBlockTime + 3600) {
            epoch += 1;
            emit NewEpoch(epoch);
        }
    }

    event NewEpoch(uint64 epoch);
}
```

### 4.1.3 Actor Inheritance (from Solidity)

Actors can inherit from abstract actors, similar to Solidity's `contract B is A`:

```tola
abstract actor Ownable {
    ActorId owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function transferOwnership(ActorId newOwner) external onlyOwner {
        owner = newOwner;
    }
}

abstract actor Pausable is Ownable {
    bool paused;

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    function pause() external onlyOwner { paused = true; }
    function unpause() external onlyOwner { paused = false; }
}

// Concrete actor inherits from both
actor TokenBalance is Pausable {
    uint64 balance;

    function transfer(ActorId to, uint64 amount) external whenNotPaused {
        require(balance >= amount);
        balance -= amount;
        to.send("credit", abi.encode(amount));
    }
}
```

Note: `mixin` keyword from v0.1 is replaced by `abstract actor` + `is` for
Solidity familiarity. Multiple inheritance is supported (diamond resolved by
C3 linearization, same as Solidity).

### 4.2 Visibility

| Keyword | Meaning |
|---------|---------|
| `external` | Callable via incoming messages |
| `internal` | Only callable within the same actor |
| `view` | Read-only, cannot modify state |
| `payable` | Can receive coins with the message |
| `pure` | No state access at all (pure computation) |

### 4.3 Modifiers

Modifiers work exactly like Solidity. See Section 4.1.3 for `Ownable` and
`Pausable` examples using `modifier` with `_;` placeholder.

```tola
// Additional modifier example — rate limiting
actor RateLimited {
    uint32 lastCallTime;

    modifier throttle(uint32 interval) {
        require(block.time >= lastCallTime + interval, "too soon");
        _;
        lastCallTime = block.time;
    }

    function expensiveOp() external throttle(60) {
        // can only be called once per 60 seconds
    }
}
```

### 4.4 Error Handling

```tola
// require — revert with message if condition fails
require(balance >= amount, "insufficient balance");

// revert — unconditional revert
if (amount == 0) {
    revert("zero amount");
}

// Custom errors (gas-efficient, from Solidity) — declared inside actor
error InsufficientBalance(uint64 available, uint64 requested);

// Usage:
if (balance < amount) {
    revert InsufficientBalance(balance, amount);
}

// try/catch (from FunC's try-catch, maps to TVM TRY/TRYARGS)
// Usage inside an actor:
function safeParse(bytes data) internal returns (uint64) {
    try {
        return abi.decode(data, (uint64));
    } catch (int errorCode) {
        // errorCode is the TVM exception code
        return 0;  // return default on failure
    }
}
```

### 4.5 Events

Events are emitted for off-chain indexing. They do not affect on-chain state.

```tola
actor TokenBalance {
    uint64 balance;

    event Transfer(ActorId indexed from, ActorId indexed to, uint64 amount);
    event Credit(ActorId indexed account, uint64 amount);

    function transfer(ActorId recipient, uint64 amount) external {
        require(balance >= amount, "insufficient");
        balance -= amount;
        recipient.send("credit", abi.encode(amount));
        emit Transfer(self, recipient, amount);
    }
}
```

### 4.6 Control Flow

```tola
// If-else (from Solidity)
if (amount > threshold) {
    // ...
} else if (amount > 0) {
    // ...
} else {
    revert("invalid");
}

// For loop (from Solidity)
for (uint i = 0; i < count; i++) {
    // ...
}

// While loop (from Solidity)
while (remaining > 0) {
    remaining -= 1;
}

// Repeat loop (from FunC — more gas-efficient than for when count is known)
repeat (10) {
    // executes exactly 10 times, no loop variable overhead
}

// Do-while loop (from Solidity — also covers FunC's do-until via negation)
do {
    value = processNext();
} while (value != 0);

// Early return
function validate(uint64 amount) internal view returns (bool) {
    if (amount == 0) return false;
    if (amount > balance) return false;
    return true;
}
```

### 4.7 Unchecked Arithmetic (from Solidity)

By default, all arithmetic is checked (overflow/underflow reverts). Use `unchecked`
when overflow is intentionally safe and gas savings matter:

```tola
function hash(uint256 a, uint256 b) internal pure returns (uint256) {
    unchecked {
        // Overflow is intentional here — wrapping arithmetic
        return a * 0x100000000 + b;
    }
}
```

### 4.8 Compiler Directives

```tola
#pragma tola ^0.3.0;            // require compiler version 0.3.x
#pragma allow-experimental;     // enable experimental features

import "./IToken.tola";         // import interface file
import { Math } from "tos-stdlib";  // import from standard library
```

### 4.9 Raw Cell Access (Escape Hatch)

When you need direct Cell/Slice/Builder access — for interop with existing FunC
contracts, custom data structures, or computing storage fees — Tola provides an
`unsafe cell` block:

```tola
actor Interop {
    // Parse a message from an existing FunC contract
    function handleLegacyMessage(bytes rawBody) external {
        uint32 op;
        uint64 queryId;
        uint128 amount;

        // Drop into raw Cell mode — developer takes responsibility for correctness
        unsafe cell {
            slice s = rawBody.toSlice();
            op = s.loadUint(32);
            queryId = s.loadUint(64);
            amount = s.loadCoins();
        }

        // Back to safe Tola — use parsed values normally
        if (op == 0x7362d09c) {  // jetton transfer op
            processTransfer(amount);
        }
    }

    // Build a raw message for a FunC contract
    function sendToLegacy(ActorId target, uint64 amount) external {
        cell body;
        unsafe cell {
            builder b = beginCell();
            b.storeUint(0x0f8a7ea5, 32);    // op: jetton transfer
            b.storeUint(0, 64);              // query_id
            b.storeCoins(amount);
            b.storeAddress(target);
            body = b.endCell();
        }
        target.sendRaw(body, SendMode.DEFAULT);
    }

    // Compute storage size (from FunC: compute_data_size)
    function estimateStorage(cell data) internal view returns (uint64, uint64, uint64) {
        unsafe cell {
            (int cells, int bits, int refs) = data.computeDataSize(1000);
            return (uint64(cells), uint64(bits), uint64(refs));
        }
    }
}
```

Inside `unsafe cell` blocks, all FunC/TVM primitives are available:

**Cell/Slice/Builder types and conversion:**
- `cell`, `slice`, `builder` types
- `beginCell()` → `builder`, `b.endCell()` → `cell`
- `c.beginParse()` → `slice`, `s.endParse()` (assert empty)

**Slice read operations:**
- `s.loadUint(n)`, `s.loadInt(n)`, `s.loadCoins()`, `s.loadAddress()`
- `s.loadRef()` → `cell`, `s.loadDict()` → `cell?`
- `s.preloadUint(n)`, `s.preloadRef()` — read without consuming
- `s.skipBits(n)`, `s.sliceBits()`, `s.sliceRefs()`, `s.sliceEmpty()`

**Builder write operations:**
- `b.storeUint(v, n)`, `b.storeInt(v, n)`, `b.storeCoins(v)`
- `b.storeRef(c)`, `b.storeSlice(s)`, `b.storeDict(c)`
- `b.storeAddress(addr)`, `b.storeMaybeRef(c)`
- `b.builderBits()`, `b.builderRefs()`

**Hash and size:**
- `c.cellHash()` → `uint256`, `s.sliceHash()` → `uint256`
- `c.cellDepth()`, `c.computeDataSize(maxCells)` → `(int, int, int)`

**Dictionary operations (with explicit key length):**
- `udictGet(dict, keyLen, key)`, `idictGet(dict, keyLen, key)`
- `udictSet(dict, keyLen, key, value)`, `idictSet(dict, keyLen, key, value)`
- `udictDelete(dict, keyLen, key)`, `dictEmpty(dict)`
- `udictGetNext(dict, keyLen, pivot)`, `udictGetMin(dict, keyLen)`
- Prefix dictionary: `pfxdictGet`, `pfxdictSet`, `pfxdictDelete`

**Continuation and code:**
- `bless(s)` → continuation, `getC3()`, `setC3(cont)`

**Address parsing:**
- `parseStdAddr(s)` → `(int, int)`, `parseVarAddr(s)` → `(int, slice)`

This ensures 100% FunC stdlib coverage while keeping safe Tola as the default.

## 5. Interfaces and Message Dispatch

### 5.1 Interface Declaration

Interfaces define the message protocol between actors:

```tola
interface IToken {
    function credit(uint64 amount) external;
    function transfer(ActorId recipient, uint64 amount) external;
    function getBalance() external view returns (uint64);
}
```

### 5.2 Typed Send

When an interface is known, the compiler generates type-safe `.send()` calls:

```tola
actor DEXRouter {
    ActorId tokenActor;

    function swap(ActorId poolActor, ActorId recipient, uint64 amountIn) external {
        // Untyped send (always works)
        poolActor.send("swap", abi.encode(msg.sender, amountIn));

        // Typed send (compiler checks against interface)
        IToken(tokenActor).transfer(recipient, amountIn);
        // ↑ compiles to: tokenActor.send("transfer", abi.encode(recipient, amountIn))
    }
}
```

### 5.3 Message Dispatch (Auto-generated)

The compiler auto-generates a message dispatcher from external functions:

```tola
actor Counter {
    uint64 value;
    function add(uint64 delta) external { value += delta; }
    function reset() external { value = 0; }
}
```

Compiler generates (conceptual TVM pseudocode):

```
recv_internal(msg):
    kind = msg.load_op()
    if kind == hash("add"):
        delta = msg.decode(uint64)
        STATEGET("value") + delta → STATESET("value")
    elif kind == hash("reset"):
        STATESET("value", 0)
    else:
        revert("unknown message")
```

### 5.4 Receiving Responses (Callback Pattern)

Since all calls are async, responses come as separate messages:

```tola
actor Escrow {
    ActorId tokenActor;
    uint64 pendingAmount;

    // Step 1: request balance check
    function checkAndRelease() external {
        tokenActor.send("getBalance", abi.encode(self));
    }

    // Step 2: receive the response
    function onBalanceResponse(uint64 reportedBalance) external {
        require(msg.sender == tokenActor, "unauthorized");
        if (reportedBalance >= pendingAmount) {
            // proceed with release
        }
    }
}
```

## 6. Actor Lifecycle

### 6.1 Creating Actors

Actors are created by deriving an ActorId and sending a constructor message:

```tola
actor TokenFactory {
    function createToken(string name, string symbol, uint64 supply) external {
        // Derive a deterministic ActorId
        ActorId master = ActorId.derive(self, name);

        // Send constructor message
        master.create("TokenMaster", abi.encode(name, symbol, supply, msg.sender));
    }
}
```

### 6.2 Actor Identity

ActorId is deterministically derived:

```
ActorId = sha256(account_address ++ discriminator)
```

This means:
- Same inputs always produce the same ActorId
- No on-chain registry needed
- Anyone can compute an ActorId off-chain before the actor exists

### 6.3 Actor Destruction

```tola
actor Temporary is Ownable {
    function cleanup() external onlyOwner {
        // Transfer remaining balance before destruction
        owner.send("credit", abi.encode(self.balance));
        // Mark actor as destroyed — state and balance reclaimed
        selfdestruct();
    }
}
```

### 6.4 Code Upgrade (from FunC set_code)

Actors can upgrade their code on-chain:

```tola
actor Upgradable {
    ActorId admin;

    function upgrade(bytes newCode) external {
        require(msg.sender == admin, "not admin");
        // Replace actor code — takes effect after current execution completes
        unsafe cell {
            cell codeCell = newCode.toCell();
            setCode(codeCell);
            emit Upgraded(codeCell.cellHash());
        }
    }

    event Upgraded(uint256 newCodeHash);
}
```

`setCode()` maps directly to FunC's `set_code()` / TVM's SETCODE instruction.

## 7. Built-in Standard Library

TOS ships built-in actors compiled as native C++ in the node binary.
Tola contracts can interact with them directly.

### 7.1 Standard Token (Built-in)

```tola
// Users don't deploy token contracts — they create actor instances of built-in types.
// ActorId is derived deterministically, so it is known before creation.

// Derive the address first (pure computation, no message needed)
ActorId master = ActorId.derive(self, "MyToken");

// Send constructor message to create the actor
master.create("TokenMaster", abi.encode(
    "MyToken",    // name
    "MTK",        // symbol
    1000000       // initial supply to msg.sender
));

// Transfer tokens (sends message to your balance actor)
ActorId myBalance = ActorId.derive(master, msg.sender);
IToken(myBalance).transfer(recipient, 100);
```

### 7.2 Calling Built-in Actors from Tola

Built-in actors and Tola actors use the same message format. They are interoperable:

```tola
actor Crowdfund {
    ActorId tokenMaster;
    ActorId treasury;
    uint64 goal;
    uint64 raised;

    function contribute() external payable {
        raised += uint64(msg.value);
        // Mint reward tokens to contributor via built-in TokenMaster
        tokenMaster.send("mint_to", abi.encode(
            ActorId.derive(tokenMaster, msg.sender),  // contributor's balance actor
            msg.value * 10                             // 10x reward tokens
        ));
    }

    function finalize() external {
        require(raised >= goal, "goal not met");
        treasury.send("credit", abi.encode(raised));
    }
}
```

## 8. Differences from Solidity

### 8.1 What Tola Removes

| Solidity feature | Why removed | Tola alternative |
|-----------------|-------------|------------------|
| Synchronous external calls | Causes reentrancy | Async `.send()` only |
| `delegatecall` | Security nightmare | Not needed in Actor model |
| `receive()` / `fallback()` | Implicit behavior, footgun | Explicit message dispatch |
| Storage slots (256-bit aligned) | EVM-specific | HashmapE-backed KV (arbitrary keys) |
| `tx.origin` | Security anti-pattern | Only `msg.sender` |

### 8.2 What Tola Adds

| Tola feature | Why added |
|--------------|----------|
| `actor` keyword | First-class Actor declaration |
| `ActorId` type | 256-bit actor identity with `.send()` |
| `ActorId.derive()` | Deterministic actor addressing |
| `.send(kind, payload, options)` | Async message passing with mode flags |
| `SendMode` enum | Full control over message delivery (from FunC modes) |
| `.create(type, args)` | Actor instantiation |
| `receive_external` | Handle wallet/dApp messages (from FunC recv_external) |
| `tick()` / `tock()` | System actor lifecycle hooks (from FunC run_ticktock) |
| `bounce()` handler | Explicit bounce recovery |
| `unsafe cell { }` | Escape hatch to raw Cell/Slice/Builder (100% FunC coverage) |
| `gas.accept()` | Accept external messages (from FunC accept_message) |
| `gas.commit()` | Mid-execution state commit (from FunC commit) |
| `setCode()` | On-chain code upgrade (from FunC set_code) |
| `config.param()` | Read blockchain config (from FunC config_param) |
| `crypto.*` | Signature verification, hashing (from FunC check_signature etc.) |
| `random.*` | On-chain randomness (from FunC random, randomize_lt) |
| `reserve()` | Balance reservation (from FunC raw_reserve) |
| No reentrancy | Impossible by design — not a guard, a guarantee |

### 8.3 What Tola Keeps from Solidity

- `function`, `returns`, `external`, `internal`, `view`, `payable`, `pure`
- `require()`, `revert()`, custom errors
- `try/catch` for exception handling
- `modifier` with `_;` placeholder
- `abstract actor` + `is` inheritance (replaces v0.1's `mixin`)
- `event` and `emit`
- `mapping(K => V)`
- `struct`, `enum`
- `constant`, `immutable`
- `type` alias
- `unchecked { }` for wrapping arithmetic
- `uint8` through `uint256`, `int8` through `int256`
- `bool`, `string`, `bytes`
- `msg.sender`, `msg.value`
- `abi.encode()`, `abi.decode()`
- `for`, `while`, `do...while`, `if/else`, `return`
- `import`, `#pragma`

### 8.4 What Tola Keeps from FunC

- Compiles to TVM bytecode (same VM, same gas model)
- Cell-based storage internally (developers don't see it, but can access via `unsafe cell`)
- Async message passing with full mode flags
- `accept_message()` semantics via `gas.accept()`
- `commit()` semantics via `gas.commit()`
- `raw_reserve()` semantics via `reserve()`
- `set_code()` semantics via `setCode()`
- `config_param()` via `config.param()`
- `check_signature()` via `crypto.checkSignature()`
- `random()` / `randomize_lt()` via `random.*`
- `compute_data_size()` via `unsafe cell` block
- `send_raw_message()` mode flags via `SendMode` enum
- `recv_external()` via `receive_external`
- `run_ticktock()` via `tick()` / `tock()`
- `try/catch` exception handling
- Bounce semantics for failed messages
- Logical time ordering
- Tuple / multiple return values
- `repeat(n)` loop, `do...while`
- `null` / optional types (`T?`)

## 9. Bounce and Error Recovery

When a message to another actor fails, TOS can send a bounce message back.
Tola provides explicit bounce handling:

```tola
actor SafeTransfer {
    uint64 balance;
    mapping(uint256 => uint64) pendingTransfers;
    uint256 transferNonce;

    event TransferFailed(uint256 nonce, uint64 amount);

    function transfer(ActorId recipient, uint64 amount) external {
        require(balance >= amount, "insufficient");
        balance -= amount;

        // Record pending transfer before sending
        uint256 nonce = transferNonce++;
        pendingTransfers[nonce] = amount;

        // Send with bounce enabled (default)
        recipient.send("credit", abi.encode(amount, nonce));
    }

    // Automatically called when a sent message bounces back
    bounce("credit") function onCreditBounced(uint64 amount, uint256 nonce) {
        // Refund the amount
        balance += pendingTransfers[nonce];
        delete pendingTransfers[nonce];
        emit TransferFailed(nonce, amount);
    }
}
```

## 10. Gas Model

Tola inherits TVM's gas model. Gas costs map to TVM instruction costs:

| Operation | Approximate gas |
|-----------|----------------|
| STATEGET (read state) | ~100 gas (HashmapE lookup) |
| STATESET (write state) | ~200 gas (HashmapE insert + Cell rebuild) |
| STATEDEL (delete state) | ~150 gas (HashmapE remove) |
| ACTORSEND (send message) | ~500 gas (message construction + enqueue) |
| Arithmetic (add/mul/div) | ~20 gas |
| Comparison | ~20 gas |
| Hash (sha256) | ~50 gas |

```tola
// Gas is specified by the message sender for internal messages.
// For external messages, the actor must accept and pay
// (see Section 4.1.1 for full receive_external example).

// Check remaining gas
function heavyComputation() external {
    require(gas.left() > 10000, "insufficient gas");
    // ...
}

// Commit state mid-execution (from FunC: commit)
function riskyOperation() external {
    partialUpdate();
    gas.commit();     // save state so far — even if exception later, this is preserved
    riskyStep();      // if this throws, partialUpdate() results are still saved
}

// Reserve balance (from FunC: raw_reserve)
function safeReserve() external {
    reserve(1_000_000, ReserveMode.ALL_BUT);  // keep at least 1 TOS for storage
    // subsequent sends cannot drain below this reserve
}
```

## 11. Compilation Pipeline

```
Tola source (.tola)
  ↓ Parser
AST (Abstract Syntax Tree)
  ↓ Type Checker
Typed AST (all types resolved, interfaces checked)
  ↓ Actor Analyzer
Actor graph (message flow, state access patterns)
  ↓ Code Generator
TVM Assembly (Fift)
  ↓ TVM Assembler
TVM Bytecode (Cell)
  ↓ Deploy
On-chain as Account code Cell
```

Key compiler responsibilities:
- Map state variables to HashmapE keys (`sha256(variable_name)`)
- Generate message dispatcher from external function signatures
- Generate STATEGET/STATESET for state variable access
- Generate ACTORSEND for `.send()` calls
- Type-check interface-based sends at compile time
- Compute function selectors (hash of function signature)
- Checked arithmetic by default (overflow reverts)

## 12. Example: Complete Token System

```tola
// ============================================
// Token Master Actor — manages token metadata
// ============================================
actor TokenMaster {
    string name;
    string symbol;
    uint64 totalSupply;
    ActorId admin;

    constructor(string _name, string _symbol, uint64 _supply, ActorId _admin) {
        name = _name;
        symbol = _symbol;
        totalSupply = _supply;
        admin = _admin;

        // Mint initial supply to admin's balance actor
        ActorId adminBalance = ActorId.derive(self, _admin);
        adminBalance.send("credit", abi.encode(_supply));
    }

    function mint(ActorId balanceActor, uint64 amount) external {
        require(msg.sender == admin, "only admin");
        totalSupply += amount;
        balanceActor.send("credit", abi.encode(amount));
        emit Mint(balanceActor, amount);
    }

    event Mint(ActorId indexed to, uint64 amount);
}

// ============================================
// Token Balance Actor — per-user balance
// ============================================
actor TokenBalance {
    uint64 balance;

    function credit(uint64 amount) external {
        balance += amount;
        emit Credit(self, amount);
    }

    function transfer(ActorId recipient, uint64 amount) external {
        require(balance >= amount, "insufficient balance");
        balance -= amount;
        recipient.send("credit", abi.encode(amount));
        emit Transfer(self, recipient, amount);
    }

    function getBalance() external view returns (uint64) {
        return balance;
    }

    event Credit(ActorId indexed account, uint64 amount);
    event Transfer(ActorId indexed from, ActorId indexed to, uint64 amount);
}

// ============================================
// Token Allowance Actor — per-spender approval
// ============================================
actor TokenAllowance {
    ActorId approvedSpender;
    uint64 allowance;

    function approve(ActorId spender, uint64 amount) external {
        approvedSpender = spender;
        allowance = amount;
        emit Approval(self, spender, amount);
    }

    function transferFrom(
        ActorId fromBalance,
        ActorId toBalance,
        uint64 amount
    ) external {
        require(msg.sender == approvedSpender, "not approved");
        require(allowance >= amount, "exceeds allowance");
        allowance -= amount;
        fromBalance.send("transfer_from_debit", abi.encode(toBalance, amount));
    }

    event Approval(ActorId indexed owner, ActorId indexed spender, uint64 amount);
}
```

## 13. Example: Escrow with Bounce Recovery

```tola
actor Escrow {
    ActorId buyer;
    ActorId seller;
    ActorId treasury;
    uint64 amount;
    uint64 fee;
    bool funded;
    bool released;

    constructor(
        ActorId _buyer, ActorId _seller,
        ActorId _treasury, uint64 _amount, uint64 _fee
    ) {
        buyer = _buyer;
        seller = _seller;
        treasury = _treasury;
        amount = _amount;
        fee = _fee;
    }

    function deposit(uint64 depositAmount) external {
        require(msg.sender == buyer, "only buyer");
        require(depositAmount == amount, "wrong amount");
        require(!funded, "already funded");
        funded = true;
        emit Funded(amount);
    }

    function release() external {
        require(msg.sender == buyer, "only buyer");
        require(funded && !released, "invalid state");
        released = true;
        seller.send("credit", abi.encode(amount - fee));
        if (fee > 0) {
            treasury.send("credit", abi.encode(fee));
        }
        emit Released(seller, amount - fee, treasury, fee);
    }

    bounce("credit") function onCreditBounced(uint64 bouncedAmount) {
        // If seller or treasury can't receive, refund to buyer
        released = false;
        buyer.send("credit", abi.encode(bouncedAmount));
        emit ReleaseFailed(bouncedAmount);
    }

    event Funded(uint64 amount);
    event Released(ActorId seller, uint64 sellerAmount, ActorId treasury, uint64 fee);
    event ReleaseFailed(uint64 bouncedAmount);
}
```

## 14. Example: Simple AMM Pool

```tola
actor AMMPool {
    uint128 reserveA;
    uint128 reserveB;
    ActorId tokenA;
    ActorId tokenB;

    function swap(ActorId userBalance, uint64 amountIn, bool aToB) external {
        uint128 reserveIn = aToB ? reserveA : reserveB;
        uint128 reserveOut = aToB ? reserveB : reserveA;

        // Constant product formula: x * y = k
        uint128 amountOut = uint128(
            (uint256(reserveOut) * uint256(amountIn)) /
            (uint256(reserveIn) + uint256(amountIn))
        );

        require(amountOut > 0, "insufficient output");

        if (aToB) {
            reserveA += uint128(amountIn);
            reserveB -= amountOut;
        } else {
            reserveB += uint128(amountIn);
            reserveA -= amountOut;
        }

        userBalance.send("credit", abi.encode(uint64(amountOut)));
        emit Swap(msg.sender, amountIn, uint64(amountOut), aToB);
    }

    event Swap(ActorId indexed user, uint64 amountIn, uint64 amountOut, bool aToB);
}
```

## 15. File Structure Convention

```
my_project/
  contracts/
    token/
      TokenMaster.tola
      TokenBalance.tola
      TokenAllowance.tola
    dex/
      AMMPool.tola
      DEXRouter.tola
    governance/
      Governor.tola
      Timelock.tola
  interfaces/
    IToken.tola
    IPool.tola
  tests/
    token_test.tola
  tola.toml              # project configuration
```

`tola.toml`:

```toml
[project]
name = "my_defi_app"
version = "0.1.0"

[compiler]
version = "0.1.0"
target = "tvm"
optimize = true

[dependencies]
tos-stdlib = "0.1.0"     # standard actor interfaces
```

## 16. Standard Library (tos-stdlib)

Shipped with the compiler, provides common interfaces and utilities:

```tola
// tos-stdlib/IToken.tola
interface IToken {
    function credit(uint64 amount) external;
    function transfer(ActorId recipient, uint64 amount) external;
    function getBalance() external view returns (uint64);
}

// tos-stdlib/IOwnable.tola
interface IOwnable {
    function owner() external view returns (ActorId);
    function transferOwnership(ActorId newOwner) external;
}

// tos-stdlib/Ownable.tola — see Section 4.1.3 for full definition

// tos-stdlib/Pausable.tola — see Section 4.1.3 for full definition

// tos-stdlib/Math.tola
library Math {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }
    function abs(int256 x) internal pure returns (uint256) {
        return x >= 0 ? uint256(x) : uint256(-x);
    }
    function mulDiv(uint256 a, uint256 b, uint256 denom) internal pure returns (uint256) {
        return (a * b) / denom;
    }
}

// tos-stdlib/Crypto.tola — convenience wrappers
library Crypto {
    function verifyEd25519(uint256 hash, bytes sig, uint256 pubkey) internal returns (bool) {
        return crypto.checkSignature(hash, sig, pubkey);
    }
}
```

## 17. Summary

| Dimension | Tola |
|-----------|------|
| **Paradigm** | Actor-oriented, async message passing |
| **Syntax** | Solidity-compatible subset + Actor extensions |
| **Types** | uint8-uint256, int8-int256, bool, string, bytes, ActorId, mapping, struct, enum, tuple, optional |
| **Compile target** | TVM bytecode (STATEGET/STATESET/ACTORSEND opcodes) |
| **State storage** | HashmapE (Cell-based dictionary) — hidden from developer |
| **Cross-actor calls** | Async `.send()` with full mode flags — no synchronous calls, no reentrancy |
| **External messages** | `receive_external` + `gas.accept()` — full wallet/dApp support |
| **System actors** | `tick()` / `tock()` handlers — scheduler-driven system work |
| **Error handling** | `require()`, `revert()`, custom errors, `try/catch`, bounce handlers |
| **Safety** | Checked arithmetic (with `unchecked` escape), no reentrancy, no delegatecall, no tx.origin |
| **Raw Cell access** | `unsafe cell { }` blocks — 100% FunC functionality when needed |
| **Inheritance** | `abstract actor` + `is` — Solidity-style inheritance for code reuse |
| **Gas control** | `gas.accept()`, `gas.commit()`, `gas.setLimit()`, `reserve()` |
| **Crypto** | Ed25519 signatures, SHA256, cell/slice hashing |
| **Randomness** | `random.uint256()`, `random.range()`, `random.seedWithLt()` |
| **Config** | `config.param()` — read blockchain configuration |
| **Code upgrade** | `setCode()` — on-chain actor code replacement |
| **Interop** | Full interop with built-in native C++ actors, FunC/Tolk contracts via `unsafe cell` |
| **Toolchain** | `tolac` compiler, standard library (tos-stdlib), project manager |
| **FunC coverage** | 100% — every FunC primitive is accessible (directly or via `unsafe cell`) |
