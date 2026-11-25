// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./SignatureChecker.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

interface IWrappedToken {
    function isWrappedToken() external pure returns (bool);
}

interface IDecimals {
    function decimals() external view returns (uint8);
}

contract Bridge is SignatureChecker, ReentrancyGuard {
    using SafeERC20 for IERC20;
    address[] oracleSet;
    mapping(address => bool) public isOracle;
    mapping(address => bool) public disabledTokens;
    mapping(bytes32 => bool) public finishedVotings;
    // finishedVotings only stops a digest that already executed. A governance
    // signature that was produced but never executed stays valid forever, so an
    // old rotation could be replayed to undo a newer one. These cursors make
    // each governance action strictly move forward. Every value is already
    // inside its signed digest, so the signing format is unchanged.
    uint256 public lastLockStatusNonce;
    mapping(address => uint256) public lastDisableTokenNonce;
    bool public allowLock;

    // Source generations. The history of which locks a TOS bridge may act on
    // must outlive the TOS contracts, which the TOS chain may delete; it lives
    // here. Each generation names one TOS bridge life and starts above every
    // lock already allocated, so a recreated TOS bridge can never act on a
    // lock of an earlier generation.
    struct Generation {
        bytes32 tosBridge; // account hash of the TOS bridge
        uint64 tosLife; // logical time of that bridge's first transaction
        uint64 start; // first lock nonce of the generation
    }

    uint32 public generation;
    mapping(uint32 => Generation) public generations;
    uint256 public lastGenerationNonce;

    // Every lock is numbered densely: the TOS bridge identifies a swap by
    // (chain id, this contract, generation, n) and folds a watermark over n.
    // n = 2^64 - 1 is never allocated; the TOS side reserves it.
    uint64 public constant MAX_LOCK_NONCE = type(uint64).max - 1;
    uint64 public lockNonce;

    uint8 public constant LOCK_NONE = 0;
    uint8 public constant LOCK_OPEN = 1;
    uint8 public constant LOCK_REFUNDED = 2;

    struct LockRecord {
        address locker;
        address token;
        uint256 amount;
        uint32 generation;
        uint8 status;
    }

    mapping(uint64 => LockRecord) public locks;

    // Lock caps. Every amount below is a received amount, the balance delta
    // that lock credits, so a fee-on-transfer token is capped by what the
    // bridge actually received, never by what was requested.
    //
    // - total: the bridge's balance of the token after a lock may not exceed
    //   it. That balance is the exposure: it backs the wrapped supply and the
    //   open locks, and unlocks and refunds lower it. Measuring it by the
    //   balance has two consequences. A direct transfer to the bridge fills
    //   the room left and blocks locks until the oracles vote a higher cap;
    //   it costs the sender those tokens, which stay as unswept extra
    //   backing. An issuer burn or freeze of the bridge's balance lowers the
    //   balance without lowering the wrapped supply, so the total cap then
    //   undercounts exposure; the control for that is the disable-token vote.
    //   Payouts (unlock, refundLock) never read the caps.
    // - perLock: one lock may not receive more.
    // - hourly, daily: the sum received by the locks of one fixed UTC hour
    //   (block.timestamp / 1 hours) or one fixed UTC day (/ 1 days) may not
    //   exceed it. Unlocks and refunds do not give rate back.
    //
    // The windows are fixed buckets, not sliding windows. Two adjacent
    // buckets can each be filled, so any span of one hour admits at most
    // 2 * hourly, any span of one day at most 2 * daily, and any span of k
    // whole periods at most (k + 1) times that period's cap. The total cap
    // holds at every instant regardless. A rate cap is therefore set to half
    // the burst that can be tolerated before a pause lands.
    //
    // A token whose caps were never set, or were set to zero, cannot be
    // locked, so the caps are also the source-side token allowlist. They
    // change only by an oracle vote (voteForLockCap).
    struct LockCap {
        uint128 total;
        uint128 perLock;
        uint128 hourly;
        uint128 daily;
    }

    struct LockUsage {
        uint128 hourUsed;
        uint64 hour;
        uint128 dayUsed;
        uint64 day;
    }

    mapping(address => LockCap) public lockCaps;
    mapping(address => LockUsage) public lockUsage;
    mapping(address => uint256) public lastLockCapNonce;

    event Lock(
        address indexed from,
        address indexed token,
        bytes32 indexed to_addr_hash,
        uint256 value,
        uint256 new_bridge_balance,
        uint8 decimals,
        uint64 nonce,
        uint32 generation
    );
    event LockRefunded(uint64 indexed nonce, address indexed locker, address indexed token, uint256 value);
    event NewGeneration(uint32 indexed generation, bytes32 tosBridge, uint64 tosLife, uint64 start);
    event Unlock(
        address indexed token,
        bytes32 tos_address_hash,
        bytes32 indexed tos_tx_hash,
        uint64 lt,
        address indexed to,
        uint256 value,
        uint256 new_bridge_balance
    );
    event NewOracleSet(uint256 oracleSetHash, address[] newOracles);
    event LockCapSet(
        address indexed token,
        uint256 total,
        uint256 perLock,
        uint256 hourly,
        uint256 daily,
        uint256 nonce
    );

    // initiallyDisabledTokens must name this deployment's coin-bridge wrapped
    // token, so the token bridge cannot wrap what the coin bridge already
    // wrapped. The addresses are supplied per deployment rather than compiled
    // in: this contract has no way to know them ahead of the coin-plane launch.
    constructor(address[] memory initialSet, address[] memory initiallyDisabledTokens) {
        _updateOracleSet(0, initialSet);
        disabledTokens[address(0)] = true;
        for (uint256 i = 0; i < initiallyDisabledTokens.length; i++) {
            require(initiallyDisabledTokens[i] != address(0), "Zero token in disabled list");
            disabledTokens[initiallyDisabledTokens[i]] = true;
        }
    }

    function _generalVote(bytes32 digest, Signature[] memory signatures)
        internal
        view
    {
        require(
             signatures.length >= (2 * oracleSet.length + 2) / 3,
            "Not enough signatures"
        );
        require(!finishedVotings[digest], "Vote is already finished");
        uint256 signum = signatures.length;
        uint256 last_signer = 0;
        for (uint256 i = 0; i < signum; i++) {
            address signer = signatures[i].signer;
            require(isOracle[signer], "Unauthorized signer");
            uint256 next_signer = uint256(uint160(signer));
            require(next_signer > last_signer, "Signatures are not sorted");
            last_signer = next_signer;
            checkSignature(digest, signatures[i]);
        }
    }

    function lock(
        address token,
        uint256 amount,
        bytes32 to_address_hash
    ) external nonReentrant {
        require(allowLock, "Lock is currently disabled");
        require(generation != 0, "No active generation");
        require(lockNonce <= MAX_LOCK_NONCE, "Lock nonces exhausted");
        require(!disabledTokens[token], "lock: disabled token");
        require(!checkTokenIsWrappedToken(token), "lock wrapped token");
        require(lockCaps[token].total != 0, "lock: token has no lock cap");

        uint256 oldBalance = IERC20(token).balanceOf(address(this));

        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        uint256 newBalance = IERC20(token).balanceOf(address(this));

        require(newBalance > oldBalance, "newBalance must be greater than oldBalance");

        require(newBalance <= 2 ** 120 - 1, "Max token totalSupply 2 ** 120 - 1");

        uint64 n = lockNonce;
        lockNonce = n + 1;
        uint256 received = newBalance - oldBalance;
        _consumeLockCap(token, received, newBalance);
        locks[n] = LockRecord(msg.sender, token, received, generation, LOCK_OPEN);

        emit Lock(
            msg.sender,
            token,
            to_address_hash,
            received,
            newBalance,
            getDecimals(token),
            n,
            generation
        );
    }

    // Charges one lock's received amount to its token's caps, or refuses the
    // lock. Every operand is at most 2 ** 120 - 1 (the supply bound in lock
    // and the bound voteForLockCap places on every cap), so the checked sums
    // cannot overflow and the narrowing casts are exact.
    function _consumeLockCap(address token, uint256 received, uint256 newBalance) internal {
        LockCap memory cap = lockCaps[token];
        require(received <= cap.perLock, "lock: over the per-lock cap");
        require(newBalance <= cap.total, "lock: over the token cap");
        (uint64 hour, uint64 day, uint256 hourUsed, uint256 dayUsed) = _currentLockUsage(token);
        hourUsed += received;
        dayUsed += received;
        require(hourUsed <= cap.hourly, "lock: over the hourly cap");
        require(dayUsed <= cap.daily, "lock: over the daily cap");
        lockUsage[token] = LockUsage(uint128(hourUsed), hour, uint128(dayUsed), day);
    }

    // The current hour and day buckets and what the token's locks have used
    // in each. A bucket recorded for an earlier hour or day counts as empty.
    function _currentLockUsage(address token)
        internal
        view
        returns (uint64 hour, uint64 day, uint256 hourUsed, uint256 dayUsed)
    {
        LockUsage memory usage = lockUsage[token];
        hour = uint64(block.timestamp / 1 hours);
        day = uint64(block.timestamp / 1 days);
        hourUsed = usage.hour == hour ? usage.hourUsed : 0;
        dayUsed = usage.day == day ? usage.dayUsed : 0;
    }

    // What an oracle reads before it votes: the token's caps, what the
    // current hour and day buckets have used, and the largest amount one lock
    // could receive now under the caps alone (0 for a token without caps).
    // allowLock, the generation and the disabled list are separate checks.
    function getLockCapState(address token)
        external
        view
        returns (LockCap memory cap, uint256 hourUsed, uint256 dayUsed, uint256 available)
    {
        cap = lockCaps[token];
        (, , hourUsed, dayUsed) = _currentLockUsage(token);
        if (cap.total == 0) {
            return (cap, hourUsed, dayUsed, 0);
        }
        uint256 balance = IERC20(token).balanceOf(address(this));
        available = cap.perLock;
        available = _min(available, cap.hourly > hourUsed ? cap.hourly - hourUsed : 0);
        available = _min(available, cap.daily > dayUsed ? cap.daily - dayUsed : 0);
        available = _min(available, cap.total > balance ? cap.total - balance : 0);
    }

    function _min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    // Returns lock n to its locker. Oracles sign this only after observing the
    // TOS bridge of the lock's generation cancel n, which is terminal there: a
    // cancelled lock can never be consumed, so a refund never doubles a mint.
    function refundLock(uint64 n, Signature[] calldata signatures)
        external nonReentrant
    {
        LockRecord storage record = locks[n];
        require(record.status == LOCK_OPEN, "Lock is not refundable");
        bytes32 _id = getRefundLockId(n, record.generation, record.locker, record.token, record.amount);
        _generalVote(_id, signatures);
        finishedVotings[_id] = true;
        record.status = LOCK_REFUNDED;
        IERC20(record.token).safeTransfer(record.locker, record.amount);
        emit LockRefunded(n, record.locker, record.token, record.amount);
    }

    // Makes newGeneration current, bound to one TOS bridge life. It starts at
    // the next lock nonce, above every lock already allocated.
    function voteForNewGeneration(
        uint32 newGeneration,
        bytes32 tosBridge,
        uint64 tosLife,
        uint256 nonce,
        Signature[] calldata signatures
    ) external {
        bytes32 _id = getNewGenerationId(newGeneration, tosBridge, tosLife, nonce);
        _generalVote(_id, signatures);
        require(nonce > lastGenerationNonce, "Stale generation nonce");
        require(generation < type(uint32).max, "Generations exhausted");
        require(newGeneration == generation + 1, "Generation must follow the current one");
        require(tosBridge != bytes32(0) && tosLife != 0, "Generation names no TOS bridge");
        lastGenerationNonce = nonce;
        finishedVotings[_id] = true;
        generation = newGeneration;
        generations[newGeneration] = Generation(tosBridge, tosLife, lockNonce);
        emit NewGeneration(newGeneration, tosBridge, tosLife, lockNonce);
    }

    function unlock(SwapData calldata data, Signature[] calldata signatures)
        external nonReentrant
    {
        bytes32 _id = getSwapDataId(data);
        _generalVote(_id, signatures);
        finishedVotings[_id] = true;
        IERC20(data.token).safeTransfer(data.receiver, data.amount);
        uint256 newBalance = IERC20(data.token).balanceOf(address(this));
        emit Unlock(data.token, data.tx.address_hash, data.tx.tx_hash, data.tx.lt, data.receiver, data.amount, newBalance);
    }

    function voteForNewOracleSet(
        uint256 oracleSetHash,
        address[] calldata newOracles,
        Signature[] calldata signatures
    ) external {
        bytes32 _id = getNewSetId(oracleSetHash, newOracles);
        _generalVote(_id, signatures);
        // oracleSetHash names the set being replaced. Binding it to the live
        // set invalidates a rotation signature the moment any other rotation
        // lands, so a stale one cannot undo a newer one.
        require(
            oracleSetHash == uint256(keccak256(abi.encode(oracleSet))),
            "Stale oracle set hash"
        );
        finishedVotings[_id] = true;
        _updateOracleSet(oracleSetHash, newOracles);
    }

    function voteForSwitchLock(
        bool newLockStatus,
        uint256 nonce,
        Signature[] calldata signatures
    ) external {
        bytes32 _id = getNewLockStatusId(newLockStatus, nonce);
        _generalVote(_id, signatures);
        require(nonce > lastLockStatusNonce, "Stale lock status nonce");
        lastLockStatusNonce = nonce;
        finishedVotings[_id] = true;
        allowLock = newLockStatus;
    }

    function voteForDisableToken(
        bool isDisable,
        address tokenAddress,
        uint256 nonce,
        Signature[] calldata signatures
    ) external {
        bytes32 _id = getNewDisableToken(isDisable, tokenAddress, nonce);
        _generalVote(_id, signatures);
        require(nonce > lastDisableTokenNonce[tokenAddress], "Stale disable token nonce");
        lastDisableTokenNonce[tokenAddress] = nonce;
        finishedVotings[_id] = true;
        if (isDisable) {
            disabledTokens[tokenAddress] = true;
        } else {
            delete disabledTokens[tokenAddress];
        }
    }

    // Sets a token's lock caps. All four zero closes the token to locks.
    // Otherwise every cap is non-zero, perLock <= hourly <= daily, and each is
    // within the supply bound. The nonce strictly increases per token, as for
    // voteForDisableToken, so a signed but unexecuted older vote can never
    // undo a newer one. What the current buckets have already used stays
    // charged, so a lowered rate cap takes effect at once.
    function voteForLockCap(
        address token,
        uint256 total,
        uint256 perLock,
        uint256 hourly,
        uint256 daily,
        uint256 nonce,
        Signature[] calldata signatures
    ) external {
        bytes32 _id = getNewLockCapId(token, total, perLock, hourly, daily, nonce);
        _generalVote(_id, signatures);
        require(nonce > lastLockCapNonce[token], "Stale lock cap nonce");
        require(token != address(0), "Lock cap names no token");
        if (total != 0 || perLock != 0 || hourly != 0 || daily != 0) {
            require(total != 0 && perLock != 0, "Lock cap is partly zero");
            require(perLock <= hourly && hourly <= daily, "Lock caps are not ordered");
            require(total <= 2 ** 120 - 1 && daily <= 2 ** 120 - 1, "Lock cap over the supply bound");
        }
        lastLockCapNonce[token] = nonce;
        finishedVotings[_id] = true;
        lockCaps[token] = LockCap(uint128(total), uint128(perLock), uint128(hourly), uint128(daily));
        emit LockCapSet(token, total, perLock, hourly, daily, nonce);
    }

    function _updateOracleSet(uint256 oracleSetHash, address[] memory newOracles)
        internal
    {
        require(newOracles.length > 2, "New set is too short");
        uint256 oldSetLen = oracleSet.length;
        for (uint256 i = 0; i < oldSetLen; i++) {
            isOracle[oracleSet[i]] = false;
        }
        oracleSet = newOracles;
        uint256 newSetLen = oracleSet.length;
        for (uint256 i = 0; i < newSetLen; i++) {
            require(newOracles[i] != address(0), "zero signer");
            require(!isOracle[newOracles[i]], "Duplicate oracle in Set");
            isOracle[newOracles[i]] = true;
        }
        emit NewOracleSet(oracleSetHash, newOracles);
    }

    function getFullOracleSet() external view returns (address[] memory) {
        return oracleSet;
    }

    function checkTokenIsWrappedToken(address token) public pure returns (bool) {
        try IWrappedToken(token).isWrappedToken() returns (
            bool isWrappedToken
        ) {
            return isWrappedToken;
        } catch {
            return false;
        }
    }

    function getDecimals(address token) public view returns (uint8) {
        try IDecimals(token).decimals() returns (
            uint8 decimals
        ) {
            return decimals;
        } catch {
            return 0;
        }
    }
}
