// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title  EToSPoWGiver — eTOS Proof-of-Work distribution contract (wc=1 EVM)
/// @notice Mirrors the TOS TVM giver but for the EVM workchain.
///         Miners submit a keccak-256 Proof-of-Work to receive `reward` eTOS.
///         Difficulty auto-adjusts toward `targetDelta` seconds per solve,
///         using the same multiplicative factor ∈ [7/8, 9/8] as the TVM giver.
///
/// @dev    Storage layout (slots 0–6, one variable per 32-byte slot):
///           slot 0: seed       (bytes32 — lower 16 bytes active; upper 16 zero)
///           slot 1: target     (uint256 — 256-bit PoW difficulty threshold)
///           slot 2: lastSuccess (uint256 — unix timestamp of last solved block)
///           slot 3: targetDelta (uint256 — desired seconds between solves = 12)
///           slot 4: reward     (uint256 — wei sent per solve = 2 ether)
///           slot 5: minCpl     (uint256 — log2 of the MINIMUM target value = 192)
///           slot 6: maxCpl     (uint256 — log2 of the MAXIMUM target value = 228)
///
///         Each variable occupies its own 32-byte slot (no packing) so that
///         genesis storage seeds can be trivially written as slot → 32-byte value.
///
/// Difficulty semantics (analogous to the TVM giver):
///   A hash h (keccak-256, 256-bit) is valid iff uint256(h) < target.
///   Higher target ⇒ easier mining (more hashes satisfy the condition).
///   Expected hashes per solve = 2^256 / target.
///   Complexity bits N = 256 - log2(target) ⇒ target = 2^(256-N).
///
///   minCpl (= 192 at genesis) is the log2 of the MINIMUM target:
///     target ≥ 2^minCpl  →  max difficulty, ≤ 1 in 2^(256-minCpl) hashes win
///   maxCpl (= 228 at genesis) is the log2 of the MAXIMUM target:
///     target ≤ 2^maxCpl  →  min difficulty, ≥ 1 in 2^(256-maxCpl) hashes win
///
///   These correspond to the Mining-Design.md "complexity bits" via:
///     minCpl = 256 - max_complexity_bits = 256 - 64 = 192
///     maxCpl = 256 - min_complexity_bits = 256 - 28 = 228
///
/// Genesis parameters (Mining-Design.md §eTOS Mining calibration):
///   seed        = per-giver deterministic value (16-byte prefix of bytes32)
///   target      = 2^222  (init_cpl≈34 expected hashes: 1.5 GH/s × 12s ≈ 1.8e10)
///   targetDelta = 12 s   (matches Ethereum PoW 12-second block time)
///   reward      = 2 ether = 2e18 wei
///   minCpl      = 192    (2^28 complexity bits floor → target floor = 2^192)
///   maxCpl      = 228    (2^64 complexity bits ceiling → target ceiling = 2^228)
///
/// Anti-replay: the `rseed` field must match the stored seed (lower bytes16).
///   The `rdata1` and `rdata2` fields must be equal (anti-replay pair from the TVM giver).
///   Seed is rotated after each solve from the old seed, winning proof hash,
///   parent block hash, recipient/proof data, this contract address, and the
///   previous solve timestamp.  A repeated proof therefore cannot keep claiming
///   rewards even when multiple calls land in the same EVM block.
///
/// Funds: each giver is pre-funded with 10 M eTOS (= 10_000_000e18 wei) at
///   genesis.  The contract pays out `reward` per solve until empty.
///   10 M eTOS ÷ 2 eTOS/solve = 5 M solves per giver.
///   5 M × 12s = 60 Ms ≈ 1.9 years per giver (10 givers run in parallel).
contract EToSPoWGiver {
    // -------------------------------------------------------------------------
    // Storage (one variable per slot — see @dev layout note above)
    // -------------------------------------------------------------------------

    /// @notice Current anti-replay seed that miners must echo back.
    ///         Stored as bytes32; only the upper 16 bytes (= bytes16(seed)) are
    ///         used as the actual seed.  The lower 16 bytes remain zero.
    ///         Using bytes32 keeps each variable in its own 32-byte slot for
    ///         predictable genesis seeding.
    bytes32 public seed;

    /// @notice Current 256-bit PoW difficulty target.  A hash is valid iff
    ///         uint256(keccak256(payload)) < target.
    ///         Higher target ⇒ easier.  Adjusted after every solve.
    uint256 public target;

    /// @notice Unix timestamp (seconds) of the last successfully solved PoW.
    ///         Set to genesis time (current block.timestamp) by the constructor.
    uint256 public lastSuccess;

    /// @notice Desired solve interval in seconds (= 12 for eTOS).
    uint256 public targetDelta;

    /// @notice Reward in wei sent to the solver per successful mine() call.
    ///         = 2 ether = 2e18 wei at genesis.
    uint256 public reward;

    /// @notice log2 of the minimum allowed target value.
    ///         target ≥ 2^minCpl always holds (hardness ceiling).
    ///         = 192 at genesis (= 256 - 64 complexity-bits ceiling).
    uint256 public minCpl;

    /// @notice log2 of the maximum allowed target value.
    ///         target ≤ 2^maxCpl always holds (easiness ceiling).
    ///         = 228 at genesis (= 256 - 28 complexity-bits floor).
    uint256 public maxCpl;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted on each successful PoW solve.
    /// @param whom   Address that receives the reward.
    /// @param nonce  Nonce that produced the winning hash.
    event Mined(address indexed whom, uint256 nonce);

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /// @notice Deploy a new giver.  All parameters are validated on-chain.
    ///         Caller must send the initial balance as msg.value.
    ///
    /// @param _seed        Initial anti-replay seed (upper 16 bytes of bytes32).
    /// @param _target      Initial difficulty target (must satisfy min/max bounds).
    /// @param _targetDelta Desired solve interval in seconds (> 0).
    /// @param _reward      Wei paid per solve (> 0).
    /// @param _minCpl      log2 of the minimum target value (target >= 2^minCpl).
    /// @param _maxCpl      log2 of the maximum target value (target <= 2^maxCpl).
    constructor(
        bytes32 _seed,
        uint256 _target,
        uint256 _targetDelta,
        uint256 _reward,
        uint256 _minCpl,
        uint256 _maxCpl
    ) payable {
        require(_targetDelta > 0,  "targetDelta must be > 0");
        require(_reward > 0,       "reward must be > 0");
        require(_minCpl >= 1,      "minCpl must be >= 1");
        require(_maxCpl <= 255,    "maxCpl must be <= 255");
        require(_minCpl < _maxCpl, "minCpl must be < maxCpl");

        seed        = _seed;
        target      = _target;
        lastSuccess = block.timestamp;
        targetDelta = _targetDelta;
        reward      = _reward;
        minCpl      = _minCpl;
        maxCpl      = _maxCpl;
    }

    // -------------------------------------------------------------------------
    // Core PoW function
    // -------------------------------------------------------------------------

    /// @notice Submit a Proof-of-Work solution and claim the reward.
    ///
    /// @param nonce  The miner-chosen value that produces a valid hash.
    /// @param whom   Recipient address for the eTOS reward.
    /// @param expire Unix timestamp after which this submission is rejected.
    /// @param rseed  Anti-replay seed; must equal bytes16(seed) (upper 16 bytes).
    /// @param rdata1 Additional nonce data; must equal rdata2 (anti-replay pair).
    /// @param rdata2 Additional nonce data; must equal rdata1 (anti-replay pair).
    ///
    /// @dev  Hash preimage format (mirrors the TOS convention, adapted for EVM):
    ///         h = keccak256(abi.encode(uint32(0x706f7754), nonce, whom, expire, rseed, rdata1))
    ///       0x706f7754 = "powT" magic selector matching the TVM giver op-code analog.
    function mine(
        uint256 nonce,
        address whom,
        uint32  expire,
        bytes16 rseed,
        bytes32 rdata1,
        bytes32 rdata2
    ) external {
        // Expiry check — reject stale solutions
        require(block.timestamp < uint256(expire), "expired");

        // Anti-replay: submitted seed must match upper bytes16 of stored seed
        require(bytes16(seed) == rseed, "seed mismatch");

        // Anti-replay pair: rdata1 and rdata2 must be equal
        require(rdata1 == rdata2, "rdata mismatch");

        // Compute PoW hash using the canonical TOS eTOS preimage
        bytes32 h = keccak256(abi.encode(
            uint32(0x706f7754),  // magic "powT"
            nonce,
            whom,
            expire,
            rseed,
            rdata1
        ));

        // Verify hash is below the current target
        require(uint256(h) < target, "PoW not solved");

        // Contract must have enough balance to pay the reward
        require(address(this).balance >= reward, "giver exhausted");

        bytes32 oldSeed = seed;
        uint256 previousSuccess = lastSuccess;

        // Adjust difficulty before rotating seed (uses current timestamp)
        _adjustDifficulty();

        // Rotate seed to a per-success value.  Using the parent hash alone lets
        // every successful tx in the same block reset to the same seed, so bind
        // this transition to the previous seed and this exact winning proof.
        seed = keccak256(abi.encodePacked(
            oldSeed,
            h,
            nonce,
            whom,
            rdata1,
            blockhash(block.number - 1),
            address(this),
            previousSuccess
        ));

        // Record solve time
        lastSuccess = block.timestamp;

        // Emit before the external call (Checks-Effects-Interactions pattern)
        emit Mined(whom, nonce);

        // Pay reward — forward all gas so EOA and contract recipients both work
        (bool ok, ) = whom.call{value: reward}("");
        require(ok, "transfer failed");
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /// @notice Adjust the PoW target using the TOS multiplicative formula.
    ///
    /// @dev  Direct translation of pow-testgiver-code.fc lines 28–33:
    ///
    ///         delta  = now - lastSuccess
    ///         factor = (delta << 128) / targetDelta        (Q128 fixed-point)
    ///         factor = clamp(factor, 7<<125, 9<<125)       (range: 7/8 .. 9/8)
    ///         target = (target * factor) >> 128
    ///         target = clamp(target, 2^minCpl, 2^maxCpl)
    ///
    ///       The factor is computed in Q128 fixed-point arithmetic:
    ///         factor = 1.0 in Q128 = 2^128
    ///         factor = 7/8 in Q128 = 7 << 125
    ///         factor = 9/8 in Q128 = 9 << 125
    ///
    ///       The product target * factor is computed via 128-bit decomposition
    ///       to avoid uint256 overflow (target ≤ 2^228, factor ≤ 9<<125 < 2^129).
    function _adjustDifficulty() internal {
        uint256 delta = block.timestamp - lastSuccess;
        if (delta == 0) {
            return;  // same-block solve — skip adjustment
        }

        // factor = (delta << 128) / targetDelta  in Q128 fixed-point.
        // Safe because delta < 2^40 (unix time) so delta<<128 < 2^168 < 2^256.
        uint256 factor = (delta << 128) / targetDelta;

        // Clamp factor to [7/8, 9/8] in Q128:
        //   7/8 in Q128 = 7 << 125   (= 7 * 2^125)
        //   9/8 in Q128 = 9 << 125   (= 9 * 2^125)
        uint256 factorMin = uint256(7) << 125;
        uint256 factorMax = uint256(9) << 125;
        if (factor < factorMin) factor = factorMin;
        if (factor > factorMax) factor = factorMax;

        // target' = (target * factor) >> 128
        //
        // Decompose target = hi * 2^128 + lo where hi,lo < 2^128:
        //   target * factor = (hi * 2^128 + lo) * factor
        //                   = hi*factor*2^128 + lo*factor
        //   >> 128           = hi*factor + (lo*factor >> 128)
        //
        // Safety: hi < 2^128, factor < 9<<125 < 2^129
        //   hi*factor < 2^128 * 2^129 = 2^257 — OVERFLOWS uint256!
        //
        // However, hi = target >> 128 and target <= 2^maxCpl <= 2^228,
        // so hi <= 2^(228-128) = 2^100.
        // hi*factor <= 2^100 * 9<<125 = 2^100 * 9 * 2^125 = 9 * 2^225 < 2^229 < 2^256 ✓
        //
        // So with the maxCpl=228 bound, hi*factor never overflows uint256.
        uint256 hi  = target >> 128;
        uint256 lo  = target & type(uint128).max;
        uint256 newTarget;
        unchecked {
            newTarget = hi * factor + ((lo * factor) >> 128);
        }

        // Clamp to [2^minCpl, 2^maxCpl]
        uint256 minTarget = uint256(1) << minCpl;
        uint256 maxTarget = uint256(1) << maxCpl;
        if (newTarget < minTarget) newTarget = minTarget;
        if (newTarget > maxTarget) newTarget = maxTarget;

        target = newTarget;
    }

    // -------------------------------------------------------------------------
    // View helpers (for miner clients polling the contract)
    // -------------------------------------------------------------------------

    /// @notice Returns the current PoW difficulty target.
    function currentTarget() external view returns (uint256) {
        return target;
    }

    /// @notice Returns the current anti-replay seed (bytes32; upper 16 bytes used).
    function currentSeed() external view returns (bytes32) {
        return seed;
    }

    /// @notice Returns the expected unix timestamp of the next solve, based on
    ///         the last successful solve and the current targetDelta.
    function nextSolveExpected() external view returns (uint256) {
        return lastSuccess + targetDelta;
    }

    /// @notice Returns all mining parameters in a single RPC call (reduces
    ///         latency for miner clients that need to poll frequently).
    /// @return _seed        Current anti-replay seed (bytes32).
    /// @return _target      Current difficulty target (uint256).
    /// @return _targetDelta Desired seconds between solves.
    /// @return _reward      Wei reward per solve.
    /// @return _minCpl      log2 of the minimum target (hardest difficulty).
    /// @return _maxCpl      log2 of the maximum target (easiest difficulty).
    /// @return _balance     Remaining eTOS balance in this giver (wei).
    function getMiningParams() external view returns (
        bytes32 _seed,
        uint256 _target,
        uint256 _targetDelta,
        uint256 _reward,
        uint256 _minCpl,
        uint256 _maxCpl,
        uint256 _balance
    ) {
        return (seed, target, targetDelta, reward, minCpl, maxCpl, address(this).balance);
    }

    // -------------------------------------------------------------------------
    // Receive ether (allows the giver to be topped-up post-genesis if needed)
    // -------------------------------------------------------------------------
    receive() external payable {}
}
