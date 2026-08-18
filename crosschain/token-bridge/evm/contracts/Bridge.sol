// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./SignatureChecker.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

interface IWrappedJetton {
    function isWrappedJetton() external pure returns (bool);
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

    event Lock(
        address indexed from,
        address indexed token,
        bytes32 indexed to_addr_hash,
        uint256 value,
        uint256 new_bridge_balance,
        uint8 decimals
    );
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
        require(!disabledTokens[token], "lock: disabled token");
        require(!checkTokenIsWrappedJetton(token), "lock wrapped jetton");

        uint256 oldBalance = IERC20(token).balanceOf(address(this));

        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        uint256 newBalance = IERC20(token).balanceOf(address(this));

        require(newBalance > oldBalance, "newBalance must be greater than oldBalance");

        require(newBalance <= 2 ** 120 - 1, "Max jetton totalSupply 2 ** 120 - 1");

        emit Lock(
            msg.sender,
            token,
            to_address_hash,
            newBalance - oldBalance,
            newBalance,
            getDecimals(token)
        );
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

    function checkTokenIsWrappedJetton(address token) public pure returns (bool) {
        try IWrappedJetton(token).isWrappedJetton() returns (
            bool isWrappedJetton
        ) {
            return isWrappedJetton;
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
