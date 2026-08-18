// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.9;

interface TosUtils {
    struct TosTxID {
        bytes32 address_hash; // sender user address
        bytes32 tx_hash; // transaction hash on bridge smart contract
        uint64 lt; // transaction LT (logical time) on bridge smart contract
    }

    struct SwapData {
        address receiver; // user's EVM-address to receive tokens
        address token; // ERC-20 token address
        uint256 amount; // token amount in units to receive in EVM-network
        TosTxID tx;
    }

    struct Signature {
        address signer; // oracle's EVM-address
        bytes signature; // oracle's signature
    }
}
