// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.7.0;

interface TosUtils {
    struct TosAddress {
        int8 workchain;
        bytes32 address_hash;
    }
    struct TosTxID {
        TosAddress address_; // sender user address in TOS network
        bytes32 tx_hash; // transaction hash on TOS bridge smart contract
        uint64 lt; // transaction LT (logical time) on TOS bridge smart contract
    }

  struct SwapData {
        address receiver; // user's EVM-address to receive wrapped TOS
        uint64 amount; // nanotomis amount to receive in EVM-network
        TosTxID tx;
  }
  struct Signature {
        address signer; // oracle's EVM-address
        bytes signature; // oracle's signature
  }

}
