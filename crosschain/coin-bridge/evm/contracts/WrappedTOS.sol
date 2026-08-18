// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.7.0;
pragma experimental ABIEncoderV2;

import "./ERC20.sol";
import "./TosUtils.sol";


abstract contract WrappedTOS is ERC20, TosUtils {
    bool public allowBurn;

    function mint(SwapData memory sd) internal {
      _mint(sd.receiver, sd.amount);
      emit SwapTosToEth(sd.tx.address_.workchain, sd.tx.address_.address_hash, sd.tx.tx_hash, sd.tx.lt, sd.receiver, sd.amount);
    }

    /**
     * @dev Destroys `amount` tokens from the caller and request transfer to `addr` on TOS network
     *
     * See {ERC20-_burn}.
     */
    function burn(uint256 amount, TosAddress memory addr) external {
      require(allowBurn, "Burn is currently disabled");
      _burn(msg.sender, amount);
      emit SwapEthToTos(msg.sender, addr.workchain, addr.address_hash, amount);
    }

    /**
     * @dev Destroys `amount` tokens from `account`, deducting from the caller's
     * allowance and request transfer to `addr`
     *
     * See {ERC20-_burn} and {ERC20-allowance}.
     *
     * Requirements:
     *
     * - the caller must have allowance for ``accounts``'s tokens of at least
     * `amount`.
     */
    function burnFrom(address account, uint256 amount, TosAddress memory addr) external {
        require(allowBurn, "Burn is currently disabled");
        uint256 currentAllowance = allowance(account,msg.sender);
        require(currentAllowance >= amount, "ERC20: transfer amount exceeds allowance");
        _approve(account, msg.sender, currentAllowance - amount);
        _burn(account, amount);
        emit SwapEthToTos(account, addr.workchain, addr.address_hash, amount);
    }

    function decimals() public pure override returns (uint8) {
        return 9;
    }

    event SwapEthToTos(
        address indexed from, // sender user EVM-network
        int8 to_wc, // workchain of receiver user in TOS-network
        bytes32 indexed to_addr_hash, // // address of receiver user in TOS-network
        uint256 value // amount in nanotomis
    );
    event SwapTosToEth(
        int8 workchain, // sender user workchain in TOS network
        bytes32 indexed tos_address_hash, // sender user address in TOS network
        bytes32 indexed tos_tx_hash, // transaction hash on TOS bridge smart contract
        uint64 lt, // transaction LT (logical time) on TOS bridge smart contract
        address indexed to, // user's EVM-address to receive wrapped TOS
        uint256 value // nanotomis amount to receive in EVM-network
    );
}
