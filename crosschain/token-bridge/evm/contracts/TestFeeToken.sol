// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.9;

// A test stand-in for a 6-decimal stablecoin with a transfer-fee switch:
// transfer and transferFrom return nothing, and while the fee is non-zero the
// recipient receives the amount less feeBasisPoints / 10000 of it. The fee is
// burned, so a recipient's balance delta is the only honest measure of what
// arrived.
contract TestFeeToken {
    uint256 public constant FEE_DENOMINATOR = 10000;

    string public constant name = "TestFeeToken";
    string public constant symbol = "TFT";
    uint8 public constant decimals = 6;

    address public immutable owner;
    uint256 public totalSupply;
    uint256 public feeBasisPoints;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 supply) {
        owner = msg.sender;
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
        emit Transfer(address(0), msg.sender, supply);
    }

    function setFee(uint256 basisPoints) external {
        require(msg.sender == owner, "TestFeeToken: not the owner");
        require(basisPoints <= FEE_DENOMINATOR, "TestFeeToken: fee over 100%");
        feeBasisPoints = basisPoints;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external {
        _transfer(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) external {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "TestFeeToken: insufficient allowance");
        allowance[from][msg.sender] = allowed - amount;
        _transfer(from, to, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(to != address(0), "TestFeeToken: transfer to the zero address");
        require(balanceOf[from] >= amount, "TestFeeToken: insufficient balance");
        uint256 fee = (amount * feeBasisPoints) / FEE_DENOMINATOR;
        balanceOf[from] -= amount;
        balanceOf[to] += amount - fee;
        totalSupply -= fee;
        emit Transfer(from, to, amount - fee);
        if (fee != 0) {
            emit Transfer(from, address(0), fee);
        }
    }
}
