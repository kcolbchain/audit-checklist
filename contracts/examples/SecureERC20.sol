pragma solidity ^0.8.0;

contract SecureERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function transfer(address to, uint256 amount) public {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }

    function increaseAllowance(address spender, uint256 addedValue) public {
        allowance[msg.sender][spender] += addedValue;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public {
        allowance[msg.sender][spender] -= subtractedValue;
    }

    function transferFrom(address from, address to, uint256 amount) public {
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}
