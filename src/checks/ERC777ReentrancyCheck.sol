// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";

interface IERC777Balance {
    function balanceOf(address account) external view returns (uint256);
}

/// @title ERC777ReentrancyCheck — detect tokensReceived hook reentrancy
/// @notice Tests whether an ERC-777 token callback can re-enter a token withdrawal
///         before the audited contract updates internal accounting.
/// @author kcolbchain
abstract contract ERC777ReentrancyCheck is ChecklistBase {
    /// @dev Override to return the ERC-777 token used by the target contract.
    function getERC777Token() internal view virtual returns (address);

    /// @dev Override to return calldata for the target's token withdrawal function.
    function getERC777WithdrawCalldata() internal view virtual returns (bytes memory);

    /// @dev Override to return the token amount to deposit for the attacker.
    function getERC777DepositAmount() internal view virtual returns (uint256) {
        return 100 ether;
    }

    /// @dev Override to mint, transfer, or otherwise fund `depositor`.
    function fundERC777Depositor(address depositor, uint256 amount) internal virtual;

    /// @dev Override to deposit `amount` from `depositor` into the target.
    function performERC777Deposit(address depositor, uint256 amount) internal virtual;

    function test_erc777_tokens_received_reentrancy() public virtual {
        address token = getERC777Token();
        uint256 depositAmount = getERC777DepositAmount();
        bytes memory withdrawCalldata = getERC777WithdrawCalldata();
        ERC777ReentrantReceiver attacker = new ERC777ReentrantReceiver(targetContract, token, withdrawCalldata);

        fundERC777Depositor(address(attacker), depositAmount);
        performERC777Deposit(address(attacker), depositAmount);

        uint256 attackerBalanceBefore = IERC777Balance(token).balanceOf(address(attacker));

        attacker.attack();

        uint256 attackerBalanceAfter = IERC777Balance(token).balanceOf(address(attacker));
        uint256 extracted = attackerBalanceAfter - attackerBalanceBefore;

        if (extracted > depositAmount) {
            emit log("VULNERABILITY: ERC-777 tokensReceived reentrancy extracted more than deposited");
            emit log_named_uint("Deposited", depositAmount);
            emit log_named_uint("Extracted", extracted);
        }
        assertLe(extracted, depositAmount, "ERC-777 tokensReceived reentrancy extracted more than deposited");
    }
}

/// @dev Helper recipient that re-enters the target when ERC-777 tokens are received.
contract ERC777ReentrantReceiver {
    address public immutable target;
    address public immutable token;
    bytes public withdrawCalldata;
    uint256 public attackCount;

    constructor(address _target, address _token, bytes memory _withdrawCalldata) {
        target = _target;
        token = _token;
        withdrawCalldata = _withdrawCalldata;
    }

    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata) external {
        if (msg.sender == token && attackCount < 2) {
            attackCount++;
            (bool success,) = target.call(withdrawCalldata);
            success;
        }
    }

    function attack() external {
        (bool success,) = target.call(withdrawCalldata);
        success;
    }
}
