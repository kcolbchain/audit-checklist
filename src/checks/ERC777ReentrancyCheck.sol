// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";
import {IERC777Recipient} from "@openzeppelin/contracts/token/ERC777/IERC777Recipient.sol";
import {IERC1820Registry} from "@openzeppelin/contracts/utils/introspection/IERC1820Registry.sol";

/// @title ERC777ReentrancyCheck — detect ERC-777 tokensReceived reentrancy
/// @notice Tests whether ERC-777 token transfers can be re-entered via the
///         `tokensReceived` hook. This is the same class of vulnerability that
///         drained imBTC and Uniswap V1 in 2020.
/// @dev Override `getWithdrawCalldata()` to point at your contract's withdraw.
///      The check deploys a mock ERC-777 token and an attacker that re-enters
///      from `tokensReceived`.
/// @author kcolbchain
abstract contract ERC777ReentrancyCheck is ChecklistBase {
    IERC1820Registry internal constant ERC1820_REGISTRY =
        IERC1820Registry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24);

    /// @dev Override to return calldata that triggers a withdrawal of ERC-777 tokens
    function getERC777WithdrawCalldata() internal view virtual returns (bytes memory);

    /// @dev Override to return the amount of tokens to deposit for testing
    function getERC777DepositAmount() internal view virtual returns (uint256) {
        return 1000 ether;
    }

    /// @dev Override to perform a deposit into the target contract.
    ///      The depositor must hold the mock token (already minted).
    function performERC777Deposit(address depositor, uint256 amount) internal virtual;

    function test_erc777_reentrancy_on_withdraw() public {
        uint256 depositAmount = getERC777DepositAmount();
        bytes memory withdrawCall = getERC777WithdrawCalldata();

        // Deploy mock ERC-777 token and fund the attacker
        MockERC777 token = new MockERC777("Mock777", "M777", new address[](0));
        address attacker = _deployERC777Reentrant(address(token), withdrawCall);

        token.mint(attacker, depositAmount);

        // Attacker deposits tokens into target
        vm.prank(attacker);
        token.approve(address(targetContract), depositAmount);
        vm.prank(attacker);
        performERC777Deposit(attacker, depositAmount);

        uint256 targetBalBefore = token.balanceOf(address(targetContract));

        // Trigger attack — attacker calls withdraw, which sends tokens,
        // which triggers tokensReceived(), which re-enters withdraw()
        vm.prank(attacker);
        ERC777ReentrantAttacker(payable(attacker)).attack();

        uint256 attackerBal = token.balanceOf(attacker);
        // If attacker has more tokens than deposited, reentrancy succeeded
        if (attackerBal > depositAmount) {
            emit log(unicode"VULNERABILITY: ERC-777 tokensReceived reentrancy detected — attacker extracted more than deposited");
            fail();
        }
    }

    function _deployERC777Reentrant(
        address token,
        bytes memory attackCalldata
    ) internal returns (address) {
        ERC777ReentrantAttacker attacker = new ERC777ReentrantAttacker(
            targetContract,
            IERC777Recipient(token),
            attackCalldata
        );
        return address(attacker);
    }
}

/// @title MockERC777 — Minimal ERC-777 token for reentrancy testing
contract MockERC777 {
    string public name;
    string public symbol;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;
    address[] private _defaultOperators;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    constructor(string memory _name, string memory _symbol, address[] memory defaultOperators) {
        name = _name;
        symbol = _symbol;
        _defaultOperators = defaultOperators;
    }

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
        _callTokensReceived(msg.sender, address(0), to, amount, "", "");
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "insufficient allowance");
        allowance[from][msg.sender] -= amount;
        _transfer(from, to, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "insufficient balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        _callTokensReceived(msg.sender, from, to, amount, "", "");
    }

    function _callTokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes memory userData,
        bytes memory operatorData
    ) internal {
        if (_isContract(to)) {
            try IERC777Recipient(to).tokensReceived(
                operator, from, to, amount, userData, operatorData
            ) {} catch {}
        }
    }

    function _isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
}

/// @title ERC777ReentrantAttacker — Calls target, re-enters from tokensReceived
contract ERC777ReentrantAttacker is IERC777Recipient {
    address public target;
    IERC777Recipient public token;
    bytes public attackCalldata;
    bool private _attacking;

    constructor(address _target, IERC777Recipient _token, bytes memory _attackCalldata) {
        target = _target;
        token = _token;
        attackCalldata = _attackCalldata;
    }

    function attack() external {
        _attacking = true;
        (bool success,) = target.call(attackCalldata);
        require(success, "attack call failed");
        _attacking = false;
    }

    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external override {
        if (_attacking) {
            // Re-enter the target's withdraw function from within tokensReceived
            (bool success,) = target.call(attackCalldata);
            require(success, "re-entrant call failed");
        }
    }

    receive() external payable {}
}
