// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableERC777Vault — intentionally vulnerable for demonstration
/// @notice DO NOT USE IN PRODUCTION. Mirrors the 2020 imBTC/Uniswap V1 drain
///         pattern: ERC-777 hook fires before balance state is settled, so a
///         malicious recipient can re-enter withdraw via tokensReceived.
/// @author kcolbchain
interface IERC777Recipient {
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external;
}

/// @dev Minimal ERC-777-like token. Real ERC-777 routes tokensReceived via
///      the ERC-1820 registry; for the test fixture we hard-call the hook on
///      any contract recipient. The semantics that matter for the bug class
///      (recipient hook before settlement) are identical.
contract MockERC777Token {
    mapping(address => uint256) public balanceOf;
    string public name = "Mock 777";
    string public symbol = "M777";

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    /// @dev Transfer with the ERC-777 recipient hook. If `to` is a contract,
    ///      its `tokensReceived` is called *before* this function returns,
    ///      but *after* the transfer is reflected in `balanceOf` — which is
    ///      the standard ERC-777 behavior.
    function transfer(address to, uint256 amount) public returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;

        if (_isContract(to)) {
            IERC777Recipient(to).tokensReceived(
                msg.sender, msg.sender, to, amount, "", ""
            );
        }
        return true;
    }

    function _isContract(address a) private view returns (bool) {
        return a.code.length > 0;
    }
}

/// @notice Holds ERC-777 tokens for users. Pays out before zeroing the
///         internal accounting — classic reentrancy via tokensReceived.
contract VulnerableERC777Vault {
    MockERC777Token public immutable token;
    mapping(address => uint256) public deposits;

    constructor(address tokenAddr) {
        token = MockERC777Token(tokenAddr);
    }

    /// @dev Fixture-style deposit: mints tokens straight to the vault and
    ///      credits the depositor. Production vaults would pull tokens via
    ///      approve+transferFrom or push semantics — the bug class is the
    ///      same either way (state ordering in `withdraw`).
    function deposit(uint256 amount) external {
        token.mint(address(this), amount);
        deposits[msg.sender] += amount;
    }

    /// @dev BUG: transfer (which fires tokensReceived) happens BEFORE the
    ///      `deposits[msg.sender] = 0` write. An attacker contract whose
    ///      `tokensReceived` re-enters `withdraw()` drains the vault.
    function withdraw() external {
        uint256 owed = deposits[msg.sender];
        require(owed > 0, "no deposit");

        // External call (with hook) BEFORE state update — vulnerable.
        token.transfer(msg.sender, owed);

        deposits[msg.sender] = 0; // Too late — attacker already re-entered.
    }
}
