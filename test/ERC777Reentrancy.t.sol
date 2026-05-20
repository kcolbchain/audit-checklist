// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/checks/ERC777ReentrancyCheck.sol";

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

contract MockERC777Token {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function send(address to, uint256 amount, bytes calldata data) external {
        _send(msg.sender, msg.sender, to, amount, data, "");
    }

    function _send(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes memory userData,
        bytes memory operatorData
    ) internal {
        require(balanceOf[from] >= amount, "insufficient balance");

        balanceOf[from] -= amount;
        balanceOf[to] += amount;

        if (to.code.length > 0) {
            try IERC777Recipient(to).tokensReceived(operator, from, to, amount, userData, operatorData) {} catch {}
        }
    }
}

contract VulnerableERC777Vault is IERC777Recipient {
    MockERC777Token public immutable token;
    mapping(address => uint256) public balances;

    constructor(MockERC777Token _token) {
        token = _token;
    }

    function tokensReceived(address, address from, address, uint256 amount, bytes calldata, bytes calldata) external {
        require(msg.sender == address(token), "unknown token");
        balances[from] += amount;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");

        token.send(msg.sender, amount, "");

        balances[msg.sender] = 0;
    }
}

contract SafeERC777Vault is IERC777Recipient {
    MockERC777Token public immutable token;
    mapping(address => uint256) public balances;

    constructor(MockERC777Token _token) {
        token = _token;
    }

    function tokensReceived(address, address from, address, uint256 amount, bytes calldata, bytes calldata) external {
        require(msg.sender == address(token), "unknown token");
        balances[from] += amount;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");

        balances[msg.sender] = 0;

        token.send(msg.sender, amount, "");
    }
}

contract VulnerableERC777Audit is ERC777ReentrancyCheck {
    MockERC777Token token;
    VulnerableERC777Vault vault;

    function setUp() public {
        token = new MockERC777Token();
        vault = new VulnerableERC777Vault(token);
        targetContract = address(vault);

        address victim = makeAddr("victim");
        token.mint(victim, 300 ether);
        vm.prank(victim);
        token.send(address(vault), 300 ether, "");
    }

    function getERC777Token() internal view override returns (address) {
        return address(token);
    }

    function getERC777WithdrawCalldata() internal pure override returns (bytes memory) {
        return abi.encodeWithSignature("withdraw()");
    }

    function fundERC777Depositor(address depositor, uint256 amount) internal override {
        token.mint(depositor, amount);
    }

    function performERC777Deposit(address depositor, uint256 amount) internal override {
        vm.prank(depositor);
        token.send(address(vault), amount, "");
    }

    function test_erc777_tokens_received_reentrancy() public override {}

    function runERC777ReentrancyCheck() external {
        super.test_erc777_tokens_received_reentrancy();
    }
}

contract SafeERC777Audit is ERC777ReentrancyCheck {
    MockERC777Token token;
    SafeERC777Vault vault;

    function setUp() public {
        token = new MockERC777Token();
        vault = new SafeERC777Vault(token);
        targetContract = address(vault);

        address victim = makeAddr("victim");
        token.mint(victim, 300 ether);
        vm.prank(victim);
        token.send(address(vault), 300 ether, "");
    }

    function getERC777Token() internal view override returns (address) {
        return address(token);
    }

    function getERC777WithdrawCalldata() internal pure override returns (bytes memory) {
        return abi.encodeWithSignature("withdraw()");
    }

    function fundERC777Depositor(address depositor, uint256 amount) internal override {
        token.mint(depositor, amount);
    }

    function performERC777Deposit(address depositor, uint256 amount) internal override {
        vm.prank(depositor);
        token.send(address(vault), amount, "");
    }
}

contract ERC777ReentrancyTemplateTest is Test {
    function test_check_passes_for_safe_erc777_vault() public {
        SafeERC777Audit audit = new SafeERC777Audit();
        audit.setUp();
        audit.test_erc777_tokens_received_reentrancy();
    }

    function test_check_flags_vulnerable_erc777_vault() public {
        VulnerableERC777Audit audit = new VulnerableERC777Audit();
        audit.setUp();

        (bool success,) = address(audit).call(abi.encodeWithSignature("runERC777ReentrancyCheck()"));

        assertFalse(success, "ERC777 reentrancy check should fail on vulnerable accounting");
    }
}
