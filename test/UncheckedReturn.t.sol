// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/checks/UncheckedReturnCheck.sol";
import "../src/examples/VulnerableUncheckedReturn.sol";
import "../src/examples/FixedUncheckedReturn.sol";

contract ExampleUncheckedReturnAudit is UncheckedReturnCheck {
    VulnerableUncheckedReturn vul;

    function setUp() public {
        vul = new VulnerableUncheckedReturn();
        targetContract = address(vul);
    }

    function getCallCalldata() internal pure override returns (bytes memory) {
        return abi.encodeWithSignature("withdraw(uint256)", 1 ether);
    }

    function setupCallContext(address caller) internal override {
        vm.deal(caller, 1 ether);
        vm.prank(caller);
        vul.deposit{value: 1 ether}();
    }
}

contract ExampleFixedUncheckedReturnAudit is UncheckedReturnCheck {
    FixedUncheckedReturn fixedContract;

    function setUp() public {
        fixedContract = new FixedUncheckedReturn();
        targetContract = address(fixedContract);
    }

    function getCallCalldata() internal pure override returns (bytes memory) {
        return abi.encodeWithSignature("withdraw(uint256)", 1 ether);
    }

    function setupCallContext(address caller) internal override {
        vm.deal(caller, 1 ether);
        vm.prank(caller);
        fixedContract.deposit{value: 1 ether}();
    }
}
