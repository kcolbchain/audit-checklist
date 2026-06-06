// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract VulnerableUncheckedCall {
    address public externalContract;
    uint256 public counter;

    function setExternal(address _ext) external {
        externalContract = _ext;
    }

    function executeCall() external {
        // Vulnerability: silently discards the boolean return value
        externalContract.call(abi.encodeWithSignature("doSomething()"));
        counter++;
    }
}

contract FixedUncheckedCall {
    address public externalContract;
    uint256 public counter;

    function setExternal(address _ext) external {
        externalContract = _ext;
    }

    function executeCall() external {
        (bool success, ) = externalContract.call(abi.encodeWithSignature("doSomething()"));
        require(success, "Call failed");
        counter++;
    }
}
