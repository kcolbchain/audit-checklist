// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/checks/GovernanceCheck.sol";
import "../src/examples/VulnerableGovernance.sol";

contract ExampleGovernanceAudit is GovernanceCheck {
    SimpleGovernanceToken token;
    VulnerableGovernance gov;

    function setUp() public {
        token = new SimpleGovernanceToken();
        gov = new VulnerableGovernance(
            address(token),
            100e18,    // proposal threshold: 100 tokens
            4,         // quorum: 4% of supply
            1,         // voting delay: 1 block
            10,        // voting period: 10 blocks
            172800     // timelock: 2 days
        );
        targetContract = address(gov);
    }

    function distributeTokens(address to, uint256 amount) internal override {
        token.mint(to, amount);
    }

    function transferTokens(address from, address to, uint256 amount) internal override {
        vm.prank(from);
        token.transfer(to, amount);
    }

    function getProposeCalldata(bytes memory proposalData) internal view override returns (bytes memory) {
        return abi.encodeWithSignature("propose(bytes)", proposalData);
    }

    function getVoteCalldata(uint256 proposalId, bool support) internal pure override returns (bytes memory) {
        return abi.encodeWithSignature("castVote(uint256,bool)", proposalId, support);
    }

    function getExecuteCalldata(uint256 proposalId) internal pure override returns (bytes memory) {
        return abi.encodeWithSignature("execute(uint256)", proposalId);
    }

    function getQueueCalldata(uint256 proposalId) internal pure override returns (bytes memory) {
        return abi.encodeWithSignature("queue(uint256)", proposalId);
    }

    function getProposalThreshold() internal pure override returns (uint256) { return 100e18; }

    function getQuorum() internal view override returns (uint256) {
        return (token.totalSupply() * 4) / 100;
    }

    function getVotingDelay() internal pure override returns (uint256) { return 1; }
    function getVotingPeriod() internal pure override returns (uint256) { return 10; }
    function getTimelockDelay() internal pure override returns (uint256) { return 172800; }

    function createTestProposal() internal override returns (uint256) {
        address proposer = makeAddr("proposer");
        distributeTokens(proposer, 1000e18);
        vm.prank(proposer);
        return gov.propose(abi.encode("test proposal"));
    }

    function getProposalVotes(uint256 proposalId) internal view override returns (
        uint256 forVotes, uint256 againstVotes, uint256 abstainVotes
    ) {
        return gov.getProposalVotes(proposalId);
    }

    function isProposalExecuted(uint256 proposalId) internal view override returns (bool) {
        return gov.isProposalExecuted(proposalId);
    }

    function getGovernanceTokenSupply() internal view override returns (uint256) {
        return token.totalSupply();
    }
}
