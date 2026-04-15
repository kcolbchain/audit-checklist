// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";

/// @title GovernanceCheck -- detect governance attack vulnerabilities
/// @notice Checks for: flash-loan governance attacks, proposal threshold manipulation,
///         timelock bypass, quorum calculation issues, and double voting prevention.
/// @author kcolbchain
abstract contract GovernanceCheck is ChecklistBase {

    // -----------------------------------------------------------------------
    // Hooks -- override these to adapt checks to your governance contract
    // -----------------------------------------------------------------------

    /// @dev Override to distribute governance tokens to an address
    function distributeTokens(address to, uint256 amount) internal virtual;

    /// @dev Override to return the calldata for creating a proposal
    function getProposeCalldata(bytes memory proposalData) internal view virtual returns (bytes memory);

    /// @dev Override to return the calldata for casting a vote
    function getVoteCalldata(uint256 proposalId, bool support) internal pure virtual returns (bytes memory);

    /// @dev Override to return the calldata for executing a proposal
    function getExecuteCalldata(uint256 proposalId) internal pure virtual returns (bytes memory);

    /// @dev Override to return the calldata for queueing a proposal in the timelock
    function getQueueCalldata(uint256 proposalId) internal pure virtual returns (bytes memory);

    /// @dev Override to return the proposal threshold (minimum tokens to propose)
    function getProposalThreshold() internal view virtual returns (uint256);

    /// @dev Override to return the quorum required for a proposal to pass
    function getQuorum() internal view virtual returns (uint256);

    /// @dev Override to return the voting delay in blocks
    function getVotingDelay() internal view virtual returns (uint256);

    /// @dev Override to return the voting period in blocks
    function getVotingPeriod() internal view virtual returns (uint256);

    /// @dev Override to return the timelock delay in seconds
    function getTimelockDelay() internal view virtual returns (uint256);

    /// @dev Override to create a test proposal and return its ID
    function createTestProposal() internal virtual returns (uint256);

    /// @dev Override to get the current vote count for a proposal
    function getProposalVotes(uint256 proposalId) internal view virtual returns (uint256 forVotes, uint256 againstVotes, uint256 abstainVotes);

    /// @dev Override to check if a proposal has been executed
    function isProposalExecuted(uint256 proposalId) internal view virtual returns (bool);

    /// @dev Override to get the total supply of governance tokens
    function getGovernanceTokenSupply() internal view virtual returns (uint256);

    /// @dev Override to transfer tokens between addresses
    function transferTokens(address from, address to, uint256 amount) internal virtual;

    // -----------------------------------------------------------------------
    // TEST 1: Flash-loan governance attack
    // -----------------------------------------------------------------------
    function test_flash_loan_governance_attack() public {
        uint256 proposalId = createTestProposal();
        uint256 flashAmount = getGovernanceTokenSupply() / 2;

        address attacker = makeAddr("gov_flash_attacker");

        // Simulate flash loan: give attacker massive voting power temporarily
        distributeTokens(attacker, flashAmount);

        // Advance past voting delay
        vm.roll(block.number + getVotingDelay() + 1);

        // Attacker attempts to vote with flash-loaned tokens
        vm.prank(attacker);
        (bool voteSuccess,) = targetContract.call(getVoteCalldata(proposalId, true));

        if (voteSuccess) {
            (uint256 forVotes,,) = getProposalVotes(proposalId);

            uint256 quorum = getQuorum();
            if (forVotes >= quorum) {
                emit log("VULNERABILITY: Flash-loaned tokens can single-handedly meet quorum");
                emit log_named_uint("Flash loan amount", flashAmount);
                emit log_named_uint("Quorum", quorum);
                emit log_named_uint("Votes cast", forVotes);
                fail();
            }
        }
    }

    // -----------------------------------------------------------------------
    // TEST 2: Proposal threshold manipulation
    // -----------------------------------------------------------------------
    function test_proposal_threshold_manipulation() public {
        uint256 threshold = getProposalThreshold();
        address proposer = makeAddr("threshold_manipulator");

        // Give proposer exactly the threshold amount + 1
        distributeTokens(proposer, threshold + 1);

        // Proposer creates a proposal at minimum threshold
        vm.prank(proposer);
        (bool proposeSuccess,) = targetContract.call(
            getProposeCalldata(abi.encode("malicious proposal"))
        );

        if (!proposeSuccess) {
            emit log("PASS: Proposal creation blocked at minimum threshold");
            return;
        }

        // Proposer transfers tokens away
        transferTokens(proposer, address(0xdead), threshold);

        // Check if a second proposal can be created with zero remaining balance
        vm.prank(proposer);
        (bool secondPropose,) = targetContract.call(
            getProposeCalldata(abi.encode("second proposal after drain"))
        );

        if (secondPropose) {
            emit log("VULNERABILITY: Can create proposals after draining governance tokens");
            fail();
        }
    }

    // -----------------------------------------------------------------------
    // TEST 3: Timelock bypass
    // -----------------------------------------------------------------------
    function test_timelock_bypass() public {
        uint256 proposalId = createTestProposal();
        uint256 votingDelayBlocks = getVotingDelay();
        uint256 votingPeriodBlocks = getVotingPeriod();

        // Advance past voting delay
        vm.roll(block.number + votingDelayBlocks + 1);

        // Cast enough votes to pass the proposal
        address voter = makeAddr("timelock_voter");
        uint256 govSupply = getGovernanceTokenSupply();
        distributeTokens(voter, govSupply / 2 + 1);

        vm.prank(voter);
        targetContract.call(getVoteCalldata(proposalId, true));

        // Advance past voting period
        vm.roll(block.number + votingPeriodBlocks + 1);

        // Try to queue
        (bool queueSuccess,) = targetContract.call(getQueueCalldata(proposalId));

        if (queueSuccess) {
            // Queue succeeded - now try to execute BEFORE timelock expires
            (bool execSuccess,) = targetContract.call(getExecuteCalldata(proposalId));

            if (execSuccess && isProposalExecuted(proposalId)) {
                emit log("VULNERABILITY: Proposal executed without waiting for timelock delay");
                emit log_named_uint("Timelock delay (seconds)", getTimelockDelay());
                fail();
            }
        }
    }

    // -----------------------------------------------------------------------
    // TEST 4: Quorum calculation issues
    // -----------------------------------------------------------------------
    function test_quorum_calculation() public {
        uint256 quorum = getQuorum();
        uint256 totalSupply = getGovernanceTokenSupply();

        // Check 1: Quorum should not exceed total supply
        if (quorum > totalSupply) {
            emit log("VULNERABILITY: Quorum exceeds total token supply - governance is permanently locked");
            emit log_named_uint("Quorum", quorum);
            emit log_named_uint("Total supply", totalSupply);
            fail();
            return;
        }

        // Check 2: Quorum percentage sanity check
        uint256 quorumPct = (quorum * 100) / totalSupply;
        if (quorumPct > 50) {
            emit log("WARNING: Quorum exceeds 50% of supply - governance may be difficult to pass proposals");
            emit log_named_uint("Quorum pct", quorumPct);
        }

        // Check 3: Abstain votes should not count toward quorum
        uint256 proposalId = createTestProposal();

        address abstainer = makeAddr("abstainer");
        distributeTokens(abstainer, quorum);

        vm.roll(block.number + getVotingDelay() + 1);

        // Vote against (abstain proxy) with quorum worth of tokens
        vm.prank(abstainer);
        targetContract.call(getVoteCalldata(proposalId, false));

        (uint256 forVotes, uint256 againstVotes, uint256 abstainVotes) = getProposalVotes(proposalId);

        // If only against votes were cast and forVotes is 0, quorum should NOT be met
        // unless the protocol incorrectly counts all votes toward quorum
        uint256 totalParticipation = forVotes + againstVotes + abstainVotes;
        if (totalParticipation >= quorum && forVotes == 0) {
            emit log("WARNING: Quorum met with only against/abstain votes - check if this is intended");
            emit log_named_uint("Total participation", totalParticipation);
            emit log_named_uint("Quorum", quorum);
        }
    }

    // -----------------------------------------------------------------------
    // TEST 5: Double voting prevention
    // -----------------------------------------------------------------------
    function test_double_voting_prevention() public {
        uint256 proposalId = createTestProposal();
        uint256 voteAmount = getProposalThreshold();

        address voter1 = makeAddr("double_voter_1");
        address voter2 = makeAddr("double_voter_2");

        distributeTokens(voter1, voteAmount * 2);

        vm.roll(block.number + getVotingDelay() + 1);

        // Voter1 votes
        vm.prank(voter1);
        targetContract.call(getVoteCalldata(proposalId, true));

        (uint256 forVotesBefore,,) = getProposalVotes(proposalId);

        // Voter1 transfers tokens to voter2
        transferTokens(voter1, voter2, voteAmount);

        // Voter2 tries to vote with received tokens
        vm.prank(voter2);
        (bool secondVoteSuccess,) = targetContract.call(getVoteCalldata(proposalId, true));

        if (secondVoteSuccess) {
            (uint256 forVotesAfter,,) = getProposalVotes(proposalId);

            if (forVotesAfter > forVotesBefore) {
                uint256 voteDiff = forVotesAfter - forVotesBefore;
                uint256 expectedMaxIncrease = voteAmount;

                if (voteDiff > expectedMaxIncrease) {
                    emit log("VULNERABILITY: Double voting detected - votes cast exceed token transfer");
                    emit log_named_uint("Vote increase", voteDiff);
                    emit log_named_uint("Expected max", expectedMaxIncrease);
                    fail();
                }
            }
        }
    }
}
