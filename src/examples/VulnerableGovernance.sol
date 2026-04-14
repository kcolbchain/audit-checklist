// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableGovernance - intentionally vulnerable governance for testing
/// @notice DO NOT USE IN PRODUCTION. This contract has deliberate vulnerabilities
///         to demonstrate GovernanceCheck detection capabilities.
/// @author kcolbchain

contract SimpleGovernanceToken {
    string public name = "GovernanceToken";
    string public symbol = "GOV";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor() {
        _mint(msg.sender, 1_000_000e18);
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function mint(address to, uint256 amount) external {
        // BUG: Anyone can mint - no access control
        _mint(to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract VulnerableGovernance {
    struct Proposal {
        address proposer;
        bytes callData;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 abstainVotes;
        uint256 startBlock;
        uint256 endBlock;
        bool executed;
        bool queued;
        mapping(address => bool) hasVoted;
    }

    SimpleGovernanceToken public token;
    uint256 public proposalCount;
    uint256 public proposalThreshold;
    uint256 public quorumNumerator;
    uint256 public votingDelay;
    uint256 public votingPeriod;
    uint256 public timelockDelay;

    mapping(uint256 => Proposal) public proposals;

    constructor(
        address _token,
        uint256 _threshold,
        uint256 _quorumNumerator,
        uint256 _votingDelay,
        uint256 _votingPeriod,
        uint256 _timelockDelay
    ) {
        token = SimpleGovernanceToken(_token);
        proposalThreshold = _threshold;
        quorumNumerator = _quorumNumerator;
        votingDelay = _votingDelay;
        votingPeriod = _votingPeriod;
        timelockDelay = _timelockDelay;
    }

    function propose(bytes memory _callData) external returns (uint256) {
        // BUG 1: Only checks current balance, not snapshot - flash loan attackable
        require(token.balanceOf(msg.sender) >= proposalThreshold, "Below threshold");

        uint256 proposalId = proposalCount++;
        Proposal storage p = proposals[proposalId];
        p.proposer = msg.sender;
        p.callData = _callData;
        p.startBlock = block.number + votingDelay;
        p.endBlock = block.number + votingDelay + votingPeriod;

        return proposalId;
    }

    function castVote(uint256 proposalId, bool support) external {
        Proposal storage p = proposals[proposalId];
        require(block.number >= p.startBlock, "Voting not started");
        require(block.number <= p.endBlock, "Voting ended");
        require(!p.hasVoted[msg.sender], "Already voted");

        // BUG 2: Uses current balance, not snapshot - allows flash loan voting
        uint256 weight = token.balanceOf(msg.sender);
        require(weight > 0, "No voting power");

        p.hasVoted[msg.sender] = true;

        if (support) {
            p.forVotes += weight;
        } else {
            p.againstVotes += weight;
        }
    }

    function queue(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(block.number > p.endBlock, "Voting still active");
        require(!p.queued, "Already queued");

        uint256 quorum = (token.totalSupply() * quorumNumerator) / 100;
        uint256 totalVotes = p.forVotes + p.againstVotes + p.abstainVotes;
        require(totalVotes >= quorum, "Quorum not reached");
        require(p.forVotes > p.againstVotes, "Proposal defeated");

        p.queued = true;
    }

    function execute(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(p.queued, "Not queued");
        // BUG 3: No timelock delay enforcement - can execute immediately after queue
        require(!p.executed, "Already executed");

        p.executed = true;
    }

    function getProposalVotes(uint256 proposalId) external view returns (
        uint256 forVotes, uint256 againstVotes, uint256 abstainVotes
    ) {
        Proposal storage p = proposals[proposalId];
        return (p.forVotes, p.againstVotes, p.abstainVotes);
    }

    function isProposalExecuted(uint256 proposalId) external view returns (bool) {
        return proposals[proposalId].executed;
    }
}
