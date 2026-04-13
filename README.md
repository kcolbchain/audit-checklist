# audit-checklist

Executable smart contract audit checklist — drop-in Foundry test templates for common vulnerability classes. By [kcolbchain](https://kcolbchain.com) (est. 2015).

## Why this exists

Most audit checklists are PDFs. This one is code. Import it into your Foundry project and run `forge test` — it checks for reentrancy, access control gaps, oracle manipulation, upgrade risks, and flash loan vectors against your contracts.

Based on patterns from real audits since 2019.

## Quick start

```bash
# Install Foundry if you haven't already
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Create a new Foundry project (or use existing)
forge init my-audit-project
cd my-audit-project

# Install audit-checklist
forge install kcolbchain/audit-checklist
```

### Your First Audit — 5-minute tutorial

This walks you end-to-end against a deliberately vulnerable contract that
ships with the repo (`VulnerableVault.sol`). By the end you'll have run a
real audit and seen each check flag a real bug.

#### 1. Install

```bash
forge init my-audit-project && cd my-audit-project
forge install kcolbchain/audit-checklist
```

`remappings.txt` should now contain `audit-checklist/=lib/audit-checklist/src/`.

#### 2. Write the audit harness

Create `test/VaultAudit.t.sol` — every check needs a `setUp()` that
deploys the target contract and points `targetContract` at it, plus any
protocol-specific hooks (e.g. how to deposit, which function to withdraw).
Checks subclass `forge-std/Test`, so you can use all the usual Foundry
helpers.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyCheck} from "audit-checklist/checks/ReentrancyCheck.sol";
import {AccessControlCheck} from "audit-checklist/checks/AccessControlCheck.sol";
import {VulnerableVault} from "audit-checklist/examples/VulnerableVault.sol";

contract VaultReentrancyAudit is ReentrancyCheck {
    VulnerableVault vault;

    function setUp() public {
        vault = new VulnerableVault();
        vault.initialize();
        targetContract = address(vault);
    }

    // Tell ReentrancyCheck how to trigger a withdraw + how to seed deposits.
    function getWithdrawCalldata() internal pure override returns (bytes memory) {
        return abi.encodeWithSignature("withdraw()");
    }

    function performDeposit(address depositor, uint256 amount) internal override {
        vm.prank(depositor);
        vault.deposit{value: amount}();
    }
}
```

See `test/Example.t.sol` in this repo for the same pattern applied to
`AccessControlCheck`, `OracleCheck`, `UpgradeCheck`, and `FlashLoanCheck`.

#### 3. Run it

```bash
forge test -vv
```

Against `VulnerableVault`, expected output is:

```
Running 1 test for test/VaultAudit.t.sol:VaultReentrancyAudit
[FAIL. Reason: Reentrancy detected: balance drained by recursive call]
    test_Reentrancy_WithdrawDoesNotFollowCEI()
```

That's the tool **working as intended** — a failing test means the
check found a bug. For your own contracts, a clean `forge test` run
means no pattern matched; a failure is a vulnerability lead to
investigate.

#### 4. Interpret results

| Outcome                        | What it means                                                                 |
| ------------------------------ | ----------------------------------------------------------------------------- |
| ✅ All checks pass             | No pattern from this checklist fired. Still audit manually.                   |
| ❌ A check fails               | A known-bad pattern matched. Read the failure reason, then verify by hand.    |
| ⚠️ Test reverts during `setUp` | Your hook (e.g. `performDeposit`) is wrong — the check never actually ran.    |

#### 5. Walk through the shipped example

```bash
forge test --match-contract Example -vvv
```

This runs every check against `VulnerableVault`, which has four
deliberate bugs (missing init guard, reentrancy in `withdraw`, missing
access control on `emergencyWithdraw`, spot-price oracle). Every check
should fail — confirming your installation works and giving you a
reference for what real failures look like.

### Running Specific Checks

```solidity
// Run only reentrancy checks
import {ReentrancyCheck} from "audit-checklist/checks/ReentrancyCheck.sol";
contract MyAudit is ReentrancyCheck { ... }

// Run only access control checks
import {AccessControlCheck} from "audit-checklist/checks/AccessControlCheck.sol";
contract MyAudit is AccessControlCheck { ... }

// Run all checks
import {ReentrancyCheck, AccessControlCheck, OracleCheck, UpgradeCheck, FlashLoanCheck} from "audit-checklist/checks/ReentrancyCheck.sol";
contract MyAudit is ReentrancyCheck, AccessControlCheck, OracleCheck, UpgradeCheck, FlashLoanCheck { ... }
```

### Example: Auditing a Vulnerable Contract

The repo includes `VulnerableVault.sol` to demonstrate how the checks work:

```bash
# Run the example audit
forge test --match-contract Example -vvv
```

This runs all checks against the intentionally vulnerable demo contract, showing what each test catches.

## Vulnerability classes covered

| Check | What it detects |
|-------|----------------|
| `ReentrancyCheck` | Checks-effects-interactions violations, cross-function reentrancy via callbacks |
| `AccessControlCheck` | Unprotected admin functions, unguarded initializers, missing role checks |
| `OracleCheck` | Spot price reads (manipulable), missing TWAP, single-source oracles |
| `UpgradeCheck` | Storage layout collisions in proxies, uninitialized implementation contracts |
| `FlashLoanCheck` | Functions vulnerable to flash-loan-powered price/state manipulation |

## Architecture

```
src/
├── ChecklistBase.sol        — Base contract with shared test helpers
├── checks/
│   ├── ReentrancyCheck.sol  — Reentrancy detection tests
│   ├── AccessControlCheck.sol — Access control verification
│   ├── OracleCheck.sol      — Oracle manipulation checks
│   ├── UpgradeCheck.sol     — Proxy upgrade safety
│   └── FlashLoanCheck.sol   — Flash loan resistance
├── examples/
│   └── VulnerableVault.sol  — Intentionally vulnerable demo contract
test/
└── Example.t.sol            — Full example audit against VulnerableVault
```

## License

MIT

## Contributing

Issues and PRs welcome. If you've found a vulnerability pattern that isn't covered, open an issue or submit a check.
