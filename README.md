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

### Your First Audit

1. **Create a test file** that imports the checks you need:

```solidity
// test/MyContractAudit.t.sol
import {ReentrancyCheck} from "audit-checklist/checks/ReentrancyCheck.sol";
import {AccessControlCheck} from "audit-checklist/checks/AccessControlCheck.sol";

contract MyContractAudit is ReentrancyCheck, AccessControlCheck {
    function setUp() public {
        // Replace with your contract address
        targetContract = address(new MyContract());
    }
}
```

2. **Deploy your contract** in `setUp()` if needed:

```solidity
function setUp() public {
    vm.deal(address(this), 100 ether);
    targetContract = address(new MyContract());
}
```

3. **Run the audit:**

```bash
forge test -vv
```

4. **Review results:**
   - ✅ Passing tests = no issues found
   - ❌ Failing tests = potential vulnerability detected
   - Review each failing test to determine if it's a false positive

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
