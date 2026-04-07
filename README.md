# audit-checklist

Executable smart contract audit checklist — drop-in Foundry test templates for common vulnerability classes. By [kcolbchain](https://kcolbchain.com) (est. 2015).

## Why this exists

Most audit checklists are PDFs. This one is code. Import it into your Foundry project and run `forge test` — it checks for reentrancy, access control gaps, oracle manipulation, upgrade risks, and flash loan vectors against your contracts.

Based on patterns from real audits since 2019.

## Quick start

```bash
forge install kcolbchain/audit-checklist
```

```solidity
import {ReentrancyCheck} from "audit-checklist/checks/ReentrancyCheck.sol";

contract MyVaultAudit is ReentrancyCheck {
    function setUp() public {
        targetContract = address(new MyVault());
    }
}
```

```bash
forge test
```

## Vulnerability classes covered

| Check | What it detects |
|-------|----------------|
| `ReentrancyCheck` | Checks-effects-interactions violations, cross-function reentrancy via callbacks |
| `AccessControlCheck` | Unprotected admin functions, unguarded initializers, missing role checks |
| `OracleCheck` | Spot price reads (manipulable), missing TWAP, single-source oracles |
| `UpgradeCheck` | Storage layout collisions in proxies, uninitialized implementation contracts |
| `FlashLoanCheck` | Functions vulnerable to flash-loan-powered price/state manipulation |
| `ERC4626Check` | First depositor attack, share price manipulation, rounding consistency, preview accuracy |

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
