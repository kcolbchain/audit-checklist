# Slither Integration

Custom Slither static analysis detectors that mirror the Foundry test checks.

## Detectors

| Detector | Confidence | Impact | What It Catches | Vulnerable Example | CLI Invocation |
|----------|-----------|--------|-----------------|-------------------|----------------|
| `custom-reentrancy-detector` | Medium | High | CEI violations (Checks-Effects-Interactions pattern broken), unprotected `receive`/`fallback` with external calls, public functions with external calls and state writes but no `ReentrancyGuard` | ```solidity\nfunction withdraw() public {\n    (bool ok, ) = caller.call{value: bal}("");  // external call\n    balances[msg.sender] = 0;                     // state write after\n}\n``` | `slither . --detect custom-reentrancy-detector` |
| `custom-access-control-detector` | Medium | High | Critical functions (`transfer`, `mint`, `pause`, `withdraw`, etc.) missing `onlyOwner`/`onlyAdmin` modifiers, uninitialized `owner`/`admin` variables | ```solidity\nfunction pause() public {    // public, no modifier\n    paused = true;\n}\n\nconstructor() {\n    // owner never initialized\n}\n``` | `slither . --detect custom-access-control-detector` |
| `custom-flash-loan-detector` | Low | High | Functions with names containing `swap`/`liquidate`/`redeem`/`execute` that read external state and write state atomically — classic flash loan attack surface | ```solidity\nfunction swap(address tokenIn, address tokenOut) external {\n    uint256 price = IUniswapV2Pair(pair).getReserves()[0];  // read external\n    uint256 amountOut = price * amountIn / 1e18;              // write state\n    IERC20(tokenOut).transfer(msg.sender, amountOut);         // external call\n}\n``` | `slither . --detect custom-flash-loan-detector` |
| `custom-oracle-manipulation-detector` | Medium | High | Spot price usage (`getPrice`, `latestPrice`, `spotPrice`) without TWAP, single-source oracle without fallback, price-dependent state changes on uncached values | ```solidity\nfunction getAmountOut(uint256 amountIn) public view returns (uint256) {\n    uint256 price = pair.getReserves()[0];      // spot price, no TWAP\n    return price * amountIn / 1e18;\n}\n\nfunction executeTrade() external {\n    uint256 price = getAmountOut(1000);          // reads spot → state change\n    // vulnerable to flash loan manipulation\n}\n``` | `slither . --detect custom-oracle-manipulation-detector` |
| `custom-governance-detector` | Medium | High | `execute`/`propose` functions without timelock delay, governance parameter changes (`setFee`, `setDelay`, `updateThreshold`) without `onlyGovernance` modifier | ```solidity\nfunction execute(uint256 proposalId) external {\n    // no timelock check — executes immediately\n    targets[proposalId].call(calldata[proposalId]);\n}\n\nfunction setFee(uint256 newFee) external {       // public, no modifier\n    fee = newFee;                                 // critical param change\n}\n``` | `slither . --detect custom-governance-detector` |

## Usage

### Run all detectors
```bash
pip install slither-analyzer
slither . --config slither.config.json
```

### Run a specific detector
```bash
slither . --detect custom-reentrancy-detector
```

### Run with SARIF output
```bash
slither . --config slither.config.json --sarif output.sarif
```

## Per-Detector Source Files

| Detector | Source File |
|----------|------------|
| `custom-reentrancy-detector` | [`slither/detectors/custom_reentrancy.py`](slither/detectors/custom_reentrancy.py) |
| `custom-access-control-detector` | [`slither/detectors/custom_access_control.py`](slither/detectors/custom_access_control.py) |
| `custom-flash-loan-detector` | [`slither/detectors/custom_flash_loan.py`](slither/detectors/custom_flash_loan.py) |
| `custom-oracle-manipulation-detector` | [`slither/detectors/custom_oracle.py`](slither/detectors/custom_oracle.py) |
| `custom-governance-detector` | [`slither/detectors/custom_governance.py`](slither/detectors/custom_governance.py) |

## Confidence vs Impact

- **Confidence** reflects how reliably the detector identifies real vulnerabilities vs false positives:
  - **Medium** — heuristics can trigger on benign code; manual review recommended
  - **Low** — intentionally broad to catch more cases; expect false positives
- **Impact** reflects the severity of the issue if it is a true positive:
  - **High** — can lead to significant fund loss or contract compromise

## GitHub Actions

The `.github/workflows/audit.yml` workflow runs both:
1. **Foundry tests** — runtime vulnerability checks
2. **Slither analysis** — static analysis with custom detectors

Results are uploaded as SARIF for GitHub Code Scanning integration.

## Adding New Detectors

1. Create a new file in `slither/detectors/`
2. Extend `AbstractDetector` from Slither
3. Add the detector argument to `slither.config.json`
4. The CI workflow will automatically pick it up
