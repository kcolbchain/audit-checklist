# Slither Integration

Custom Slither static analysis detectors that mirror the Foundry test checks.

## Detectors

| Detector | Pattern | Severity |
|----------|---------|----------|
| `custom-reentrancy-detector` | CEI violations, unprotected callbacks | High |
| `custom-access-control-detector` | Missing modifiers on critical functions | High |
| `custom-oracle-manipulation-detector` | Spot price without TWAP | High |
| `custom-flash-loan-detector` | Atomic read-write on external state | High |
| `custom-governance-detector` | Timelock bypass, parameter manipulation | High |

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
