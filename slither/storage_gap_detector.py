"""Custom Slither detector for UUPS/Transparent proxy storage-gap violations.

Detects upgradeable contracts that are missing __gap array slots,
which can cause storage collisions in proxy upgrade patterns.
"""
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StorageGapDetector(AbstractDetector):
    ARGUMENT = "storage-gap-check"
    HELP = "Check for missing __gap array in upgradeable contracts"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/kcolbchain/audit-checklist"
    WIKI_TITLE = "Storage gap check"
    WIKI_DESCRIPTION = "Detects upgradeable contracts missing __gap storage slots"

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            if contract.is_upgradeable or "Upgradeable" in str(contract.contract_kind):
                has_gap = any(v.name == "__gap" for v in contract.state_variables if v.is_storage)
                if not has_gap:
                    info = ["Contract ", contract, " is upgradeable but missing __gap array"]
                    res = self.generate_result(info)
                    results.append(res)
        return results
