"""Custom Slither detector for upgradeable storage gap regressions.

Detects upgradeable contracts that declare new state variables after a
reserved `__gap` array. In OpenZeppelin-style upgradeable contracts, new
storage belongs before the gap and the gap should shrink by the same slot
width; appending after `__gap` defeats that convention and can mask layout
regressions.
"""
try:
    from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
except ModuleNotFoundError:
    class DetectorClassification:
        MEDIUM = "medium"

    class AbstractDetector:
        pass


UPGRADEABLE_BASE_PATTERNS = (
    "initializable",
    "uupsupgradeable",
    "transparentupgradeableproxy",
    "erc1967",
    "upgradeable",
)


def _name_of(item) -> str:
    return str(getattr(item, "name", item)).lower()


def _declared_state_variables(contract) -> list:
    return list(getattr(contract, "state_variables_declared", None) or contract.state_variables)


def _is_storage_gap(variable) -> bool:
    return _name_of(variable) == "__gap"


def _is_persistent_state(variable) -> bool:
    if _is_storage_gap(variable):
        return False
    if getattr(variable, "is_constant", False) or getattr(variable, "is_immutable", False):
        return False
    return True


def is_upgradeable_contract(contract) -> bool:
    names = [_name_of(contract)]
    names.extend(_name_of(base) for base in getattr(contract, "inheritance", []))
    return any(pattern in name for name in names for pattern in UPGRADEABLE_BASE_PATTERNS)


def find_gap_order_violations(contract) -> list:
    """Return state variables declared after `__gap` in an upgradeable contract."""
    if getattr(contract, "is_interface", False) or not is_upgradeable_contract(contract):
        return []

    violations = []
    saw_gap = False
    for variable in _declared_state_variables(contract):
        if _is_storage_gap(variable):
            saw_gap = True
            continue
        if saw_gap and _is_persistent_state(variable):
            violations.append(variable)
    return violations


class CustomUpgradeGapDetector(AbstractDetector):
    ARGUMENT = "custom-upgrade-gap"
    HELP = "Detects upgradeable storage variables appended after __gap"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/kcolbchain/audit-checklist/wiki/Upgrade-Gap-Detector"
    WIKI_TITLE = "Custom Upgrade Gap Detector"

    def _detect(self) -> list:
        results = []
        for contract in self.compilation_unit.contracts:
            for variable in find_gap_order_violations(contract):
                info = [
                    "Upgradeable storage variable declared after __gap: ",
                    f"{variable.name} in {contract.name}\n",
                    "\nMove the new variable before __gap and shrink the gap array by the same slot width.\n",
                ]
                res = self.generate_result(info)
                res.add(variable)
                results.append(res)

        return results
