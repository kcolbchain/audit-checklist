"""Custom Slither detector for ERC-20 approval race hazards.

Detects token-like contracts whose approve(address,uint256) implementation
directly overwrites allowance state without an obvious zero-first or
delta-based allowance guard. This flags the classic allowance front-running
pattern where a spender can consume the old allowance before a lower approval
lands, then consume the new allowance as well.
"""
try:
    from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
except ModuleNotFoundError:
    class DetectorClassification:
        MEDIUM = "medium"

    class AbstractDetector:
        pass


ALLOWANCE_NAMES = ("allowance", "allowances", "_allowances")
SAFE_GUARD_TERMS = (
    "increaseallowance",
    "decreaseallowance",
    "safeincreaseallowance",
    "safedecreaseallowance",
)


def _name_of(item) -> str:
    return str(getattr(item, "name", item)).lower()


def is_approve_function(function) -> bool:
    if _name_of(function) != "approve":
        return False
    parameters = list(getattr(function, "parameters", []) or [])
    return len(parameters) == 2


def function_writes_allowance(function) -> bool:
    for node in getattr(function, "nodes", []) or []:
        for ir in getattr(node, "irs", []) or []:
            writes = getattr(ir, "writes", None) or []
            for write in writes:
                variable = write[0] if isinstance(write, tuple) and write else write
                if _name_of(variable) in ALLOWANCE_NAMES:
                    return True
    text = str(getattr(function, "source_mapping", "")) + " " + str(getattr(function, "nodes", ""))
    lowered = text.lower()
    return any(name in lowered for name in ALLOWANCE_NAMES)


def has_allowance_race_guard(function) -> bool:
    text = " ".join(str(item).lower() for item in getattr(function, "nodes", []) or [])
    if any(term in text for term in SAFE_GUARD_TERMS):
        return True
    zero_guard_patterns = (
        "amount == 0",
        "amount==0",
        "value == 0",
        "value==0",
        "current == 0",
        "current==0",
        "allowance[msg.sender][spender] == 0",
        "_allowances[msg.sender][spender] == 0",
    )
    return any(pattern in text for pattern in zero_guard_patterns)


def find_approval_race_functions(contract) -> list:
    if getattr(contract, "is_interface", False):
        return []

    findings = []
    for function in getattr(contract, "functions", []) or []:
        if not getattr(function, "is_implemented", True):
            continue
        if is_approve_function(function) and function_writes_allowance(function) and not has_allowance_race_guard(function):
            findings.append(function)
    return findings


class CustomERC20ApprovalRaceDetector(AbstractDetector):
    ARGUMENT = "custom-erc20-approval-race"
    HELP = "Detects ERC-20 approve implementations vulnerable to allowance race conditions"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/kcolbchain/audit-checklist/wiki/ERC20-Approval-Race"
    WIKI_TITLE = "Custom ERC20 Approval Race Detector"

    def _detect(self) -> list:
        results = []
        for contract in self.compilation_unit.contracts:
            for function in find_approval_race_functions(contract):
                info = [
                    "ERC20 approve may overwrite allowance unsafely: ",
                    f"{function.name}() in {contract.name}\n",
                    "\nPrefer increase/decrease allowance flows or reject direct non-zero allowance changes.\n",
                ]
                res = self.generate_result(info)
                res.add(function)
                results.append(res)
        return results
