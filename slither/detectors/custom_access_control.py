"""Custom Slither detector for access control vulnerabilities.

Detects: uninitialized ownership, missing access control on critical functions,
and functions that can only be called by owner but lack onlyOwner modifier.
"""
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Function


CRITICAL_PATTERNS = [
    "transfer", "transferfrom", "transferownership", "renounceownership",
    "mint", "burn", "pause", "unpause", "upgrade", "initialize",
    "withdraw", "deposit", "setfee", "setadmin", "grantrole", "revokerole",
    "setprotocolfee", "settreasury", "sweep", "recover",
]


class CustomAccessControlDetector(AbstractDetector):
    ARGUMENT = "custom-access-control-detector"
    HELP = "Detects access control issues (missing modifiers, unprotected critical functions)"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/kcolbchain/audit-checklist/wiki/Access-Control-Detector"
    WIKI_TITLE = "Custom Access Control Detector"

    def _detect(self) -> list:
        results = []
        for contract in self.compilation_unit.contracts:
            if contract.is_interface:
                continue

            owner_vars = [
                v for v in contract.state_variables
                if any(p in v.name.lower() for p in ["owner", "admin", "authority", "governor"])
            ]

            for function in contract.functions:
                if not function.is_implemented or function.is_constructor:
                    continue

                func_name = function.name.lower()

                # Check critical functions for access control
                is_critical = any(p in func_name for p in CRITICAL_PATTERNS)

                if is_critical and function.visibility in ["public", "external"]:
                    has_access_control = any(
                        m.name.lower() in ("onlyowner", "onlyadmin", "onlyrole", "onlygovernor",
                                           "whennotpaused", "nonreentrant", "authorized")
                        for m in function.modifiers
                    )

                    if not has_access_control:
                        info = [
                            "Critical function lacks access control: ",
                            f"{function.name}() in {contract.name}\n",
                            f"  Visibility: {function.visibility}\n",
                            f"  Modifiers: {[m.name for m in function.modifiers] or 'none'}\n",
                            "\nConsider adding onlyOwner or equivalent access control.\n",
                        ]
                        res = self.generate_result(info)
                        res.add(function)
                        results.append(res)

            # Check for uninitialized owner in non-abstract contracts
            if owner_vars and not any(
                f.is_constructor and any(
                    str(v) in str(f.nodes) for v in owner_vars
                ) for f in contract.functions
            ):
                # Check initialize function for proxies
                has_init = any(f.name.lower() == "initialize" for f in contract.functions)
                if not has_init and contract.kind != "interface":
                    for var in owner_vars:
                        # Check if variable has an initializer
                        has_default = var.expression is not None
                        if not has_default:
                            info = [
                                "Owner variable potentially uninitialized: ",
                                f"{var.name} in {contract.name}\n",
                                "\nEnsure ownership is set in constructor or initialize().\n",
                            ]
                            res = self.generate_result(info)
                            res.add(var)
                            results.append(res)

        return results
