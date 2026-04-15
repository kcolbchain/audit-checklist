"""Custom Slither detector for governance attack vulnerabilities.

Detects: timelock bypass, proposal execution without delay,
and governance parameter manipulation.
"""
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CustomGovernanceDetector(AbstractDetector):
    ARGUMENT = "custom-governance-detector"
    HELP = "Detects governance attack patterns (timelock bypass, missing execution delays)"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/kcolbchain/audit-checklist/wiki/Governance-Detector"
    WIKI_TITLE = "Custom Governance Detector"

    def _detect(self) -> list:
        results = []
        gov_patterns = [
            "propose", "execute", "queue", "cancel", "castvote",
            "timelock", "delay", "governor", "proposal",
        ]

        for contract in self.compilation_unit.contracts:
            if contract.is_interface:
                continue

            has_timelock = any("timelock" in f.name.lower() or "delay" in f.name.lower() for f in contract.functions)
            has_execute = any("execute" in f.name.lower() for f in contract.functions)

            for function in contract.functions:
                if not function.is_implemented:
                    continue

                func_name = function.name.lower()

                # Check execute functions for timelock
                if "execute" in func_name and "proposal" in func_name:
                    if not has_timelock:
                        info = [
                            "Governance execution without timelock: ",
                            f"{function.name}() in {contract.name}\n",
                            "\nProposal execution should go through a timelock to allow review.\n",
                        ]
                        res = self.generate_result(info)
                        res.add(function)
                        results.append(res)

                # Check for direct state changes without governance
                if any(p in func_name for p in ["set", "update", "change", "modify"]):
                    if function.visibility in ["public", "external"]:
                        has_gov_modifier = any(
                            m.name.lower() in ("onlygovernance", "onlyowner", "onlytimelock", "onlyproxy")
                            for m in function.modifiers
                        )
                        # Check if function modifies critical governance parameters
                        modifies_critical = any(
                            p in str(node.irs).lower()
                            for node in function.nodes
                            for p in ["fee", "rate", "threshold", "quorum", "delay", "period"]
                        )
                        if modifies_critical and not has_gov_modifier:
                            info = [
                                "Governance parameter change without access control: ",
                                f"{function.name}() in {contract.name}\n",
                                "\nCritical parameter changes should require governance approval.\n",
                            ]
                            res = self.generate_result(info)
                            res.add(function)
                            results.append(res)

        return results
