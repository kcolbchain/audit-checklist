"""Custom Slither detector for ERC-20 approval race conditions.

Detects: `approve(address,uint256)` functions that do not enforce
the allowance to be zero before setting a new non-zero value.
"""
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import Binary, BinaryType

class ERC20ApprovalRaceDetector(AbstractDetector):
    ARGUMENT = "erc20-approval-race"
    HELP = "Detects ERC-20 approval race conditions"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/kcolbchain/audit-checklist/wiki/ERC20-Approval-Race-Detector"
    WIKI_TITLE = "ERC20 Approval Race Detector"

    def _detect(self) -> list:
        results = []
        for contract in self.compilation_unit.contracts:
            for function in contract.functions_and_modifiers:
                if not function.is_implemented:
                    continue

                if function.name == "approve":
                    # Check if it has the standard signature (address,uint256)
                    if len(function.parameters) == 2 and str(function.parameters[1].type) == "uint256":
                        
                        # Look for a check that allowance == 0 or amount == 0
                        has_zero_check = False
                        for node in function.nodes:
                            if node.contains_require_or_assert():
                                # Very basic heuristic: look for equality checks with 0 in the condition
                                for ir in node.irs:
                                    if isinstance(ir, Binary) and ir.type == BinaryType.EQUAL:
                                        if "0" in str(ir.variable_right) or "0" in str(ir.variable_left):
                                            has_zero_check = True

                        if not has_zero_check:
                            info = [
                                "ERC-20 Approval Race Condition: ",
                                f"{function.name}() in {contract.name} does not enforce allowance to be zero before updating.\n",
                                "\nConsider using increaseAllowance/decreaseAllowance, or require(allowance == 0).\n",
                            ]
                            res = self.generate_result(info)
                            res.add(function)
                            results.append(res)

        return results
