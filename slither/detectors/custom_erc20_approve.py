"""Custom Slither detector for ERC-20 approval race condition.

Detects: ERC20 approve functions that don't enforce changing from/to zero.
"""
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.cfg.node import NodeType

class CustomERC20ApproveDetector(AbstractDetector):
    ARGUMENT = "custom-erc20-approve-detector"
    HELP = "Detects ERC20 approve race condition"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/kcolbchain/audit-checklist/wiki/ERC20-Approve-Detector"
    WIKI_TITLE = "Custom ERC20 Approve Detector"

    def _detect(self) -> list:
        results = []
        for contract in self.compilation_unit.contracts:
            for function in contract.functions_and_modifiers:
                if not function.is_implemented:
                    continue

                if function.name == "approve":
                    has_zero_check = False
                    for node in function.nodes:
                        if node.type in [NodeType.IF, NodeType.EXPRESSION]:
                            if node.expression and "0" in str(node.expression):
                                has_zero_check = True
                    
                    if not has_zero_check:
                        info = [
                            "ERC20 approve() lacks race condition mitigation: ",
                            f"{function.name}() in {contract.name}\n",
                            "\nConsider forcing allowance to 0 first, or using increaseAllowance/decreaseAllowance.\n",
                        ]
                        res = self.generate_result(info)
                        results.append(res)

        return results
