"""Custom Slither detector for unchecked low-level calls.

Detects: contracts that make low-level calls without checking the return value.
"""
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declaration import Function
from slither.core.cfg.node import Node
from slither.analyses.data_flow.data_flow import get_all_calls
from slither.exceptions import SlitherError


class CustomUncheckedLowLevelCallDetector(AbstractDetector):
    ARGUMENT = "custom-unchecked-low-level-call-detector"
    HELP = "Detects contracts that make low-level calls without checking the return value"
    DESCRIPTION = "Detects contracts that make low-level calls without checking the return value"
    CLASSIFICATION = DetectorClassification.BEST_PRACTICE

    def detect(self, contract: "Contract") -> List[Dict]:
        results = []

        for function in contract.functions_and_modifiers_declared:
            for node in function.nodes:
                calls = get_all_calls(node)
                for call in calls:
                    if isinstance(call, Node) and call.type == NodeType.EXPRESSION:
                        expression = call.expression
                        if isinstance(expression, CallExpression):
                            if expression.function == "call" or expression.function == "staticcall":
                                if not self.is_return_value_checked(node, function):
                                    results.append(
                                        {
                                            "contract": contract,
                                            "function": function,
                                            "node": node,
                                        }
                                    )

        return results

    def is_return_value_checked(self, node: Node, function: Function) -> bool:
        # Simplified implementation, might need to be adjusted based on actual Slither API
        for n in function.nodes:
            if n == node:
                if n.solidity_code:
                    code = n.solidity_code
                    lines = code.split("\n")
                    for line in lines:
                        line = line.strip()
                        if line.endswith("= call(") or line.endswith("= staticcall("):
                            return True
        return False
