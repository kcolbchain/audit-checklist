from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.cfg.node import Node

class ERC20ApprovalRaceDetector(AbstractDetector):
    ARGUMENT = "erc20-approval-race-detector"
    HELP = "Detects ERC-20 approval race condition vulnerabilities"

    def detect(self, contract):
        violations = []
        for function in contract.functions:
            if function.name == "approve":
                for node in function.nodes:
                    if node.calls_internal("transferFrom") or node.calls_internal("transfer"):
                        # Check if the state variable is updated after the external call
                        state_variable_updated = False
                        for n in node.sons:
                            if n.update_state_variable:
                                state_variable_updated = True
                                break
                        if not state_variable_updated:
                            violations.append(node)
        return violations
