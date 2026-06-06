"""Custom Slither detector for ERC-20 approval race condition.

Detects: approve() functions that do not require the current allowance to be zero
before setting a new non-zero value, which is vulnerable to front-running.
"""
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.cfg.node import Node


class ERC20ApprovalRaceDetector(AbstractDetector):
    ARGUMENT = "erc20-approval-race"
    HELP = "Detects ERC-20 approve() race condition vulnerability"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/kcolbchain/audit-checklist/wiki/ERC20-Approval-Race"
    WIKI_TITLE = "ERC20 Approval Race Condition"

    def _detect(self) -> list:
        results = []
        for contract in self.compilation_unit.contracts:
            # Look for approve(address,uint256) function
            approve = contract.get_function_from_signature("approve(address,uint256)")
            if not approve or not approve.is_implemented:
                continue

            # Check if it implements a zero-allowance requirement
            # Common pattern: require(allowance[msg.sender][spender] == 0)
            has_zero_check = False
            for node in approve.nodes:
                if node.contains_require_or_assert():
                    # Check if the require condition involves the allowance mapping
                    # This is a heuristic: looking for comparisons with zero
                    if "0" in str(node.expression):
                        has_zero_check = True
                        break
                
                # Check for if (allowance != 0) revert
                if node.contains_if():
                    if "0" in str(node.expression):
                        has_zero_check = True
                        break

            if not has_zero_check:
                info = [
                    "ERC-20 approve() race condition vulnerability: ",
                    f"Function {approve.name} in {contract.name} does not require allowance to be zero before update.\n",
                    "  Location: ",
                    approve,
                    "\nAttacker can front-run the approval change to spend both old and new allowances.\n",
                    "Recommendation: Use increaseAllowance/decreaseAllowance or require(allowance == 0).\n",
                ]
                res = self.generate_result(info)
                results.append(res)

        return results
