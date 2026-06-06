from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations.function import Function

class ERC20ApprovalRace(AbstractDetector):
    """
    Detects the ERC20 approval race condition vulnerability
    """

    ARGUMENT = "erc20-approval-race"
    HELP = "ERC20 approve race condition"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729"
    WIKI_TITLE = "ERC20 API: An Attack Vector on Approve/TransferFrom Methods"
    WIKI_DESCRIPTION = "The standard ERC20 approve method is vulnerable to a front-running attack."
    WIKI_EXPLOIT_SCENARIO = "Alice approves Bob for 100 tokens. Alice later decides to approve Bob for 50 tokens. Bob sees this transaction and front-runs it by spending the 100 tokens. Then Alice's 50 token approve transaction succeeds. Bob then spends the 50 tokens, stealing 150 tokens from Alice."
    WIKI_RECOMMENDATION = "Use increaseAllowance and decreaseAllowance instead of approve."

    def _detect(self):
        results = []

        for contract in self.compilation_unit.contracts_derived:
            has_approve = False
            has_increase = False
            has_decrease = False
            
            for function in contract.functions_declared:
                if function.name == "approve":
                    has_approve = True
                elif function.name == "increaseAllowance":
                    has_increase = True
                elif function.name == "decreaseAllowance":
                    has_decrease = True

            if has_approve and not (has_increase and has_decrease):
                info = [contract, " has approve() but lacks increaseAllowance()/decreaseAllowance(), making it vulnerable to the ERC20 approval race condition.\n"]
                res = self.generate_result(info)
                results.append(res)

        return results
