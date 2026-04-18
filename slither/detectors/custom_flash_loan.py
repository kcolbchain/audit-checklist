"""Custom Slither detector for flash loan vulnerabilities.

Detects: functions callable in a single transaction that read then write
based on external state (classic flash loan attack surface).
"""
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CustomFlashLoanDetector(AbstractDetector):
    ARGUMENT = "custom-flash-loan-detector"
    HELP = "Detects flash loan attack vectors (atomic read-write on external state)"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/kcolbchain/audit-checklist/wiki/Flash-Loan-Detector"
    WIKI_TITLE = "Custom Flash Loan Detector"

    def _detect(self) -> list:
        results = []
        flash_sensitive_ops = [
            "swap", "trade", "liquidate", "redeem", "repay",
            "auction", "settle", "execute", "flashloan", "flash",
        ]

        for contract in self.compilation_unit.contracts:
            if contract.is_interface:
                continue

            for function in contract.functions:
                if not function.is_implemented:
                    continue

                func_name = function.name.lower()
                is_sensitive = any(op in func_name for op in flash_sensitive_ops)

                if not is_sensitive:
                    continue

                # Check if function reads external state and writes state atomically
                reads_external = False
                writes_state = False

                for node in function.nodes:
                    for ir in node.irs:
                        if hasattr(ir, "reads") and ir.reads:
                            for var in ir.reads:
                                if hasattr(var, "contract") and var.contract != contract:
                                    reads_external = True
                        if hasattr(ir, "writes") and ir.writes:
                            writes_state = True

                if reads_external and writes_state:
                    info = [
                        "Flash loan attack surface: ",
                        f"{function.name}() in {contract.name}\n",
                        "  Reads external state and writes state atomically\n",
                        "\nConsider adding delay or using TWAP for external price reads.\n",
                    ]
                    res = self.generate_result(info)
                    res.add(function)
                    results.append(res)

        return results
