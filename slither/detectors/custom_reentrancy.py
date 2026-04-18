"""Custom Slither detector for reentrancy patterns.

Detects: external calls before state updates (CEI violations),
callbacks without reentrancy guards, and receive/fallback functions
that make external calls.
"""
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.cfg.node import Node
from slither.analyses.data_dependency.data_dependency import is_dependent


class CustomReentrancyDetector(AbstractDetector):
    ARGUMENT = "custom-reentrancy-detector"
    HELP = "Detects reentrancy vulnerabilities (CEI violations, unprotected callbacks)"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/kcolbchain/audit-checklist/wiki/Reentrancy-Detector"
    WIKI_TITLE = "Custom Reentrancy Detector"

    def _detect(self) -> list:
        results = []
        for contract in self.compilation_unit.contracts:
            for function in contract.functions_and_modifiers:
                if not function.is_implemented:
                    continue

                external_calls = []
                state_writes_after = []

                for node in function.nodes:
                    for ir in node.irs:
                        # Find external calls
                        if hasattr(ir, "destination") and ir.destination:
                            if ir.destination != contract.address:
                                external_calls.append(node)
                        # Find state variable writes after external calls
                        if hasattr(ir, "writes") and ir.writes:
                            state_writes_after.append((node, ir.writes))

                # Check if any state writes happen after external calls in same function
                for call_node in external_calls:
                    for write_node, writes in state_writes_after:
                        if write_node.function == call_node.function:
                            # Check ordering: write happens after call
                            if self._node_after(write_node, call_node):
                                for write in writes:
                                    if isinstance(write, tuple):
                                        var = write[0]
                                    else:
                                        var = write
                                    info = [
                                        "CEI violation: ",
                                        "state write after external call\n",
                                        f"  External call in {function.name}() at {call_node.source_mapping}\n",
                                        f"  State write to {var.name} at {write_node.source_mapping}\n",
                                        "\nConsider using Checks-Effects-Interactions pattern or ReentrancyGuard.\n",
                                    ]
                                    res = self.generate_result(info)
                                    res.add(write_node)
                                    results.append(res)

                # Check receive/fallback for external calls (reentrancy via ETH transfer)
                if function.name in ("receive", "fallback", ""):
                    if function.is_payable and external_calls:
                        info = [
                            "Payable callback with external call: ",
                            f"{function.name or 'receive/fallback'}() makes external calls while being callable via ETH transfer\n",
                            f"  Contract: {contract.name}\n",
                            "\nEnsure reentrancy guard is in place.\n",
                        ]
                        res = self.generate_result(info)
                        for node in external_calls:
                            res.add(node)
                        results.append(res)

                # Check for missing reentrancy guard modifier
                if external_calls and state_writes_after:
                    has_guard = any(
                        "nonReentrant" in str(mod) or "reentrancyGuard" in str(mod)
                        for mod in function.modifiers
                    )
                    if not has_guard and function.visibility in ["public", "external"]:
                        info = [
                            "Function with external calls and state writes lacks reentrancy guard: ",
                            f"{function.name}() in {contract.name}\n",
                            "\nConsider adding a ReentrancyGuard modifier.\n",
                        ]
                        res = self.generate_result(info)
                        results.append(res)

        return results

    def _node_after(self, node_a, node_b) -> bool:
        """Check if node_a appears after node_b in control flow."""
        # Simple heuristic: compare node offsets
        try:
            return node_a.node_id > node_b.node_id
        except (AttributeError, TypeError):
            return False
