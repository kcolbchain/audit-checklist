"""Custom Slither detector for unchecked low-level return values.

Detects: .call() without inspecting the return boolean.
"""
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import LowLevelCall

class CustomUncheckedReturnDetector(AbstractDetector):
    ARGUMENT = "custom-unchecked-return"
    HELP = "Detects unchecked low-level calls"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/kcolbchain/audit-checklist/wiki/Unchecked-Return-Detector"
    WIKI_TITLE = "Custom Unchecked Return Detector"

    def _detect(self) -> list:
        results = []
        for contract in self.compilation_unit.contracts:
            for function in contract.functions_and_modifiers:
                if not function.is_implemented:
                    continue

                for node in function.nodes:
                    for ir in node.irs:
                        if isinstance(ir, LowLevelCall):
                            is_unchecked = False
                            
                            # If there's no lvalue, the return was completely ignored.
                            if not ir.lvalue:
                                is_unchecked = True
                            else:
                                lvalue = ir.lvalue
                                is_read = False
                                
                                # Find all downstream nodes
                                downstream_nodes = function.nodes
                                
                                # Handle Slither's TupleVariable or standard tuples
                                bool_var = None
                                if hasattr(lvalue, "variables") and lvalue.variables:
                                    bool_var = lvalue.variables[0]
                                elif isinstance(lvalue, tuple) and len(lvalue) > 0:
                                    bool_var = lvalue[0]
                                else:
                                    bool_var = lvalue
                                
                                for n in downstream_nodes:
                                    if n != node and bool_var in n.variables_read:
                                        is_read = True
                                        break
                                            
                                if not is_read:
                                    is_unchecked = True

                            if is_unchecked:
                                info = [
                                    "Unchecked low-level call return value: ",
                                    f"  Call in {function.name}() at {node.source_mapping}\n",
                                    "\nConsider checking the success boolean return value.\n",
                                ]
                                res = self.generate_result(info)
                                res.add(node)
                                results.append(res)
        return results
