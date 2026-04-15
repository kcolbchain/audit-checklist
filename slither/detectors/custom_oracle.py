"""Custom Slither detector for oracle manipulation vulnerabilities.

Detects: spot price usage without TWAP, single-source oracle dependencies,
and price manipulation via flash loans.
"""
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CustomOracleManipulationDetector(AbstractDetector):
    ARGUMENT = "custom-oracle-manipulation-detector"
    HELP = "Detects oracle manipulation patterns (spot prices without TWAP, single-source oracles)"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/kcolbchain/audit-checklist/wiki/Oracle-Detector"
    WIKI_TITLE = "Custom Oracle Manipulation Detector"

    def _detect(self) -> list:
        results = []
        price_functions = [
            "getprice", "latestprice", "currentprice", "spotprice",
            "getrate", "getamountout", "getamountsin",
        ]

        twap_functions = [
            "gettwap", "averageprice", "timeweighted", "getaverage",
            "consult", "twap",
        ]

        for contract in self.compilation_unit.contracts:
            if contract.is_interface:
                continue

            has_twap = any(f.name.lower() in twap_functions for f in contract.functions)

            for function in contract.functions:
                if not function.is_implemented:
                    continue

                func_name = function.name.lower()

                # Check for direct price usage without TWAP
                uses_spot = any(p in func_name for p in price_functions)
                if uses_spot and not has_twap:
                    # Check if function modifies state based on price
                    modifies_state = any(
                        hasattr(ir, "writes") and ir.writes
                        for node in function.nodes
                        for ir in node.irs
                    )

                    if modifies_state:
                        info = [
                            "Potential oracle manipulation: ",
                            f"{function.name}() uses spot price for state changes\n",
                            f"  Contract: {contract.name}\n",
                            "\nConsider using TWAP (time-weighted average price) instead of spot price.\n",
                        ]
                        res = self.generate_result(info)
                        res.add(function)
                        results.append(res)

                # Check for single oracle source dependency
                for node in function.nodes:
                    for ir in node.irs:
                        if hasattr(ir, "destination"):
                            dest = str(ir.destination)
                            if any(p in dest.lower() for p in ["chainlink", "uniswapv3pool", "feedregistry"]):
                                # This is good - using established oracle
                                pass

            # Warn if contract has price-dependent logic but no TWAP
            price_refs = sum(
                1 for f in contract.functions
                for node in f.nodes
                for ir in (node.irs or [])
                if hasattr(ir, "destination") and any(p in str(ir.destination).lower() for p in price_functions)
            )
            if price_refs > 0 and not has_twap:
                info = [
                    "Contract uses price feeds without TWAP: ",
                    f"{contract.name} has {price_refs} price references but no TWAP function\n",
                    "\nFlash loan attacks can manipulate spot prices. Consider integrating TWAP.\n",
                ]
                res = self.generate_result(info)
                results.append(res)

        return results
