import unittest
from slither.core import Contract
from slither.detectors.custom_unchecked_low_level_call import CustomUncheckedLowLevelCallDetector

class CustomUncheckedLowLevelCallDetectorTest(unittest.TestCase):

    def test_detects_unchecked_low_level_call(self):
        contract = Contract("TestContract")
        function = contract.add_function("testFunction")
        node = function.add_node("    address(0x123).call();")
        detector = CustomUncheckedLowLevelCallDetector()
        results = detector.detect(contract)
        self.assertEqual(len(results), 1)

    def test_ignores_checked_low_level_call(self):
        contract = Contract("TestContract")
        function = contract.add_function("testFunction")
        node = function.add_node("    bool success = address(0x123).call();")
        detector = CustomUncheckedLowLevelCallDetector()
        results = detector.detect(contract)
        self.assertEqual(len(results), 0)

if __name__ == "__main__":
    unittest.main()
