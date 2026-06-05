import unittest
from slither import Slither

class ERC20ApprovalRaceDetectorTest(unittest.TestCase):
    def test_vulnerable_contract(self):
        slither = Slither("contracts/examples/VulnerableERC20.sol")
        detector = ERC20ApprovalRaceDetector()
        violations = detector.detect(slither.get_contracts()[0])
        self.assertGreater(len(violations), 0)

    def test_secure_contract(self):
        slither = Slither("contracts/examples/SecureERC20.sol")
        detector = ERC20ApprovalRaceDetector()
        violations = detector.detect(slither.get_contracts()[0])
        self.assertEqual(len(violations), 0)

if __name__ == "__main__":
    unittest.main()
