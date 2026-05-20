import importlib.util
import pathlib
import types
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
DETECTOR_PATH = ROOT / "slither" / "detectors" / "custom_upgrade_gap.py"

spec = importlib.util.spec_from_file_location("custom_upgrade_gap", DETECTOR_PATH)
custom_upgrade_gap = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(custom_upgrade_gap)


def variable(name, type_name="uint256"):
    return types.SimpleNamespace(
        name=name,
        type=type_name,
        is_constant=False,
        is_immutable=False,
    )


def contract(name, bases, state_variables):
    return types.SimpleNamespace(
        name=name,
        inheritance=[types.SimpleNamespace(name=base) for base in bases],
        state_variables_declared=state_variables,
        state_variables=state_variables,
        is_interface=False,
    )


class CustomUpgradeGapDetectorTest(unittest.TestCase):
    def test_flags_variable_declared_after_gap(self):
        candidate = contract(
            "BadUpgradeGap",
            ["UUPSUpgradeable"],
            [
                variable("existingValue"),
                variable("__gap", "uint256[50]"),
                variable("newFeeBps"),
            ],
        )

        violations = custom_upgrade_gap.find_gap_order_violations(candidate)

        self.assertEqual([item.name for item in violations], ["newFeeBps"])

    def test_ignores_variable_before_shrunken_gap(self):
        candidate = contract(
            "GoodUpgradeGap",
            ["UUPSUpgradeable"],
            [
                variable("existingValue"),
                variable("newFeeBps"),
                variable("__gap", "uint256[49]"),
            ],
        )

        self.assertEqual(custom_upgrade_gap.find_gap_order_violations(candidate), [])

    def test_ignores_non_upgradeable_contracts(self):
        candidate = contract(
            "PlainContract",
            [],
            [
                variable("__gap", "uint256[50]"),
                variable("newFeeBps"),
            ],
        )

        self.assertFalse(custom_upgrade_gap.is_upgradeable_contract(candidate))
        self.assertEqual(custom_upgrade_gap.find_gap_order_violations(candidate), [])


if __name__ == "__main__":
    unittest.main()
