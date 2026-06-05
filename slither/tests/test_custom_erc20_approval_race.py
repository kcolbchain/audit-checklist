import importlib.util
import pathlib
import types
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
DETECTOR_PATH = ROOT / "slither" / "detectors" / "custom_erc20_approval_race.py"

spec = importlib.util.spec_from_file_location("custom_erc20_approval_race", DETECTOR_PATH)
custom_erc20_approval_race = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(custom_erc20_approval_race)


def ir_writing(name):
    return types.SimpleNamespace(writes=[types.SimpleNamespace(name=name)])


def node(text, writes=None):
    return types.SimpleNamespace(irs=writes or [], __str__=lambda self: text)


class TextNode:
    def __init__(self, text, writes=None):
        self.text = text
        self.irs = writes or []

    def __str__(self):
        return self.text


def function(name, nodes):
    return types.SimpleNamespace(
        name=name,
        parameters=[types.SimpleNamespace(name="spender"), types.SimpleNamespace(name="amount")],
        nodes=nodes,
        is_implemented=True,
    )


def contract(functions):
    return types.SimpleNamespace(
        name="Token",
        functions=functions,
        is_interface=False,
    )


class CustomERC20ApprovalRaceDetectorTest(unittest.TestCase):
    def test_flags_approve_that_writes_allowance_without_guard(self):
        approve = function("approve", [TextNode("allowance[msg.sender][spender] = amount", [ir_writing("allowance")])])

        findings = custom_erc20_approval_race.find_approval_race_functions(contract([approve]))

        self.assertEqual(findings, [approve])

    def test_ignores_approve_with_zero_guard(self):
        approve = function(
            "approve",
            [
                TextNode("require(current == 0 || amount == 0)"),
                TextNode("allowance[msg.sender][spender] = amount", [ir_writing("allowance")]),
            ],
        )

        self.assertEqual(custom_erc20_approval_race.find_approval_race_functions(contract([approve])), [])

    def test_ignores_non_approve_function(self):
        transfer = function("transferFrom", [TextNode("allowance[from][msg.sender] -= amount", [ir_writing("allowance")])])

        self.assertEqual(custom_erc20_approval_race.find_approval_race_functions(contract([transfer])), [])


if __name__ == "__main__":
    unittest.main()
