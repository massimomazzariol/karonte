import unittest

import claripy

from taint_analysis.summary_functions import is_size_taint


class NoStringLeaf:
    def __init__(self, variables):
        self.variables = frozenset(variables)

    def __str__(self):
        raise AssertionError(
            "size-taint detection must not stringify AST leaves"
        )


class SizeTaintMarkerTests(unittest.TestCase):
    def test_size_marker_does_not_require_ast_stringification(self):
        value = NoStringLeaf(
            {"taint_buf__size___17_32"}
        )

        self.assertTrue(
            is_size_taint(value)
        )

    def test_real_claripy_variables_preserve_marker_semantics(self):
        plain = claripy.BVS(
            "ordinary_value",
            32,
            explicit_name=True,
        )

        size = claripy.BVS(
            "taint_buf__size___17_32",
            32,
            explicit_name=True,
        )

        concrete = claripy.BVV(
            0x12345678,
            32,
        )

        mixed = (
            size
            + plain
            + claripy.BVV(1, 32)
        )

        nested = claripy.If(
            claripy.BoolS(
                "condition",
                explicit_name=True,
            ),
            size,
            plain,
        )

        cases = [
            (plain, False),
            (size, True),
            (concrete, False),
            (mixed, True),
            (nested, True),
        ]

        for value, expected in cases:
            legacy = "__size__" in str(value)

            structural = any(
                "__size__" in name
                for name in value.variables
            )

            self.assertEqual(
                legacy,
                structural,
            )

            self.assertEqual(
                structural,
                expected,
            )


if __name__ == "__main__":
    unittest.main()
