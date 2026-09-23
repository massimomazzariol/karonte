import unittest

import claripy

from taint_analysis.coretaint import CoreTaint


class ExplodingAst:
    def __init__(self, variables, length=32):
        self.variables = set(variables)
        self.length = length
        self.args = ()
        self.recursive_leaf_asts = [self]

    def __str__(self):
        raise ValueError(
            "Exceeds the limit (4300) for integer string conversion: "
            "synthetic regression"
        )


class LoadedValue:
    def __init__(self, *args):
        self.args = args
        self.length = sum(getattr(x, "length", 0) for x in args)


class FakeMemory:
    def __init__(self, value):
        self.value = value

    def load(self, addr, size):
        return self.value


class FakeState:
    def __init__(self, value):
        self.memory = FakeMemory(value)


def make_coretaint():
    ct = object.__new__(CoreTaint)
    ct._taint_buf = "taint_buf"
    ct._taint_buf_size = 4096
    ct._allow_untaint = False
    return ct


class AstStringificationTests(unittest.TestCase):
    def test_is_tainted_does_not_stringify_ast(self):
        ct = make_coretaint()
        ast = ExplodingAst({"taint_buf_1_32"})

        self.assertTrue(ct.is_tainted(ast))

    def test_non_tainted_ast_does_not_require_stringification(self):
        ct = make_coretaint()
        ast = ExplodingAst({"ordinary_symbol_1_32"})

        self.assertFalse(ct.is_tainted(ast))

    def test_buffer_size_detection_does_not_stringify_ast(self):
        ct = make_coretaint()

        leaf = ExplodingAst(
            {"taint_buf_2_32"},
            length=32,
        )

        loaded = LoadedValue(leaf)
        state = FakeState(loaded)

        size = ct.estimate_mem_buf_size(
            state,
            addr=0x1000,
            max_size=4096,
        )

        self.assertEqual(size, 32)

    def test_real_claripy_tainted_expression(self):
        ct = make_coretaint()

        tainted = claripy.BVS(
            "taint_buf_real_regression",
            32,
            explicit_name=True,
        )

        huge = claripy.BVV(
            (1 << 32768) - 1,
            32768,
        )

        expr = claripy.Concat(
            tainted,
            huge,
        )

        self.assertTrue(ct.is_tainted(expr))

    def test_real_claripy_untainted_expression(self):
        ct = make_coretaint()

        ordinary = claripy.BVS(
            "ordinary_real_regression",
            32,
            explicit_name=True,
        )

        huge = claripy.BVV(
            (1 << 32768) - 1,
            32768,
        )

        expr = claripy.Concat(
            ordinary,
            huge,
        )

        self.assertFalse(ct.is_tainted(expr))


if __name__ == "__main__":
    unittest.main()
