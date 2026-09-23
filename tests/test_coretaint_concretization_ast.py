import unittest

import claripy

from taint_analysis.coretaint import CoreTaint


class ExplodingConcreteLeaf:
    symbolic = False

    def __str__(self):
        raise AssertionError(
            "concrete leaf must not be stringified "
            "when no concretization key is needed"
        )


class FakeExpression:
    def __init__(self, leaf):
        self.recursive_leaf_asts = [leaf]


class FakeSolver:
    def __init__(self):
        self.solution_calls = 0
        self.eval_calls = 0

    def solution(self, var, value):
        self.solution_calls += 1
        return True

    def eval(self, var):
        self.eval_calls += 1
        return 0x1234


class FakeState:
    def __init__(self):
        self.solver = FakeSolver()
        self.constraints = []

    def copy(self):
        return FakeState()

    def add_constraints(self, *constraints):
        self.constraints.extend(constraints)


def make_coretaint():
    ct = object.__new__(CoreTaint)

    ct._concretizations = {}
    ct._taint_buf = "taint_buf"
    ct._allow_untaint = False

    strategy_calls = []

    def strategy(state, value):
        strategy_calls.append(value)
        return 7

    ct._concretization_strategy = strategy

    return ct, strategy_calls


class ConcretizationAstRegressionTests(unittest.TestCase):
    def test_concrete_leaf_does_not_require_concretization_key(self):
        ct, strategy_calls = make_coretaint()

        leaf = ExplodingConcreteLeaf()
        expression = FakeExpression(leaf)

        result = ct._get_target_concretization(
            expression,
            FakeState(),
        )

        self.assertEqual(result, 0x1234)
        self.assertEqual(strategy_calls, [])

    def test_real_large_bvv_stringification_is_safe_in_pinned_claripy(self):
        huge = claripy.BVV(
            (1 << 32768) - 1,
            32768,
        )

        rendered = str(huge)

        self.assertTrue(rendered)
        self.assertFalse(huge.symbolic)

    def test_symbolic_unique_id_normalization_keeps_cache_reuse(self):
        ct, strategy_calls = make_coretaint()

        first = claripy.BVS(
            "concretization_cache_regression",
            32,
        )

        second = claripy.BVS(
            "concretization_cache_regression",
            32,
        )

        self.assertNotEqual(
            first.args[0],
            second.args[0],
            "test requires Claripy to assign different unique IDs",
        )

        ct._get_target_concretization(
            first,
            FakeState(),
        )

        ct._get_target_concretization(
            second,
            FakeState(),
        )

        self.assertEqual(
            len(strategy_calls),
            1,
            "equivalent symbolic variables should reuse "
            "the normalized concretization cache entry",
        )


if __name__ == "__main__":
    unittest.main()
