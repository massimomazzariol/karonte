import sys
import unittest

import z3

from z3_compat import (
    _INT_STRING_CHUNK_SIZE,
    _int_to_decimal_unlimited,
    install_z3_int_compat,
)


class Z3LargeIntegerCompatTests(
        unittest.TestCase):

    def setUp(self):
        self.limit_getter = getattr(
            sys,
            "get_int_max_str_digits",
            None,
        )

        self.limit_before = (
            self.limit_getter()
            if self.limit_getter is not None
            else None
        )

        install_z3_int_compat()

    def test_large_positive_bitvec_value(self):
        bits = 32768
        value = (
            1 << bits
        ) - 1

        result = z3.BitVecVal(
            value,
            bits,
        )

        self.assertIsNotNone(
            result
        )

        self.assertEqual(
            result.size(),
            bits,
        )

    def test_large_negative_integer_value(self):
        value = -(
            (
                1 << 32768
            )
            - 1
        )

        result = z3.IntVal(
            value
        )

        self.assertIsNotNone(
            result
        )

    def test_python_global_limit_is_unchanged(self):
        if self.limit_getter is None:
            self.skipTest(
                "runtime has no int string limit"
            )

        self.assertEqual(
            self.limit_getter(),
            self.limit_before,
        )

    def test_installer_is_idempotent(self):
        before = (
            z3.z3._to_int_str
        )

        install_z3_int_compat()

        after = (
            z3.z3._to_int_str
        )

        self.assertIs(
            before,
            after,
        )

    def test_ordinary_conversion_semantics(self):
        self.assertEqual(
            z3.z3._to_int_str(123),
            "123",
        )

        self.assertEqual(
            z3.z3._to_int_str(True),
            "1",
        )

        self.assertEqual(
            z3.z3._to_int_str(False),
            "0",
        )

        self.assertEqual(
            z3.z3._to_int_str(1.9),
            "1",
        )

        self.assertEqual(
            _int_to_decimal_unlimited(
                -1234567890123456789
            ),
            "-1234567890123456789",
        )

    def test_limit_boundary_values_work(self):
        if self.limit_getter is None:
            self.skipTest(
                "runtime has no int string limit"
            )

        limit = self.limit_getter()

        if not limit:
            self.skipTest(
                "runtime integer guard disabled"
            )

        # Well below the guard: this must retain the ordinary Z3 path.
        small = (
            1
            << (
                limit * 3
                - 1
            )
        )

        small_z3 = z3.IntVal(
            small
        )

        self.assertIsNotNone(
            small_z3
        )

        # Guaranteed beyond the decimal guard.
        huge = (
            1
            << (
                limit * 4
            )
        )

        huge_z3 = z3.IntVal(
            huge
        )

        self.assertIsNotNone(
            huge_z3
        )

    def test_bugfinder_hash_handles_huge_concrete_leaf(self):
        import claripy

        from bf.bug_finder import BugFinder

        bits = 32768

        value = claripy.BVV(
            (
                1 << bits
            )
            - 1,
            bits,
        )

        result = BugFinder.bv_to_hash(
            value
        )

        self.assertIsInstance(
            result,
            str,
        )

    def test_chunk_size_tracks_python_guard(self):
        if self.limit_getter is None:
            self.assertIsNone(
                _INT_STRING_CHUNK_SIZE
            )

            return

        limit = self.limit_getter()

        if limit == 0:
            self.assertIsNone(
                _INT_STRING_CHUNK_SIZE
            )

        else:
            self.assertEqual(
                _INT_STRING_CHUNK_SIZE,
                limit,
            )


if __name__ == "__main__":
    unittest.main()
