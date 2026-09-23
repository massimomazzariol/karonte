import inspect
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import bf.bug_finder as bug_finder_module
from bf.bug_finder import BugFinder
from taint_analysis import summary_functions
from taint_analysis.coretaint import CoreTaint


class DummyLog:
    def info(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def debug(self, *args, **kwargs):
        pass


class SafeValue:
    concrete = False
    symbolic = True
    op = "BVS"
    length = 64
    variables = frozenset()

    def __init__(self):
        self.args = ("not_a_seed_address",)

    def __str__(self):
        return "safe-symbolic-value"


class ExplodingStringValue(SafeValue):
    def __str__(self):
        raise ValueError(
            "symbolic AST must not be stringified"
        )


class ExplodingSymbolicName:
    concrete = False
    symbolic = True
    op = "BVS"
    length = 32
    variables = frozenset()
    args = ("env_key_123_32",)

    def __str__(self):
        raise ValueError(
            "symbolic AST must not be stringified"
        )

    def hash(self):
        return 0x12345678


class ExplodingEnvAst:
    concrete = False
    symbolic = True
    op = "BVS"
    length = 32
    variables = frozenset()
    args = ("environment_key_0_32",)

    def __str__(self):
        raise ValueError(
            "environment AST must not be stringified"
        )

    def hash(self):
        return 0xABCDEF


class FakeCoreTaint:
    def __init__(self):
        self.safe_load_calls = []
        self.apply_sizes = []

        self.loaded = SimpleNamespace(
            length=64,
        )

    def safe_load(
        self,
        current_path,
        addr,
        size=None,
        unconstrained=False,
        estimate_size=False,
    ):
        self.safe_load_calls.append(
            (
                size,
                estimate_size,
            )
        )

        return self.loaded

    def apply_taint(
        self,
        current_path,
        addr,
        taint_id,
        bit_size=None,
    ):
        self.apply_sizes.append(
            bit_size
        )

        return self.loaded


class FakeState:
    def __init__(self, value):
        self.regs = SimpleNamespace(
            r0=value,
        )

        self.constraints = []

    def add_constraints(self, constraint):
        self.constraints.append(
            constraint
        )


class RealFirmwareRegressionTests(unittest.TestCase):
    def _run_apply_taint(
        self,
        value,
        data_key_reg,
    ):
        project = SimpleNamespace(
            arch=SimpleNamespace(
                register_names={
                    4: "r0",
                },
            ),
            loader=SimpleNamespace(
                main_object=SimpleNamespace(
                    min_addr=0,
                ),
            ),
        )

        current_state = FakeState(
            value
        )

        current_path = SimpleNamespace(
            active=[
                current_state,
            ],
        )

        next_state = FakeState(
            value
        )

        core = FakeCoreTaint()

        bug_finder = object.__new__(
            BugFinder
        )

        bug_finder._current_p = project
        bug_finder._current_seed_addr = 0x123456
        bug_finder._ct = core

        stmt = SimpleNamespace(
            offset=4,
        )

        with patch.object(
            bug_finder_module,
            "get_ord_arguments_call",
            return_value=[
                stmt,
            ],
        ), patch.object(
            bug_finder_module,
            "get_any_arguments_call",
            return_value=[],
        ), patch.object(
            bug_finder_module,
            "are_parameters_in_registers",
            return_value=True,
        ), patch.object(
            bug_finder_module,
            "log",
            DummyLog(),
        ):
            bug_finder._apply_taint(
                0x1000,
                current_path,
                next_state,
                taint_key=True,
                data_key_reg=data_key_reg,
            )

        return core

    def test_data_key_without_known_size_uses_estimation(self):
        core = self._run_apply_taint(
            SafeValue(),
            "r0",
        )

        self.assertEqual(
            core.safe_load_calls,
            [
                (
                    None,
                    True,
                ),
            ],
        )

        self.assertEqual(
            core.apply_sizes,
            [
                64,
            ],
        )

    def test_apply_taint_logging_does_not_stringify_ast(self):
        core = self._run_apply_taint(
            ExplodingStringValue(),
            None,
        )

        self.assertEqual(
            core.apply_sizes,
            [
                None,
            ],
        )

    def test_environment_key_does_not_stringify_ast(self):
        self.assertTrue(
            hasattr(
                summary_functions,
                "_env_var_key",
            ),
            "environment summaries need a structural key helper",
        )

        value = ExplodingEnvAst()

        key = summary_functions._env_var_key(
            value
        )

        self.assertEqual(
            key,
            (
                "claripy",
                0xABCDEF,
            ),
        )

        setenv_source = inspect.getsource(
            summary_functions._setenv
        )
        getenv_source = inspect.getsource(
            summary_functions._getenv
        )

        self.assertIn(
            "_env_var_key(",
            setenv_source,
        )
        self.assertIn(
            "_env_var_key(",
            getenv_source,
        )
        self.assertNotIn(
            "str(key)",
            setenv_source,
        )
        self.assertNotIn(
            "str(reg)",
            getenv_source,
        )

    def test_concretization_key_does_not_stringify_symbolic_ast(self):
        self.assertTrue(
            hasattr(
                CoreTaint,
                "_get_concretization_key",
            ),
            "CoreTaint needs a non-stringifying concretization key",
        )

        core = object.__new__(
            CoreTaint
        )

        core._taint_buf = "taint_buf"

        key = core._get_concretization_key(
            ExplodingSymbolicName()
        )

        self.assertEqual(
            key,
            "env_key_32",
        )


if __name__ == "__main__":
    unittest.main()
