import unittest
from types import SimpleNamespace

from bdg.binary_dependency_graph import BinaryDependencyGraph
from taint_analysis.coretaint import TimeOutException


class TimeoutCPF:
    name = "timeout-test"

    def run(self, *args, **kwargs):
        raise TimeOutException("Hard timeout triggered")


class BrokenCPF:
    name = "ordinary-error-test"

    def run(self, *args, **kwargs):
        raise ValueError("ordinary CPF failure")


class DummyCoreTaint:
    def stop_run(self):
        raise AssertionError("stop_run should not be called")


def make_bdg_with(plugin):
    bdg = object.__new__(BinaryDependencyGraph)
    bdg._f_arg_vals = [object()]
    bdg._set_f_vals = False
    bdg._current_bin = "test-bin"
    bdg._cpfs = {"test-bin": [plugin]}
    bdg._current_data_key = "test-key"
    bdg._current_key_addr = 0x1000
    bdg._current_par_name = "r0"
    bdg._core_taint = DummyCoreTaint()
    bdg._current_role = None
    bdg._cpf_used = None
    return bdg


class CPFTimeoutPropagationTests(unittest.TestCase):
    def test_timeout_exception_is_propagated(self):
        bdg = make_bdg_with(TimeoutCPF())

        with self.assertRaises(TimeOutException):
            bdg._check_key_usage(SimpleNamespace())

    def test_ordinary_cpf_exception_remains_nonfatal(self):
        bdg = make_bdg_with(BrokenCPF())

        result = bdg._check_key_usage(SimpleNamespace())

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
