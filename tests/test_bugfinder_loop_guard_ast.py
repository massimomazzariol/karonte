import time
import unittest

from bf.bug_finder import BugFinder


class ExplodingTaintLeaf:
    def __init__(self):
        self.variables = {"taint_buf_loop_guard_32"}

    def __str__(self):
        raise ValueError(
            "Exceeds the limit (4300) for integer string conversion: "
            "synthetic loop-guard regression"
        )


class FakeGuard:
    def __init__(self, leaf):
        self.recursive_leaf_asts = [leaf]


class FakeHistory:
    def __init__(self, bbl_addrs=None, jump_guards=None):
        self.bbl_addrs = list(bbl_addrs or [])
        self.jump_guards = list(jump_guards or [])

    def trim(self):
        pass


class FakeState:
    def __init__(
        self,
        addr,
        bbl_addrs=None,
        jump_guards=None,
    ):
        self.addr = addr
        self.history = FakeHistory(
            bbl_addrs=bbl_addrs,
            jump_guards=jump_guards,
        )

    def downsize(self):
        pass

    def release_plugin(self, name):
        pass


class FakePath:
    def __init__(
        self,
        active,
        unconstrained=None,
        stepped_path=None,
    ):
        self.active = list(active)
        self.unconstrained = list(unconstrained or [])
        self._stepped_path = stepped_path

    def copy(self, deep=False):
        if not deep:
            raise AssertionError("BugFinder must request a deep copy")
        return self

    def step(self):
        if self._stepped_path is None:
            raise AssertionError("No stepped path configured")
        return self._stepped_path


class FakeCfgNode:
    def __init__(self, function_address):
        self.function_address = function_address


class FakeCfgModel:
    def __init__(self, addresses):
        self._nodes = {
            addr: FakeCfgNode(0x1000)
            for addr in addresses
        }

    def get_any_node(self, addr):
        return self._nodes.get(addr)


class FakeCfg:
    def __init__(self, addresses):
        self.model = FakeCfgModel(addresses)


class FakeFactory:
    def block(self, addr):
        return object()


class FakeProject:
    def __init__(self):
        self.factory = FakeFactory()


class FakeMainObject:
    binary = "/firmware/bin/example"


class FakeLoader:
    main_object = FakeMainObject()


class FakeCTProject:
    loader = FakeLoader()


class FakeCoreTaint:
    _taint_buf = "taint_buf"
    taint_applied = True
    p = FakeCTProject()

    def _contains_taint_marker(self, value):
        return any(
            self._taint_buf in name
            for name in getattr(value, "variables", ())
        )


class LoopGuardAstRegressionTests(unittest.TestCase):
    def test_loop_guard_taint_detection_does_not_stringify_leaf(self):
        leaf = ExplodingTaintLeaf()
        guard = FakeGuard(leaf)

        current_state = FakeState(
            addr=0x200,
            bbl_addrs=[
                0x100,
                0x200,
            ],
        )

        next_state_back = FakeState(
            addr=0x100,
            jump_guards=[guard],
        )

        next_state_forward = FakeState(
            addr=0x300,
            jump_guards=[guard],
        )

        next_path = FakePath(
            active=[
                next_state_back,
                next_state_forward,
            ],
        )

        current_path = FakePath(
            active=[current_state],
            stepped_path=next_path,
        )

        alerts = []

        bf = object.__new__(BugFinder)

        bf._ct = FakeCoreTaint()
        bf._current_cfg = FakeCfg(
            [
                0x100,
                0x200,
                0x300,
            ]
        )
        bf._current_p = FakeProject()
        bf._config = {}
        bf._current_role_info = {}
        bf._current_cpf_name = "regression"
        bf._analysis_starting_time = time.time()
        bf._visited_bb = 0
        bf._raised_alert = False

        bf._is_any_taint_var_bounded = (
            lambda guards_info: (False, None)
        )

        bf._is_sink_and_tainted = (
            lambda current_path, next_path: False
        )

        bf._report_alert_fun = (
            lambda *args, **kwargs: alerts.append(
                (args, kwargs)
            )
        )

        bf._check_sink(
            current_path,
            guards_info=[],
        )

        self.assertTrue(
            bf._raised_alert,
            "tainted loop guard should raise an alert",
        )

        self.assertEqual(
            len(alerts),
            1,
        )

        self.assertEqual(
            alerts[0][0][0],
            "loop",
        )


if __name__ == "__main__":
    unittest.main()
