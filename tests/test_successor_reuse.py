import types
import unittest

from bf.bug_finder import BugFinder
from taint_analysis.coretaint import CoreTaint


class _Solver:
    @staticmethod
    def satisfiable():
        return True


class _History:
    def trim(self):
        pass


class _State:
    def __init__(self, addr=0x1000):
        self.addr = addr
        self.solver = _Solver()
        self.history = _History()

    def downsize(self):
        pass

    def release_plugin(self, *_):
        pass


class _Successor:
    def __init__(self):
        self.active = []
        self.unsat = []
        self.unconstrained = []
        self.errored = []
        self.deadended = [object()]


class _Copy:
    def __init__(
            self,
            owner,
            deep):
        self.owner = owner
        self.deep = deep

    def step(self, **kwargs):
        self.owner.step_count += 1

        self.owner.steps.append(
            (
                self.deep,
                kwargs,
            )
        )

        if (
            self.owner.fail_first_step
            and self.owner.step_count == 1
        ):
            raise RuntimeError(
                "candidate step failed"
            )

        return _Successor()


class _Path:
    def __init__(
            self,
            fail_first_step=False):
        self.active = [
            _State()
        ]

        self.copy_modes = []
        self.steps = []
        self.step_count = 0
        self.fail_first_step = (
            fail_first_step
        )

    def copy(self, deep=False):
        self.copy_modes.append(
            deep
        )

        return _Copy(
            self,
            deep,
        )


def _core():
    ct = CoreTaint.__new__(
        CoreTaint
    )

    ct._keep_run = True
    ct._timeout_triggered = False
    ct._try_thumb = False
    ct._force_paths = False
    ct._follow_unsat = False

    ct._p = types.SimpleNamespace(
        filename="/tmp/test-binary"
    )

    ct.get_addr = lambda _: 0x1000

    return ct


class SuccessorReuseCoreTaintTests(
        unittest.TestCase):

    def test_legacy_mode_keeps_single_normal_step(self):
        path = _Path()
        seen = []

        def check(*args, **kwargs):
            seen.append(
                kwargs
            )

        _core()._flat_explore(
            path,
            check,
            [],
            1,
        )

        self.assertEqual(
            path.copy_modes,
            [False],
        )

        self.assertNotIn(
            "_karonte_successor_path",
            seen[0],
        )

    def test_opt_in_reuses_normal_candidate_when_callback_approves(self):
        path = _Path()
        seen = []

        def check(
                *_,
                **kwargs):
            seen.append(
                kwargs[
                    "_karonte_successor_path"
                ]
            )

            return True

        _core()._flat_explore(
            path,
            check,
            [],
            1,
            reuse_check_func_successor=True,
        )

        self.assertEqual(
            path.copy_modes,
            [False],
        )

        self.assertEqual(
            len(seen),
            1,
        )

    def test_opt_in_resteps_when_callback_invalidates_candidate(self):
        path = _Path()

        def check(
                *_,
                **__):
            return False

        _core()._flat_explore(
            path,
            check,
            [],
            1,
            reuse_check_func_successor=True,
        )

        self.assertEqual(
            path.copy_modes,
            [
                False,
                False,
            ],
        )

    def test_candidate_failure_falls_back_to_legacy_step(self):
        path = _Path(
            fail_first_step=True
        )

        calls = []

        def check(
                *_,
                **kwargs):
            calls.append(
                kwargs
            )

        _core()._flat_explore(
            path,
            check,
            [],
            1,
            reuse_check_func_successor=True,
        )

        self.assertEqual(
            path.copy_modes,
            [
                False,
                False,
            ],
        )

        self.assertNotIn(
            "_karonte_successor_path",
            calls[0],
        )


class _BugFinderCurrentPath:
    def __init__(self):
        self.active = [
            types.SimpleNamespace(
                addr=0x1000,
            )
        ]

    def copy(self, **_):
        raise AssertionError(
            "BugFinder unexpectedly stepped current_path"
        )


class _BugFinderPreview:
    active = []
    unconstrained = []


class _BugFinderCT:
    def __init__(self):
        self.taint_applied = True
        self.untaints = 0

        self.p = types.SimpleNamespace(
            loader=types.SimpleNamespace(
                main_object=types.SimpleNamespace(
                    binary="test"
                )
            )
        )

    def do_recursive_untaint(
            self,
            *_):
        self.untaints += 1


def _bugfinder():
    bf = BugFinder.__new__(
        BugFinder
    )

    bf._visited_bb = 0
    bf._config = {}
    bf._current_role_info = {}
    bf._ct = _BugFinderCT()

    bf._current_cfg = (
        types.SimpleNamespace()
    )

    bf._current_p = types.SimpleNamespace(
        factory=types.SimpleNamespace(
            block=lambda _: types.SimpleNamespace(
                vex=types.SimpleNamespace(
                    jumpkind="Ijk_Boring"
                )
            )
        )
    )

    bf._analysis_starting_time = 0
    bf._raised_alert = False

    return bf


class BugFinderSuccessorReuseTests(
        unittest.TestCase):

    def test_bugfinder_accepts_read_only_candidate(self):
        bf = _bugfinder()

        bf._is_any_taint_var_bounded = (
            lambda _: (
                False,
                None,
            )
        )

        bf._jump_in_sink = (
            lambda *_: (
                False,
                None,
            )
        )

        reusable = bf._check_sink(
            _BugFinderCurrentPath(),
            [],
            _karonte_successor_path=(
                _BugFinderPreview()
            ),
        )

        self.assertIs(
            reusable,
            True,
        )

    def test_untaint_invalidates_candidate(self):
        bf = _bugfinder()

        marker = object()

        bf._is_any_taint_var_bounded = (
            lambda _: (
                True,
                marker,
            )
        )

        bf._jump_in_sink = (
            lambda *_: (
                False,
                None,
            )
        )

        reusable = bf._check_sink(
            _BugFinderCurrentPath(),
            [],
            _karonte_successor_path=(
                _BugFinderPreview()
            ),
        )

        self.assertIsNot(
            reusable,
            True,
        )

        self.assertEqual(
            bf._ct.untaints,
            1,
        )

    def test_sink_handler_invalidates_candidate_even_without_alert(self):
        bf = _bugfinder()

        bf._is_any_taint_var_bounded = (
            lambda _: (
                False,
                None,
            )
        )

        calls = []

        def sink_check(*_):
            calls.append(
                True
            )

            return False

        bf._jump_in_sink = (
            lambda *_: (
                True,
                sink_check,
            )
        )

        reusable = bf._check_sink(
            _BugFinderCurrentPath(),
            [],
            _karonte_successor_path=(
                _BugFinderPreview()
            ),
        )

        self.assertIsNot(
            reusable,
            True,
        )

        self.assertEqual(
            len(calls),
            1,
        )


if __name__ == "__main__":
    unittest.main()
