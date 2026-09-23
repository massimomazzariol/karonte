import os
import tempfile
import unittest
from unittest.mock import patch

import angr
import claripy

from taint_analysis.coretaint import CoreTaint


class NullLogger:
    def debug(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass


class UnconstrainedCallRecoveryTests(unittest.TestCase):
    CODE = bytes.fromhex(
        "33ff2fe1"
        "0000a0e1"
        "0110a0e1"
    )

    def _run_case(
        self,
        target_name,
        taint_returns,
        taint_arguments=False,
        tainted_argument=False,
        forced_arity=None,
    ):
        project = angr.load_shellcode(
            self.CODE,
            arch="ARMEL",
            load_address=0x1000,
        )

        # load_shellcode() creates a stream-backed Project whose
        # filename is None. Real Karonte analyses use file-backed
        # projects, and CoreTaint logs basename(project.filename).
        project.filename = "unconstrained-call-test.bin"

        fd, log_path = tempfile.mkstemp(
            prefix="karonte-coretaint-",
        )

        os.close(fd)

        ct = None

        try:
            ct = CoreTaint(
                project,
                interfunction_level=0,
                smart_call=True,
                follow_unsat=False,
                default_log=False,
                allow_untaint=False,
                taint_returns_unfollowed_calls=taint_returns,
                taint_arguments_unfollowed_calls=taint_arguments,
                logger_obj=NullLogger(),
                exit_on_decode_error=False,
            )

            state = project.factory.blank_state(
                addr=0x1000,
            )

            state.regs.r3 = claripy.BVS(
                target_name,
                project.arch.bits,
                explicit_name=True,
            )

            state.regs.lr = claripy.BVV(
                0x12345678,
                project.arch.bits,
            )

            if tainted_argument:
                state.regs.r0 = claripy.BVS(
                    "taint_buf_argument",
                    project.arch.bits,
                    explicit_name=True,
                )
            else:
                state.regs.r0 = claripy.BVV(
                    0x11111111,
                    project.arch.bits,
                )

            state.regs.r1 = claripy.BVV(
                0x22222222,
                project.arch.bits,
            )

            visited = []
            recovered = {}

            def check_path(
                current_path,
                guards_info,
                current_depth,
                **kwargs
            ):
                current_state = current_path.active[0]

                if current_state.ip.symbolic:
                    visited.append("symbolic")
                    return

                addr = current_state.solver.eval(
                    current_state.ip
                )

                visited.append(addr)

                if addr != 0x1004:
                    return

                recovered["jumpkind"] = (
                    current_state.history.jumpkind
                )

                recovered["lr"] = (
                    current_state.solver.eval(
                        current_state.regs.lr
                    )
                )

                recovered["return_symbolic"] = (
                    current_state.regs.r0.symbolic
                )

                recovered["return_variables"] = set(
                    current_state.regs.r0.variables
                )

                recovered["r1_variables"] = set(
                    current_state.regs.r1.variables
                )

                ct.stop_run()

            if forced_arity is None:
                ct.flat_explore(
                    state,
                    check_path,
                    [],
                )
            else:
                with patch(
                    "taint_analysis.coretaint.get_arity",
                    return_value=forced_arity,
                ):
                    ct.flat_explore(
                        state,
                        check_path,
                        [],
                    )

            return visited, recovered

        finally:
            if ct is not None:
                try:
                    ct._fp.close()
                except Exception:
                    pass

            try:
                os.unlink(log_path)
            except FileNotFoundError:
                pass

    def test_unconstrained_indirect_call_reaches_fake_return(self):
        visited, recovered = self._run_case(
            target_name="indirect_target",
            taint_returns=False,
        )

        self.assertIn(
            0x1000,
            visited,
        )

        self.assertIn(
            0x1004,
            visited,
            "unconstrained indirect call should continue "
            "through a synthetic fake-return state",
        )

        self.assertEqual(
            recovered["jumpkind"],
            "Ijk_FakeRet",
        )

        self.assertEqual(
            recovered["lr"],
            0x12345678,
            "fake return must restore the caller link register",
        )

        self.assertTrue(
            recovered["return_symbolic"],
            "unfollowed call should produce a fresh symbolic "
            "return value",
        )

    def test_tainted_unconstrained_target_taints_return_when_enabled(self):
        visited, recovered = self._run_case(
            target_name="taint_buf_indirect_target",
            taint_returns=True,
        )

        self.assertIn(
            0x1004,
            visited,
            "tainted unconstrained call should still recover "
            "to the instruction after the call",
        )

        self.assertTrue(
            recovered["return_symbolic"],
        )

        self.assertTrue(
            any(
                "taint_buf" in name
                for name in recovered["return_variables"]
            ),
            "taint_returns_unfollowed_calls should taint "
            "the synthetic return value",
        )


    def test_tainted_arguments_are_preserved_on_fake_return(self):
        visited, recovered = self._run_case(
            target_name="indirect_target",
            taint_returns=False,
            taint_arguments=True,
            tainted_argument=True,
            forced_arity=2,
        )

        self.assertIn(
            0x1004,
            visited,
            "taint_arguments_unfollowed_calls should recover "
            "through the synthetic fake return",
        )

        self.assertTrue(
            any(
                "taint_buf" in name
                for name in recovered["r1_variables"]
            ),
            "argument registers should be tainted when an "
            "unfollowed call consumes tainted input",
        )


if __name__ == "__main__":
    unittest.main()
