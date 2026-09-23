import unittest
from types import SimpleNamespace
from unittest.mock import patch

import claripy

from bdg.bdp_enum import Role
from bdg.cpfs.semantic import Semantic


class StructuralAst:
    def __init__(self, identity):
        self.identity = identity

    def structurally_match(self, other):
        return (
            isinstance(other, StructuralAst)
            and self.identity == other.identity
        )

    def __str__(self):
        raise AssertionError(
            "semantic AST comparison must not stringify buffers"
        )


class Destination:
    def __init__(self, name, concrete=False, value=None):
        self.name = name
        self.concrete = concrete
        self.args = () if value is None else (value,)


class FakeMemory:
    def __init__(
        self,
        tainted_dst,
        global_dst,
        copied_dst,
        copied_source,
    ):
        self._tainted_dst = tainted_dst
        self._global_dst = global_dst
        self._copied_dst = copied_dst
        self._copied_source = copied_source

    def load(self, address, size):
        if address is self._tainted_dst:
            return StructuralAst("tainted-buffer")

        if address is self._global_dst:
            return StructuralAst("global-buffer")

        if address is self._copied_dst:
            return StructuralAst("copied-buffer")

        if address == self._copied_source:
            return StructuralAst("copied-buffer")

        raise AssertionError(
            "unexpected memory load: %r" % (address,)
        )


class FakeCoreTaint:
    def __init__(self, tainted_dst):
        self._tainted_dst = tainted_dst

    def is_or_points_to_tainted_data(
        self,
        value,
        path,
    ):
        return value is self._tainted_dst


class DebugLog:
    def __init__(self):
        self.messages = []

    def debug(self, message):
        self.messages.append(message)


class SemanticAstComparisonTests(unittest.TestCase):
    def _make_semantic_case(self):
        current_addr = 0x4000
        role_function = 0x3000
        caller_block = 0x1000
        copied_source = 0x9000

        tainted_dst = Destination(
            "tainted",
            concrete=False,
        )

        global_dst = Destination(
            "global",
            concrete=True,
            value=0x5000,
        )

        copied_dst = Destination(
            "copied",
            concrete=False,
        )

        memory = FakeMemory(
            tainted_dst,
            global_dst,
            copied_dst,
            copied_source,
        )

        current_state = SimpleNamespace(
            addr=current_addr,
            memory=memory,
            history=SimpleNamespace(
                bbl_addrs=[
                    caller_block,
                    role_function,
                    current_addr,
                ]
            ),
        )

        next_state = SimpleNamespace(
            regs=SimpleNamespace(
                r0=tainted_dst,
                r1=global_dst,
                r2=copied_dst,
            )
        )

        current_path = SimpleNamespace(
            active=[current_state]
        )

        next_path = SimpleNamespace(
            active=[next_state]
        )

        block = SimpleNamespace(
            vex=SimpleNamespace(
                jumpkind="Ijk_Call",
                statements=[],
            )
        )

        successor = SimpleNamespace(
            addr=0x2000,
            name="sprintf",
            successors=[],
        )

        current_node = SimpleNamespace(
            addr=current_addr,
            function_address=role_function,
            successors=[successor],
        )

        caller_node = SimpleNamespace(
            addr=caller_block,
            function_address=caller_block,
            successors=[],
        )

        class Model:
            def get_any_node(self, address):
                if address == current_addr:
                    return current_node

                if address == caller_block:
                    return caller_node

                raise AssertionError(
                    "unexpected CFG lookup: %#x" % address
                )

        section = SimpleNamespace(
            name=".bss",
            min_addr=0x4F00,
            max_addr=0x5100,
        )

        project = SimpleNamespace(
            arch=SimpleNamespace(
                bytes=4,
            ),
            factory=SimpleNamespace(
                block=lambda address: block,
            ),
            loader=SimpleNamespace(
                find_plt_stub_name=lambda address: "sprintf",
                main_object=SimpleNamespace(
                    sections=[section],
                ),
            ),
        )

        semantic = object.__new__(Semantic)
        semantic._p = project
        semantic._cfg = SimpleNamespace(
            model=Model()
        )
        semantic._role_info = {}
        semantic._name = "semantic"
        semantic._log = DebugLog()

        core_taint = FakeCoreTaint(
            tainted_dst
        )

        return (
            semantic,
            current_path,
            next_path,
            core_taint,
            copied_source,
        )

    def test_global_setter_buffer_match_does_not_stringify_ast(self):
        (
            semantic,
            current_path,
            next_path,
            core_taint,
            copied_source,
        ) = self._make_semantic_case()

        with patch(
            "bdg.cpfs.semantic.get_arity",
            return_value=3,
        ), patch(
            "bdg.cpfs.semantic.arg_reg_name",
            side_effect=lambda project, index: "r%d" % index,
        ), patch(
            "bdg.cpfs.semantic.arg_reg_id",
            return_value=0,
        ):
            matched, role = semantic._glbl_data_key_setter(
                current_path=current_path,
                data_key="data-key",
                key_addr=0x7777,
                core_taint=core_taint,
                reg_name="r0",
                par_vals=[copied_source],
                next_path=next_path,
            )

        self.assertTrue(
            matched,
            "structurally identical copied buffers should "
            "be recognized without converting ASTs to strings",
        )

        self.assertEqual(
            role,
            Role.SETTER,
        )

    def test_real_claripy_structural_match_agrees_with_legacy_equality(self):
        x = claripy.BVS(
            "semantic_regression_x",
            32,
            explicit_name=True,
        )

        same_x = claripy.BVS(
            "semantic_regression_x",
            32,
            explicit_name=True,
        )

        y = claripy.BVS(
            "semantic_regression_y",
            32,
            explicit_name=True,
        )

        cases = [
            (
                x,
                same_x,
            ),
            (
                x,
                y,
            ),
            (
                x + claripy.BVV(1, 32),
                same_x + claripy.BVV(1, 32),
            ),
            (
                x + claripy.BVV(1, 32),
                same_x + claripy.BVV(2, 32),
            ),
            (
                claripy.Concat(
                    x,
                    claripy.BVV(0x1234, 32),
                ),
                claripy.Concat(
                    same_x,
                    claripy.BVV(0x1234, 32),
                ),
            ),
        ]

        for left, right in cases:
            self.assertEqual(
                str(left) == str(right),
                left.structurally_match(right),
            )


if __name__ == "__main__":
    unittest.main()
