import unittest

from taint_analysis.utils import (
    get_arguments_call_with_instruction_address,
    get_ord_arguments_call,
)


class FakePut:
    tag = "Ist_Put"

    def __init__(self, offset):
        self.offset = offset


class FakeIMark:
    tag = "Ist_IMark"

    def __init__(self, addr):
        self.addr = addr


class FakeVex:
    def __init__(self, statements):
        self.statements = statements


class FakeBlock:
    def __init__(self, statements):
        self.vex = FakeVex(statements)


class FakeFactory:
    def __init__(self, block):
        self._block = block

    def block(self, _addr):
        return self._block


class FakeArch:
    name = "ARMEL"

    def __init__(self):
        self.register_names = {
            8: "r0",
            12: "r1",
        }


class FakeProject:
    def __init__(self, statements):
        self.arch = FakeArch()
        self.factory = FakeFactory(FakeBlock(statements))


class ArgumentRegisterRegressionTests(unittest.TestCase):
    def test_ord_arguments_ignore_unmapped_put(self):
        unmapped = FakePut(132)
        r0 = FakePut(8)
        r1 = FakePut(12)

        project = FakeProject([
            unmapped,
            r0,
            r1,
        ])

        result = get_ord_arguments_call(project, 0x1000)

        self.assertEqual(result, [r0, r1])

    def test_argument_addresses_ignore_unmapped_put(self):
        unmapped = FakePut(132)
        r0 = FakePut(8)
        r1 = FakePut(12)

        project = FakeProject([
            FakeIMark(0x1000),
            unmapped,
            FakeIMark(0x1004),
            r0,
            FakeIMark(0x1008),
            r1,
        ])

        result = get_arguments_call_with_instruction_address(
            project,
            0x1000,
        )

        self.assertEqual(
            result,
            [
                (0x1004, r0),
                (0x1008, r1),
            ],
        )


if __name__ == "__main__":
    unittest.main()
