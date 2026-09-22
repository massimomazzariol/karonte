import builtins
import importlib.util
from pathlib import Path
import types
import unittest
from unittest import mock


UTILS_PATH = Path(__file__).resolve().parents[1] / "tool" / "utils.py"


def load_utils_without_binwalk():
    real_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "binwalk":
            raise ModuleNotFoundError(
                "No module named 'binwalk'",
                name="binwalk",
            )
        return real_import(name, *args, **kwargs)

    spec = importlib.util.spec_from_file_location(
        "karonte_test_utils",
        str(UTILS_PATH),
    )
    module = importlib.util.module_from_spec(spec)

    with mock.patch(
        "builtins.__import__",
        side_effect=guarded_import,
    ):
        spec.loader.exec_module(module)

    return module


class FakeExtractor:
    instances = []

    def __init__(self, *args):
        self.args = args
        self.extract_called = False
        self.__class__.instances.append(self)

    def extract(self):
        self.extract_called = True


class OptionalBinwalkTests(unittest.TestCase):
    def setUp(self):
        FakeExtractor.instances = []

    def test_utils_import_does_not_require_binwalk(self):
        module = load_utils_without_binwalk()
        self.assertTrue(callable(module.unpack_firmware))

    def test_unpack_reports_missing_binwalk(self):
        module = load_utils_without_binwalk()
        real_import = builtins.__import__

        def guarded_import(name, *args, **kwargs):
            if name == "binwalk":
                raise ModuleNotFoundError(
                    "No module named 'binwalk'",
                    name="binwalk",
                )
            return real_import(name, *args, **kwargs)

        with mock.patch(
            "builtins.__import__",
            side_effect=guarded_import,
        ):
            with self.assertRaisesRegex(RuntimeError, "(?i)binwalk"):
                module.unpack_firmware("/tmp/fw.bin", "/tmp/fw-out")

    def test_unpack_still_invokes_extractor(self):
        module = load_utils_without_binwalk()
        real_import = builtins.__import__
        fake_module = types.SimpleNamespace(Extractor=FakeExtractor)

        def extractor_import(name, *args, **kwargs):
            if name == "libraries.extractor.extractor":
                return fake_module
            return real_import(name, *args, **kwargs)

        with mock.patch(
            "builtins.__import__",
            side_effect=extractor_import,
        ):
            result = module.unpack_firmware(
                "/tmp/fw.bin",
                "/tmp/fw-out",
            )

        self.assertEqual(result, "/tmp/fw-out")
        self.assertEqual(len(FakeExtractor.instances), 1)

        instance = FakeExtractor.instances[0]
        self.assertEqual(
            instance.args,
            (
                "/tmp/fw.bin",
                "/tmp/fw-out",
                True,
                False,
                False,
                False,
            ),
        )
        self.assertTrue(instance.extract_called)


if __name__ == "__main__":
    unittest.main()
