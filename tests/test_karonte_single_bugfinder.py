import sys
import unittest
from types import ModuleType
from unittest.mock import patch

# Upstream master still imports the firmware extractor eagerly.
# Temporarily stub that unrelated dependency while importing Karonte,
# then restore the module state so other tests are not contaminated.
extractor_module_name = "libraries.extractor.extractor"
previous_extractor_module = sys.modules.get(extractor_module_name)
previous_utils_module = sys.modules.get("utils")

extractor_stub = ModuleType(extractor_module_name)
extractor_stub.Extractor = object

if previous_extractor_module is None:
    sys.modules[extractor_module_name] = extractor_stub

import karonte as karonte_module
from karonte import Karonte

if previous_extractor_module is None:
    sys.modules.pop(extractor_module_name, None)
else:
    sys.modules[extractor_module_name] = previous_extractor_module

if previous_utils_module is None:
    sys.modules.pop("utils", None)
else:
    sys.modules["utils"] = previous_utils_module


class DummyLog:
    def info(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass

    def complete(self):
        pass


class DummyFileLogger:
    name = "dummy.log"

    def start_logging(self):
        pass

    def save_checkpoint(self, phase, status):
        pass

    def save_alert(self, *args, **kwargs):
        pass

    def save_stats(self, *args, **kwargs):
        pass

    def save_global_stats(self, *args, **kwargs):
        pass

    def close_log(self):
        pass


class DummyBorderBinariesFinder:
    def __init__(self, *args, **kwargs):
        pass

    @staticmethod
    def get_network_keywords(end=None):
        return []

    def run(self, *args, **kwargs):
        raise AssertionError("BBF should not run when border binaries are supplied")


class DummyBinaryDependencyGraph:
    def __init__(self, *args, **kwargs):
        pass

    def run(self):
        pass


class CountingBugFinder:
    instances = 0
    runs = 0

    def __init__(self, *args, **kwargs):
        type(self).instances += 1

    def run(self, *args, **kwargs):
        type(self).runs += 1


class SingleBugFinderTests(unittest.TestCase):
    def test_karonte_runs_bugfinder_once(self):
        CountingBugFinder.instances = 0
        CountingBugFinder.runs = 0

        karonte = object.__new__(Karonte)
        karonte._config = {}
        karonte._border_bins = ["/tmp/test-bin"]
        karonte._fw_path = "/tmp/test-fw"
        karonte._klog = DummyFileLogger()
        karonte._add_stats = False

        old_log = karonte_module.log
        karonte_module.log = DummyLog()

        try:
            with patch.object(karonte_module, "BorderBinariesFinder", DummyBorderBinariesFinder):
                with patch.object(karonte_module, "BinaryDependencyGraph", DummyBinaryDependencyGraph):
                    with patch.object(karonte_module, "BugFinder", CountingBugFinder):
                        karonte.run()
        finally:
            karonte_module.log = old_log

        self.assertEqual(CountingBugFinder.instances, 1)
        self.assertEqual(CountingBugFinder.runs, 1)


if __name__ == "__main__":
    unittest.main()
