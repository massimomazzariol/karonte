import os
import sys
import tempfile
import unittest
from types import ModuleType
from unittest.mock import patch


extractor_module_name = "libraries.extractor.extractor"
previous_extractor_module = sys.modules.get(extractor_module_name)
previous_utils_module = sys.modules.get("utils")

extractor_stub = ModuleType(extractor_module_name)
extractor_stub.Extractor = object

if previous_extractor_module is None:
    sys.modules[extractor_module_name] = extractor_stub

import karonte as karonte_module
from karonte import Karonte
from loggers.file_logger import FileLogger

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


class TraceFileLogger:
    name = "trace.log"

    def __init__(self):
        self.events = []

    def start_logging(self):
        self.events.append(("start_logging",))

    def save_checkpoint(self, phase, status):
        self.events.append(
            ("checkpoint", phase, status)
        )

    def save_alert(self, *args, **kwargs):
        pass

    def save_stats(self, *args, **kwargs):
        pass

    def save_global_stats(self, *args, **kwargs):
        self.events.append(("stats",))

    def close_log(self):
        self.events.append(("close",))


class DummyBorderBinariesFinder:
    def __init__(self, *args, **kwargs):
        pass

    @staticmethod
    def get_network_keywords(end=None):
        return []

    def run(self, *args, **kwargs):
        raise AssertionError(
            "BBF should not run when border binaries are supplied"
        )


class EmptyBorderBinariesFinder:
    def __init__(self, *args, **kwargs):
        pass

    @staticmethod
    def get_network_keywords(end=None):
        return []

    def run(self, *args, **kwargs):
        return []


class DummyBinaryDependencyGraph:
    def __init__(self, *args, **kwargs):
        pass

    def run(self):
        pass


class DummyBugFinder:
    def __init__(self, *args, **kwargs):
        pass

    def run(self, *args, **kwargs):
        pass


class PersistentResultsLogTests(unittest.TestCase):
    def test_checkpoint_is_flushed_immediately(self):
        fd, path = tempfile.mkstemp(
            prefix="karonte-checkpoint-",
        )
        os.close(fd)

        logger = None

        try:
            logger = FileLogger(
                "/tmp/test-fw",
                path,
            )

            logger._start_time = 100.0

            with patch(
                "loggers.file_logger.time.time",
                return_value=112.345,
            ):
                logger.save_checkpoint(
                    "bug_finding",
                    "start",
                )

            with open(path, "r") as fp:
                persisted = fp.read()

            self.assertIn(
                "Checkpoint: bug_finding: start",
                persisted,
            )

            self.assertIn(
                "timestamp=112.345",
                persisted,
            )

            self.assertIn(
                "elapsed=12.345s",
                persisted,
            )

            self.assertTrue(
                persisted.endswith("\n"),
                "checkpoint must end with a real newline",
            )

            self.assertNotIn(
                "\\n",
                persisted,
                "checkpoint must not contain a literal backslash-n",
            )

        finally:
            if logger is not None:
                try:
                    logger.close_log()
                except Exception:
                    pass

            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def test_phase_checkpoints_wrap_analysis_and_finish_after_stats(self):
        karonte = object.__new__(Karonte)

        karonte._config = {}
        karonte._border_bins = [
            "/tmp/test-bin"
        ]
        karonte._fw_path = "/tmp/test-fw"
        karonte._klog = TraceFileLogger()
        karonte._add_stats = True

        old_log = karonte_module.log
        karonte_module.log = DummyLog()

        try:
            with patch.object(
                karonte_module,
                "BorderBinariesFinder",
                DummyBorderBinariesFinder,
            ), patch.object(
                karonte_module,
                "BinaryDependencyGraph",
                DummyBinaryDependencyGraph,
            ), patch.object(
                karonte_module,
                "BugFinder",
                DummyBugFinder,
            ):
                karonte.run()
        finally:
            karonte_module.log = old_log

        self.assertEqual(
            karonte._klog.events,
            [
                ("start_logging",),
                ("checkpoint", "analysis", "start"),
                (
                    "checkpoint",
                    "binary_dependency_graph",
                    "start",
                ),
                (
                    "checkpoint",
                    "binary_dependency_graph",
                    "complete",
                ),
                (
                    "checkpoint",
                    "bug_finding",
                    "start",
                ),
                (
                    "checkpoint",
                    "bug_finding",
                    "complete",
                ),
                ("stats",),
                ("checkpoint", "analysis", "complete"),
                ("close",),
            ],
        )

    def test_empty_border_binary_run_is_persistently_closed(self):
        karonte = object.__new__(Karonte)

        karonte._config = {}
        karonte._pickle_parsers = None
        karonte._border_bins = []
        karonte._fw_path = "/tmp/test-fw"
        karonte._klog = TraceFileLogger()
        karonte._add_stats = False

        old_log = karonte_module.log
        karonte_module.log = DummyLog()

        try:
            with patch.object(
                karonte_module,
                "BorderBinariesFinder",
                EmptyBorderBinariesFinder,
            ):
                karonte.run()
        finally:
            karonte_module.log = old_log

        self.assertEqual(
            karonte._klog.events,
            [
                ("start_logging",),
                ("checkpoint", "analysis", "start"),
                (
                    "checkpoint",
                    "border_binary_finder",
                    "start",
                ),
                (
                    "checkpoint",
                    "border_binary_finder",
                    "complete",
                ),
                ("checkpoint", "analysis", "complete"),
                ("close",),
            ],
        )


if __name__ == "__main__":
    unittest.main()
