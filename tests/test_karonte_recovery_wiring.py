import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch


extractor_module_name = (
    "libraries.extractor.extractor"
)

previous_extractor_module = sys.modules.get(
    extractor_module_name
)

extractor_stub = ModuleType(
    extractor_module_name
)

extractor_stub.Extractor = object

if previous_extractor_module is None:
    sys.modules[
        extractor_module_name
    ] = extractor_stub

import karonte as karonte_module
from karonte import Karonte

if previous_extractor_module is None:
    sys.modules.pop(
        extractor_module_name,
        None,
    )
else:
    sys.modules[
        extractor_module_name
    ] = previous_extractor_module


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

    def save_checkpoint(
            self,
            phase,
            status):
        pass

    def save_alert(
            self,
            *args,
            **kwargs):
        pass

    def save_stats(
            self,
            *args,
            **kwargs):
        pass

    def save_global_stats(
            self,
            *args,
            **kwargs):
        pass

    def close_log(self):
        pass


class DummyRecovery:
    def __init__(self):
        self.completed = 0

    def mark_analysis_complete(self):
        self.completed += 1


class DummyBBF:
    def __init__(
            self,
            *args,
            **kwargs):
        pass

    @staticmethod
    def get_network_keywords(
            end=None):
        return []


class ExistingBinsBBF(DummyBBF):
    def run(
            self,
            *args,
            **kwargs):
        raise AssertionError(
            "BBF must not run"
        )


class EmptyBBF(DummyBBF):
    def run(
            self,
            *args,
            **kwargs):
        return []


class DummyBDG:
    def __init__(
            self,
            *args,
            **kwargs):
        pass

    def run(self):
        pass


class CaptureBugFinder:
    received_recovery = None

    def __init__(
            self,
            *args,
            **kwargs):

        type(self).received_recovery = (
            kwargs.get(
                "recovery_store"
            )
        )

    def run(
            self,
            *args,
            **kwargs):
        pass


class KaronteRecoveryWiringTests(
        unittest.TestCase):

    def test_config_fingerprint_is_canonical(self):
        first = Karonte._config_sha256(
            {
                "b": 2,
                "a": 1,
            }
        )

        second = Karonte._config_sha256(
            {
                "a": 1,
                "b": 2,
            }
        )

        self.assertEqual(
            first,
            second,
        )

        self.assertEqual(
            len(first),
            64,
        )

    def test_code_fingerprint_is_stable(self):
        first = Karonte._code_sha256()
        second = Karonte._code_sha256()

        self.assertEqual(
            first,
            second,
        )

        self.assertEqual(
            len(first),
            64,
        )

    def test_prepare_recovery_detects_resume_and_completion(self):
        with tempfile.TemporaryDirectory() as td:
            log_path = str(
                Path(td)
                / "results.log"
            )

            first = object.__new__(
                Karonte
            )

            first._config = {
                "fw_path": "/firmware",
                "stats": "false",
            }

            with patch.object(
                Karonte,
                "_code_sha256",
                return_value="code-A",
            ):
                store, resuming, path = (
                    first._prepare_recovery(
                        log_path
                    )
                )

                self.assertFalse(
                    resuming
                )

                self.assertEqual(
                    path,
                    os.path.abspath(
                        log_path
                    )
                    + ".recovery.json",
                )

                second = object.__new__(
                    Karonte
                )

                second._config = dict(
                    first._config
                )

                (
                    second_store,
                    second_resuming,
                    second_path,
                ) = second._prepare_recovery(
                    log_path
                )

                self.assertTrue(
                    second_resuming
                )

                self.assertEqual(
                    second_path,
                    path,
                )

                second_store.mark_analysis_complete()

                third = object.__new__(
                    Karonte
                )

                third._config = dict(
                    first._config
                )

                with self.assertRaises(
                    ValueError
                ):
                    third._prepare_recovery(
                        log_path
                    )

    def test_prepare_recovery_rejects_changed_config(self):
        with tempfile.TemporaryDirectory() as td:
            log_path = str(
                Path(td)
                / "results.log"
            )

            first = object.__new__(
                Karonte
            )

            first._config = {
                "mode": "A",
            }

            second = object.__new__(
                Karonte
            )

            second._config = {
                "mode": "B",
            }

            with patch.object(
                Karonte,
                "_code_sha256",
                return_value="code-A",
            ):
                first._prepare_recovery(
                    log_path
                )

                with self.assertRaises(
                    ValueError
                ):
                    second._prepare_recovery(
                        log_path
                    )

    def test_run_passes_recovery_and_marks_completion(self):
        karonte = object.__new__(
            Karonte
        )

        recovery = DummyRecovery()

        karonte._config = {}
        karonte._border_bins = [
            "/tmp/bin"
        ]
        karonte._fw_path = "/tmp/fw"
        karonte._klog = DummyFileLogger()
        karonte._add_stats = False
        karonte._recovery_store = recovery
        karonte._resuming = False

        old_log = karonte_module.log
        karonte_module.log = DummyLog()

        CaptureBugFinder.received_recovery = None

        try:
            with patch.object(
                karonte_module,
                "BorderBinariesFinder",
                ExistingBinsBBF,
            ), patch.object(
                karonte_module,
                "BinaryDependencyGraph",
                DummyBDG,
            ), patch.object(
                karonte_module,
                "BugFinder",
                CaptureBugFinder,
            ):
                karonte.run()
        finally:
            karonte_module.log = old_log

        self.assertIs(
            CaptureBugFinder.received_recovery,
            recovery,
        )

        self.assertEqual(
            recovery.completed,
            1,
        )

    def test_empty_border_analysis_marks_completion(self):
        karonte = object.__new__(
            Karonte
        )

        recovery = DummyRecovery()

        karonte._config = {}
        karonte._pickle_parsers = None
        karonte._border_bins = []
        karonte._fw_path = "/tmp/fw"
        karonte._klog = DummyFileLogger()
        karonte._add_stats = False
        karonte._recovery_store = recovery
        karonte._resuming = False

        old_log = karonte_module.log
        karonte_module.log = DummyLog()

        try:
            with patch.object(
                karonte_module,
                "BorderBinariesFinder",
                EmptyBBF,
            ):
                karonte.run()
        finally:
            karonte_module.log = old_log

        self.assertEqual(
            recovery.completed,
            1,
        )


if __name__ == "__main__":
    unittest.main()
