import json
import os
import tempfile
import unittest
from pathlib import Path


class RecoveryStoreTests(unittest.TestCase):

    def _recovery(self):
        from recovery import RecoveryStore
        return RecoveryStore

    def test_completed_work_unit_survives_reload(self):
        RecoveryStore = self._recovery()

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "recovery.json"

            store = RecoveryStore(
                path=path,
                config_sha256="config-A",
                code_sha256="code-A",
            )

            store.mark_started(
                "job-001",
                {
                    "binary": "bin-a",
                    "seed_addr": 0x1234,
                },
            )

            store.mark_complete(
                "job-001",
                stats={
                    "n_runs": 1,
                    "visited_bb": 42,
                },
            )

            reloaded = RecoveryStore(
                path=path,
                config_sha256="config-A",
                code_sha256="code-A",
            )

            self.assertTrue(
                reloaded.is_complete("job-001")
            )

            self.assertEqual(
                reloaded.completed_stats("job-001"),
                {
                    "n_runs": 1,
                    "visited_bb": 42,
                },
            )

    def test_running_work_unit_is_retried_after_restart(self):
        RecoveryStore = self._recovery()

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "recovery.json"

            store = RecoveryStore(
                path=path,
                config_sha256="config-A",
                code_sha256="code-A",
            )

            store.mark_started(
                "job-crashed",
                {
                    "binary": "bin-a",
                },
            )

            reloaded = RecoveryStore(
                path=path,
                config_sha256="config-A",
                code_sha256="code-A",
            )

            self.assertFalse(
                reloaded.is_complete(
                    "job-crashed"
                )
            )

            self.assertEqual(
                reloaded.status(
                    "job-crashed"
                ),
                "interrupted",
            )

    def test_config_mismatch_refuses_resume(self):
        RecoveryStore = self._recovery()

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "recovery.json"

            RecoveryStore(
                path=path,
                config_sha256="config-A",
                code_sha256="code-A",
            )

            with self.assertRaises(
                ValueError
            ):
                RecoveryStore(
                    path=path,
                    config_sha256="config-B",
                    code_sha256="code-A",
                )

    def test_code_mismatch_refuses_resume(self):
        RecoveryStore = self._recovery()

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "recovery.json"

            RecoveryStore(
                path=path,
                config_sha256="config-A",
                code_sha256="code-A",
            )

            with self.assertRaises(
                ValueError
            ):
                RecoveryStore(
                    path=path,
                    config_sha256="config-A",
                    code_sha256="code-B",
                )

    def test_write_is_atomic_and_leaves_no_tmp_file(self):
        RecoveryStore = self._recovery()

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "recovery.json"

            store = RecoveryStore(
                path=path,
                config_sha256="config-A",
                code_sha256="code-A",
            )

            store.mark_started(
                "job-001",
                {},
            )

            store.mark_complete(
                "job-001",
            )

            self.assertTrue(
                path.is_file()
            )

            data = json.loads(
                path.read_text()
            )

            self.assertEqual(
                data["jobs"]["job-001"]["status"],
                "complete",
            )

            leftovers = list(
                Path(td).glob(
                    "recovery.json.*.tmp"
                )
            )

            self.assertEqual(
                leftovers,
                [],
            )

    def test_analysis_completion_is_persisted(self):
        RecoveryStore = self._recovery()

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "recovery.json"

            store = RecoveryStore(
                path=path,
                config_sha256="config-A",
                code_sha256="code-A",
            )

            self.assertFalse(
                store.analysis_complete
            )

            store.mark_analysis_complete()

            reloaded = RecoveryStore(
                path=path,
                config_sha256="config-A",
                code_sha256="code-A",
            )

            self.assertTrue(
                reloaded.analysis_complete
            )


if __name__ == "__main__":
    unittest.main()
