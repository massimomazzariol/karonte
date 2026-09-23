import inspect
import unittest
from types import MethodType, SimpleNamespace

from bdg.bdp_enum import Role, RoleInfo
from bf.bug_finder import BugFinder


def make_info(
        data_key="admin_password",
        caller=0x1000,
        xref=0x1100,
        role_fun=0x2000,
        par_n=1):

    return {
        RoleInfo.ROLE: Role.SETTER,
        RoleInfo.DATAKEY: data_key,
        RoleInfo.CPF: None,
        RoleInfo.X_REF_FUN: xref,
        RoleInfo.CALLER_BB: caller,
        RoleInfo.ROLE_FUN: role_fun,
        RoleInfo.ROLE_INS: 0x1010,
        RoleInfo.ROLE_INS_IDX: 3,
        RoleInfo.COMM_BUFF: None,
        RoleInfo.PAR_N: par_n,
    }


class FakeRecoveryStore:
    def __init__(self):
        self.jobs = {}
        self.started = []
        self.completed = []

    def is_complete(self, job_id):
        return (
            self.jobs.get(
                job_id,
                {},
            ).get("status")
            == "complete"
        )

    def completed_stats(self, job_id):
        return dict(
            self.jobs[
                job_id
            ].get(
                "stats",
                {},
            )
        )

    def mark_started(
            self,
            job_id,
            metadata=None):

        self.started.append(
            (
                job_id,
                dict(metadata or {}),
            )
        )

        previous = self.jobs.get(
            job_id,
            {},
        )

        attempts = (
            previous.get(
                "attempts",
                0,
            )
            + 1
        )

        self.jobs[job_id] = {
            "status": "running",
            "metadata": dict(
                metadata or {}
            ),
            "attempts": attempts,
        }

        return True

    def mark_complete(
            self,
            job_id,
            stats=None):

        self.completed.append(
            (
                job_id,
                dict(stats or {}),
            )
        )

        current = self.jobs.setdefault(
            job_id,
            {},
        )

        current["status"] = "complete"
        current["stats"] = dict(
            stats or {}
        )


class BugFinderRecoveryWorkUnitTests(
        unittest.TestCase):

    def make_bugfinder(
            self,
            recovery=None):

        bf = object.__new__(
            BugFinder
        )

        bf._recovery_store = recovery
        bf._stats = {}

        return bf

    def make_node(
            self,
            path="/firmware/usr/sbin/httpd"):

        return SimpleNamespace(
            bin=path,
        )

    def test_work_unit_id_is_deterministic(self):
        bf = self.make_bugfinder()

        node_a = self.make_node()
        node_b = self.make_node()

        info_a = make_info()

        # Same semantic data, different dict insertion order.
        info_b = dict(
            reversed(
                list(
                    make_info().items()
                )
            )
        )

        job_a = bf._work_unit_id(
            node_a,
            0x4000,
            info_a,
        )

        job_b = bf._work_unit_id(
            node_b,
            0x4000,
            info_b,
        )

        self.assertEqual(
            job_a,
            job_b,
        )

        self.assertEqual(
            len(job_a),
            64,
        )

    def test_different_callsite_gets_different_id(self):
        bf = self.make_bugfinder()
        node = self.make_node()

        first = bf._work_unit_id(
            node,
            0x4000,
            make_info(
                caller=0x1000,
            ),
        )

        second = bf._work_unit_id(
            node,
            0x4000,
            make_info(
                caller=0x1004,
            ),
        )

        self.assertNotEqual(
            first,
            second,
        )

    def test_completed_job_is_skipped_and_stats_restored(self):
        recovery = FakeRecoveryStore()
        bf = self.make_bugfinder(
            recovery
        )

        node = self.make_node()
        info = make_info()

        job_id = bf._work_unit_id(
            node,
            0x4000,
            info,
        )

        recovery.jobs[job_id] = {
            "status": "complete",
            "stats": {
                "n_paths": 7,
                "ana_time": 12.5,
                "visited_bb": 99,
                "n_runs": 1,
                "to": 1,
            },
        }

        calls = []

        def fake_vuln(
                self,
                bdg_node,
                seed_addr,
                role_info):

            calls.append(
                (
                    bdg_node,
                    seed_addr,
                    role_info,
                )
            )

        bf._vuln_analysis = MethodType(
            fake_vuln,
            bf,
        )

        executed = bf._run_work_unit(
            node,
            0x4000,
            info,
        )

        self.assertFalse(
            executed
        )

        self.assertEqual(
            calls,
            [],
        )

        self.assertEqual(
            bf._stats[node.bin],
            {
                "n_paths": 7,
                "ana_time": 12.5,
                "visited_bb": 99,
                "n_runs": 1,
                "to": 1,
            },
        )

    def test_new_job_is_saved_with_stats_delta(self):
        recovery = FakeRecoveryStore()

        bf = self.make_bugfinder(
            recovery
        )

        node = self.make_node()
        info = make_info()

        def fake_vuln(
                self,
                bdg_node,
                seed_addr,
                role_info):

            stats = self._stats.setdefault(
                bdg_node.bin,
                {
                    "n_paths": 0,
                    "ana_time": 0,
                    "visited_bb": 0,
                    "n_runs": 0,
                    "to": 0,
                },
            )

            stats["n_paths"] += 3
            stats["ana_time"] += 4.25
            stats["visited_bb"] += 50
            stats["n_runs"] += 1

        bf._vuln_analysis = MethodType(
            fake_vuln,
            bf,
        )

        executed = bf._run_work_unit(
            node,
            0x4000,
            info,
        )

        self.assertTrue(
            executed
        )

        self.assertEqual(
            len(recovery.started),
            1,
        )

        self.assertEqual(
            len(recovery.completed),
            1,
        )

        _, saved_stats = recovery.completed[0]

        self.assertEqual(
            saved_stats,
            {
                "n_paths": 3,
                "ana_time": 4.25,
                "visited_bb": 50,
                "n_runs": 1,
                "to": 0,
            },
        )

    def test_interrupted_job_runs_again(self):
        recovery = FakeRecoveryStore()

        bf = self.make_bugfinder(
            recovery
        )

        node = self.make_node()
        info = make_info()

        job_id = bf._work_unit_id(
            node,
            0x4000,
            info,
        )

        recovery.jobs[job_id] = {
            "status": "interrupted",
            "stats": {},
            "attempts": 1,
        }

        calls = []

        def fake_vuln(
                self,
                bdg_node,
                seed_addr,
                role_info):

            calls.append(
                seed_addr
            )

            stats = self._stats.setdefault(
                bdg_node.bin,
                {
                    "n_paths": 0,
                    "ana_time": 0,
                    "visited_bb": 0,
                    "n_runs": 0,
                    "to": 0,
                },
            )

            stats["n_runs"] += 1

        bf._vuln_analysis = MethodType(
            fake_vuln,
            bf,
        )

        executed = bf._run_work_unit(
            node,
            0x4000,
            info,
        )

        self.assertTrue(
            executed
        )

        self.assertEqual(
            calls,
            [
                0x4000,
            ],
        )

        self.assertEqual(
            recovery.jobs[job_id]["status"],
            "complete",
        )

        self.assertEqual(
            recovery.jobs[job_id]["attempts"],
            2,
        )

    def test_no_recovery_preserves_legacy_execution(self):
        bf = self.make_bugfinder(
            None
        )

        node = self.make_node()
        info = make_info()

        calls = []

        def fake_vuln(
                self,
                bdg_node,
                seed_addr,
                role_info):

            calls.append(
                (
                    bdg_node.bin,
                    seed_addr,
                    role_info[RoleInfo.DATAKEY],
                )
            )

        bf._vuln_analysis = MethodType(
            fake_vuln,
            bf,
        )

        executed = bf._run_work_unit(
            node,
            0x4000,
            info,
        )

        self.assertTrue(
            executed
        )

        self.assertEqual(
            calls,
            [
                (
                    node.bin,
                    0x4000,
                    "admin_password",
                ),
            ],
        )

    def test_completed_stats_are_restored_only_once(self):
        recovery = FakeRecoveryStore()

        bf = self.make_bugfinder(
            recovery
        )

        node = self.make_node()
        info = make_info()

        job_id = bf._work_unit_id(
            node,
            0x4000,
            info,
        )

        recovery.jobs[job_id] = {
            "status": "complete",
            "stats": {
                "n_paths": 2,
                "ana_time": 3.0,
                "visited_bb": 20,
                "n_runs": 1,
                "to": 0,
            },
        }

        first = bf._run_work_unit(
            node,
            0x4000,
            info,
        )

        second = bf._run_work_unit(
            node,
            0x4000,
            info,
        )

        self.assertFalse(first)
        self.assertFalse(second)

        self.assertEqual(
            bf._stats[node.bin],
            {
                "n_paths": 2,
                "ana_time": 3.0,
                "visited_bb": 20,
                "n_runs": 1,
                "to": 0,
            },
        )

    def test_analyze_routes_jobs_through_recovery_wrapper(self):
        source = inspect.getsource(
            BugFinder._analyze
        )

        self.assertIn(
            "self._run_work_unit(",
            source,
        )

        self.assertNotIn(
            "self._vuln_analysis(",
            source,
        )


if __name__ == "__main__":
    unittest.main()
