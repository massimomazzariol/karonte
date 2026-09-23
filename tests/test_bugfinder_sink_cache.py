import unittest
from types import SimpleNamespace
from unittest.mock import patch

import bf.bug_finder as bug_finder_module
from bf.bug_finder import BugFinder


class FakeProject:
    def __init__(self, binary):
        self.loader = SimpleNamespace(
            main_object=SimpleNamespace(
                binary=binary,
            )
        )


class BugFinderSinkCacheTests(unittest.TestCase):
    def _make_bugfinder(self):
        bf = object.__new__(BugFinder)

        bf._sink_addrs = []
        bf._sink_addrs_cache = {}

        return bf

    def test_repeated_sink_discovery_is_cached_per_binary(self):
        bf = self._make_bugfinder()

        project = FakeProject(
            "/tmp/example-bin"
        )

        bf._current_p = project

        dyn_calls = []
        memcpy_calls = []

        def fake_dyn_sym_addr(p, name):
            dyn_calls.append(
                (
                    p.loader.main_object.binary,
                    name,
                )
            )

            return {
                "strcpy": 0x1000,
                "memcpy": 0x2000,
            }.get(name)

        def fake_find_memcpy_like(p):
            memcpy_calls.append(
                p.loader.main_object.binary
            )

            return [
                0x3000,
                0x4000,
            ]

        fake_sinks = [
            (
                "strcpy",
                object(),
            ),
            (
                "memcpy",
                object(),
            ),
        ]

        with patch.object(
            bug_finder_module,
            "SINK_FUNCS",
            fake_sinks,
        ), patch.object(
            bug_finder_module,
            "get_dyn_sym_addr",
            side_effect=fake_dyn_sym_addr,
        ), patch.object(
            bug_finder_module,
            "find_memcpy_like",
            side_effect=fake_find_memcpy_like,
        ):
            bf._find_sink_addresses()

            first = list(
                bf._sink_addrs
            )

            bf._find_sink_addresses()

            second = list(
                bf._sink_addrs
            )

        self.assertEqual(
            first,
            second,
        )

        self.assertEqual(
            len(dyn_calls),
            len(fake_sinks),
            "dynamic sink lookup should run only once "
            "for the same binary",
        )

        self.assertEqual(
            memcpy_calls,
            [
                "/tmp/example-bin",
            ],
            "memcpy-like discovery should run only once "
            "for the same binary",
        )

    def test_sink_cache_is_separate_per_binary(self):
        bf = self._make_bugfinder()

        calls = []

        def fake_dyn_sym_addr(p, name):
            calls.append(
                (
                    "dyn",
                    p.loader.main_object.binary,
                    name,
                )
            )

            return 0x1000

        def fake_find_memcpy_like(p):
            calls.append(
                (
                    "memcpy",
                    p.loader.main_object.binary,
                )
            )

            return [
                0x2000,
            ]

        fake_sinks = [
            (
                "strcpy",
                object(),
            ),
        ]

        with patch.object(
            bug_finder_module,
            "SINK_FUNCS",
            fake_sinks,
        ), patch.object(
            bug_finder_module,
            "get_dyn_sym_addr",
            side_effect=fake_dyn_sym_addr,
        ), patch.object(
            bug_finder_module,
            "find_memcpy_like",
            side_effect=fake_find_memcpy_like,
        ):
            bf._current_p = FakeProject(
                "/tmp/bin-a"
            )

            bf._find_sink_addresses()

            a_sinks = list(
                bf._sink_addrs
            )

            bf._current_p = FakeProject(
                "/tmp/bin-b"
            )

            bf._find_sink_addresses()

            b_sinks = list(
                bf._sink_addrs
            )

            bf._current_p = FakeProject(
                "/tmp/bin-a"
            )

            bf._find_sink_addresses()

        self.assertEqual(
            a_sinks,
            bf._sink_addrs,
        )

        self.assertEqual(
            a_sinks,
            b_sinks,
        )

        memcpy_calls = [
            entry
            for entry in calls
            if entry[0] == "memcpy"
        ]

        self.assertEqual(
            memcpy_calls,
            [
                (
                    "memcpy",
                    "/tmp/bin-a",
                ),
                (
                    "memcpy",
                    "/tmp/bin-b",
                ),
            ],
        )


if __name__ == "__main__":
    unittest.main()
