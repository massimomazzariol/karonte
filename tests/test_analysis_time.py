import unittest

from bbf.border_binaries_finder import BorderBinariesFinder
from bdg.binary_dependency_graph import BinaryDependencyGraph
from bf.bug_finder import BugFinder


class AnalysisTimeTests(unittest.TestCase):
    def _check_timer(self, cls):
        obj = object.__new__(cls)

        obj._start_time = 100.0
        obj._end_time = 125.5

        self.assertEqual(
            obj.analysis_time(),
            25.5,
        )

        obj._start_time = None
        obj._end_time = 125.5

        self.assertEqual(
            obj.analysis_time(),
            0,
        )

        obj._start_time = 100.0
        obj._end_time = None

        self.assertEqual(
            obj.analysis_time(),
            0,
        )

        obj._start_time = None
        obj._end_time = None

        self.assertEqual(
            obj.analysis_time(),
            0,
        )

    def test_border_binary_finder_analysis_time(self):
        self._check_timer(
            BorderBinariesFinder
        )

    def test_binary_dependency_graph_analysis_time(self):
        self._check_timer(
            BinaryDependencyGraph
        )

    def test_bug_finder_analysis_time(self):
        self._check_timer(
            BugFinder
        )


if __name__ == "__main__":
    unittest.main()
