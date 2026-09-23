import tempfile
import unittest
from pathlib import Path

from loggers.file_logger import FileLogger


class FileLoggerResumeTests(unittest.TestCase):

    def test_resume_mode_appends_instead_of_truncating(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "results.log"

            path.write_text(
                "old-result\n"
            )

            logger = FileLogger(
                "/firmware",
                str(path),
                append=True,
            )

            logger.log_line(
                "new-result\n"
            )

            logger.close_log()

            self.assertEqual(
                path.read_text(),
                "old-result\nnew-result\n",
            )

    def test_normal_mode_still_starts_clean(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "results.log"

            path.write_text(
                "old-result\n"
            )

            logger = FileLogger(
                "/firmware",
                str(path),
                append=False,
            )

            logger.log_line(
                "fresh-result\n"
            )

            logger.close_log()

            self.assertEqual(
                path.read_text(),
                "fresh-result\n",
            )


if __name__ == "__main__":
    unittest.main()
