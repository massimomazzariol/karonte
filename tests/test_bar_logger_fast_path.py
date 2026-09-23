import unittest
from unittest.mock import Mock

from loggers.bar_logger import BarLogger


class BarLoggerFastPathTests(unittest.TestCase):

    def test_suppressed_debug_does_no_output_or_bar_refresh(self):
        logger = BarLogger(
            "test",
            "INFO",
        )

        logger._print_it = Mock()
        logger._update_bar = Mock()

        logger.debug(
            "hot-path debug message"
        )

        logger._print_it.assert_not_called()
        logger._update_bar.assert_not_called()

    def test_enabled_debug_still_emits_output(self):
        logger = BarLogger(
            "test",
            "DEBUG",
        )

        logger._print_it = Mock()
        logger._update_bar = Mock()

        logger.debug(
            "debug message"
        )

        logger._print_it.assert_called_once()
        logger._update_bar.assert_not_called()

    def test_suppressed_info_does_not_refresh_bar(self):
        logger = BarLogger(
            "test",
            "WARNING",
        )

        logger._print_it = Mock()
        logger._update_bar = Mock()

        logger.info(
            "suppressed info"
        )

        logger._print_it.assert_not_called()
        logger._update_bar.assert_not_called()


if __name__ == "__main__":
    unittest.main()
