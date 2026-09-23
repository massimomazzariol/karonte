import hashlib
import json
import os
import sys
from pathlib import Path

from z3_compat import install_z3_int_compat

install_z3_int_compat()

import angr
import logging
from bdg.binary_dependency_graph import BinaryDependencyGraph
from bdg.cpfs import environment, semantic, file, socket, setter_getter
from bbf.border_binaries_finder import BorderBinariesFinder
from bf.bug_finder import BugFinder
from loggers.file_logger import FileLogger
from loggers.bar_logger import BarLogger
from recovery import RecoveryStore
from utils import *

angr.loggers.disable_root_logger()
angr.logging.disable(logging.ERROR)
log = None


class Karonte:
    @staticmethod
    def _config_sha256(config):
        encoded = json.dumps(
            config,
            sort_keys=True,
            separators=(
                ",",
                ":",
            ),
            ensure_ascii=True,
        ).encode(
            "utf-8"
        )

        return hashlib.sha256(
            encoded
        ).hexdigest()

    @staticmethod
    def _code_sha256():
        """
        Fingerprint the Python implementation actually being executed.

        This intentionally hashes source contents rather than a Git commit
        so local code changes also invalidate incompatible recovery state.
        """

        root = Path(
            __file__
        ).resolve().parent

        digest = hashlib.sha256()

        files = sorted(
            p
            for p in root.rglob(
                "*.py"
            )
            if (
                p.is_file()
                and "__pycache__"
                not in p.parts
            )
        )

        for path in files:
            relative = path.relative_to(
                root
            ).as_posix()

            digest.update(
                relative.encode(
                    "utf-8"
                )
            )

            digest.update(
                b"\0"
            )

            digest.update(
                path.read_bytes()
            )

            digest.update(
                b"\0"
            )

        return digest.hexdigest()

    def _prepare_recovery(
            self,
            log_path):

        recovery_path = (
            os.path.abspath(
                log_path
            )
            + ".recovery.json"
        )

        existed = os.path.isfile(
            recovery_path
        )

        config_sha256 = self._config_sha256(
            self._config
        )

        code_sha256 = self._code_sha256()

        store = RecoveryStore(
            path=recovery_path,
            config_sha256=config_sha256,
            code_sha256=code_sha256,
        )

        if (
            existed
            and store.analysis_complete
        ):
            raise ValueError(
                "Recovery state already belongs to a "
                "completed analysis: %s"
                % recovery_path
            )

        return (
            store,
            existed,
            recovery_path,
        )

    def _mark_recovery_complete(self):
        recovery = getattr(
            self,
            "_recovery_store",
            None,
        )

        if recovery is not None:
            recovery.mark_analysis_complete()

    def __init__(self, config_path, log_path=None):
        global log

        self._config = json.load(open(config_path))

        log_level = os.environ.get(
            "KARONTE_LOG_LEVEL",
            self._config.get(
                "log_level",
                "DEBUG",
            ),
        ).upper()

        if log_level not in {
            "DEBUG",
            "INFO",
            "WARNING",
            "ERROR",
        }:
            raise ValueError(
                "Invalid Karonte log level: %s"
                % log_level
            )

        log = BarLogger(
            "Karonte",
            log_level,
        )
        # remove empty keys from the config
        self._config = dict((k, v) for k, v in self._config.items() if v)
        self._pickle_parsers = self._config['pickle_parsers']
        self._border_bins = [str(x) for x in self._config['bin']] if 'bin' in self._config else []

        self._fw_path = self._config['fw_path']
        out_dir = os.path.join(FW_TMP_DIR, os.path.basename(self._fw_path))
        if os.path.isfile(self._fw_path) and not os.path.isdir(out_dir):
            owd = os.getcwd()
            log.info("Extracting firmware image. This may take a while...")
            self._fw_path = unpack_firmware(self._fw_path, FW_TMP_DIR)
            self._fw_path = out_dir
            # the extractor messes up the working directory. reset it
            os.chdir(owd)
        # when the image is already extracted before and the passed directory is not the extracted dir
        elif not os.path.isdir(self._fw_path) and os.path.isdir(out_dir):
            self._fw_path = out_dir

        if log_path is None:
            if 'log_path' in self._config and self._config['log_path']:
                log_path = self._config['log_path']
            else:
                log_path = DEFAULT_LOG_PATH

        (
            self._recovery_store,
            self._resuming,
            self._recovery_path,
        ) = self._prepare_recovery(
            log_path
        )

        self._klog = FileLogger(
            self._fw_path,
            log_path,
            append=self._resuming,
        )

        self._add_stats = (
            'true'
            == self._config['stats'].lower()
        )

        log.info(
            "Logging at: %s"
            % log_path
        )

        log.info(
            "Recovery state: %s"
            % self._recovery_path
        )

        if self._resuming:
            log.info(
                "Recovery state found: "
                "completed BugFinder work units "
                "will be skipped"
            )

        log.info(
            "Firmware directory: %s"
            % self._fw_path
        )

    def run(self, analyze_parents=True, analyze_children=True):
        """
        Runs Karonte
        :return:
        """

        self._klog.start_logging()

        if getattr(
                self,
                "_resuming",
                False):
            self._klog.save_checkpoint(
                "recovery",
                "resume",
            )

        self._klog.save_checkpoint(
            "analysis",
            "start",
        )

        bbf = BorderBinariesFinder(self._fw_path, use_connection_mark=False, logger_obj=log)

        log.info("Retrieving Border Binaries")
        if not self._border_bins:
            self._klog.save_checkpoint("border_binary_finder", "start")
            self._border_bins = bbf.run(pickle_file=self._pickle_parsers)
            self._klog.save_checkpoint("border_binary_finder", "complete")
            if not self._border_bins:
                log.error("No border binaries found, exiting...")
                log.info(f"Finished, results in {self._klog.name}")
                log.complete()
                self._klog.save_checkpoint(
                    "analysis",
                    "complete",
                )

                self._mark_recovery_complete()

                self._klog.close_log()
                return

        log.info("Generating Binary Dependency Graph")
        self._klog.save_checkpoint("binary_dependency_graph", "start")
        # starting the analysis with less strings makes the analysis faster
        pf_str = BorderBinariesFinder.get_network_keywords(end=N_TYPE_DATA_KEYS)
        cpfs = [environment.Environment, file.File, socket.Socket, setter_getter.SetterGetter, semantic.Semantic]
        bdg = BinaryDependencyGraph(self._config, self._border_bins, self._fw_path,
                                    init_data_keys=pf_str, cpfs=cpfs, logger_obj=log)
        bdg.run()
        self._klog.save_checkpoint("binary_dependency_graph", "complete")

        log.info("Discovering Bugs")
        self._klog.save_checkpoint("bug_finding", "start")
        bf = BugFinder(
            self._config,
            bdg,
            analyze_parents,
            analyze_children,
            logger_obj=log,
            recovery_store=getattr(
                self,
                "_recovery_store",
                None,
            ),
        )

        bf.run(
            report_alert=self._klog.save_alert,
            report_stats=(
                self._klog.save_stats
                if self._add_stats
                else None
            ),
        )
        self._klog.save_checkpoint("bug_finding", "complete")

        # Done.
        log.info(f"Finished, results in {self._klog.name}")
        log.complete()

        if self._add_stats:
            self._klog.save_global_stats(bbf, bdg, bf)

        self._klog.save_checkpoint(
            "analysis",
            "complete",
        )

        self._mark_recovery_complete()

        self._klog.close_log()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage " + sys.argv[0] + " config_path")
        sys.exit(0)

    config = sys.argv[1]
    log_file = sys.argv[2] if len(sys.argv) == 3 else DEFAULT_LOG_PATH
    so = Karonte(config, log_path=log_file)
    so.run()
