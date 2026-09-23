import json
import os
import tempfile
import time
from pathlib import Path


class RecoveryStore:
    """
    Persist logical analysis progress.

    This does not serialize angr execution states. Completed work units are
    recorded durably so they can be skipped after a restart, while a work
    unit that was still running is retried.
    """

    FORMAT_VERSION = 1

    def __init__(
            self,
            path,
            config_sha256,
            code_sha256):

        self._path = Path(path)
        self._config_sha256 = str(
            config_sha256
        )
        self._code_sha256 = str(
            code_sha256
        )

        if self._path.exists():
            self._data = self._load()
            self._validate_identity()
            self._recover_interrupted_jobs()
        else:
            self._data = {
                "version": self.FORMAT_VERSION,
                "config_sha256": self._config_sha256,
                "code_sha256": self._code_sha256,
                "analysis_complete": False,
                "analysis_completed_at": None,
                "jobs": {},
                "created_at": time.time(),
                "updated_at": None,
            }

            self._persist()

    @property
    def path(self):
        return self._path

    @property
    def analysis_complete(self):
        return bool(
            self._data.get(
                "analysis_complete",
                False,
            )
        )

    def _load(self):
        try:
            data = json.loads(
                self._path.read_text(
                    encoding="utf-8"
                )
            )
        except Exception as exc:
            raise ValueError(
                "Unable to read recovery state: %s"
                % exc
            )

        if not isinstance(data, dict):
            raise ValueError(
                "Recovery state must be a JSON object"
            )

        if data.get("version") != self.FORMAT_VERSION:
            raise ValueError(
                "Unsupported recovery format version: %r"
                % data.get("version")
            )

        if not isinstance(
                data.get("jobs"),
                dict):
            raise ValueError(
                "Recovery jobs field is invalid"
            )

        return data

    def _validate_identity(self):
        stored_config = self._data.get(
            "config_sha256"
        )

        stored_code = self._data.get(
            "code_sha256"
        )

        if stored_config != self._config_sha256:
            raise ValueError(
                "Recovery config fingerprint mismatch"
            )

        if stored_code != self._code_sha256:
            raise ValueError(
                "Recovery code fingerprint mismatch"
            )

    def _recover_interrupted_jobs(self):
        changed = False
        now = time.time()

        for job in self._data["jobs"].values():
            if job.get("status") != "running":
                continue

            job["status"] = "interrupted"
            job["interrupted_at"] = now
            changed = True

        if changed:
            self._persist()

    def _persist(self):
        self._path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._data["updated_at"] = time.time()

        fd = None
        tmp_path = None

        try:
            fd, tmp_name = tempfile.mkstemp(
                prefix=self._path.name + ".",
                suffix=".tmp",
                dir=str(self._path.parent),
            )

            tmp_path = Path(tmp_name)

            with os.fdopen(
                    fd,
                    "w",
                    encoding="utf-8") as fp:

                fd = None

                json.dump(
                    self._data,
                    fp,
                    indent=2,
                    sort_keys=True,
                )

                fp.write("\n")
                fp.flush()
                os.fsync(
                    fp.fileno()
                )

            os.replace(
                str(tmp_path),
                str(self._path),
            )

            tmp_path = None

            try:
                directory_fd = os.open(
                    str(self._path.parent),
                    getattr(
                        os,
                        "O_DIRECTORY",
                        0,
                    )
                )

                try:
                    os.fsync(
                        directory_fd
                    )
                finally:
                    os.close(
                        directory_fd
                    )

            except OSError:
                pass

        finally:
            if fd is not None:
                os.close(fd)

            if (
                tmp_path is not None
                and tmp_path.exists()
            ):
                tmp_path.unlink()

    def status(self, job_id):
        job = self._data["jobs"].get(
            str(job_id)
        )

        if job is None:
            return None

        return job.get("status")

    def is_complete(self, job_id):
        return (
            self.status(job_id)
            == "complete"
        )

    def completed_stats(self, job_id):
        job = self._data["jobs"].get(
            str(job_id)
        )

        if (
            job is None
            or job.get("status") != "complete"
        ):
            return None

        return job.get(
            "stats",
            {},
        )

    def mark_started(
            self,
            job_id,
            metadata=None):

        job_id = str(job_id)

        previous = self._data["jobs"].get(
            job_id,
            {},
        )

        if previous.get("status") == "complete":
            return False

        attempts = int(
            previous.get(
                "attempts",
                0,
            )
        ) + 1

        self._data["jobs"][job_id] = {
            "status": "running",
            "metadata": dict(
                metadata or {}
            ),
            "attempts": attempts,
            "started_at": time.time(),
            "interrupted_at": None,
            "completed_at": None,
            "stats": {},
        }

        self._persist()

        return True

    def mark_complete(
            self,
            job_id,
            stats=None):

        job_id = str(job_id)

        job = self._data["jobs"].setdefault(
            job_id,
            {
                "metadata": {},
                "attempts": 0,
                "started_at": None,
            },
        )

        job["status"] = "complete"
        job["completed_at"] = time.time()
        job["interrupted_at"] = None
        job["stats"] = dict(
            stats or {}
        )

        self._persist()

    def mark_analysis_complete(self):
        self._data["analysis_complete"] = True
        self._data["analysis_completed_at"] = time.time()

        self._persist()
