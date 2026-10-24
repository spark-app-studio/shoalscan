"""Starting scans from the dashboard: single flight, cooldowns, a global cap, and a detached worker.

The web server never scans in-process and keeps its read-only database
connection. To start a scan it spawns one worker process,
`python -m shoalscan.scanjob --target=NAME`, with a fixed argument list, no
shell, a new session, an allowlisted environment and its output going to a
bounded log in the state directory. The worker reads the registered targets
again for itself; the request contributes nothing but the target's name.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import shoalscan
from shoalscan import history
from shoalscan.dashboard import scanning, users
from shoalscan.errors import SetupError

ENV_ALLOW = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "USER",
    "LOGNAME",
    "SSL_CERT_FILE",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_CONFIG_HOME",
)


class ScanControl:
    def __init__(self, state_dir: Path, db: Path):
        self.state_dir = state_dir
        self.db = db
        self._lock = threading.Lock()
        self._worker: subprocess.Popen | None = None
        targets = self.targets()  # refuse to start with an invalid file
        if targets is not None:
            self.check_database(targets)

    def targets(self) -> scanning.Targets | None:
        return scanning.load_targets(self.state_dir)

    def check_database(self, targets: scanning.Targets) -> None:
        """The worker must record into the database this dashboard shows."""
        worker_db = targets.history_db or history.default_db_path()
        if worker_db.resolve() != self.db.resolve():
            raise SetupError(
                f"scan_targets.toml records scans into {worker_db}, but this dashboard serves {self.db}; "
                "set history_db in scan_targets.toml to the database you serve"
            )

    # ------------------------------------------------------------ state

    def _reap(self) -> None:
        if self._worker is not None and self._worker.poll() is not None:
            self._worker = None

    def running(self) -> bool:
        self._reap()
        return self._worker is not None or scanning.lock_holder(self.state_dir) is not None

    def _requests(self) -> dict:
        return scanning.read_requests(self.state_dir)

    def cooldown_remaining(self, targets: scanning.Targets, name: str, requests: dict | None = None) -> int:
        return scanning.cooldown_wait(targets, name, requests or self._requests())

    def global_remaining(self, targets: scanning.Targets, requests: dict | None = None) -> int:
        return scanning.hourly_wait(targets, requests or self._requests())

    def status(self, read_triggers) -> dict:
        """What runs or last ran. `running` is decided first and the status file and
        audit are read after it, so a scan that ends in between is never shown as
        idle with a half-written status."""
        running = self.running()
        targets = self.targets()
        current = scanning.read_json(self.state_dir / scanning.STATUS_FILE)
        current = (
            {k: current.get(k) for k in ("target", "started", "finished", "outcome", "run_id")} if current else None
        )
        clone = None
        if current and targets and current.get("target") in targets.targets:
            clone = targets.clone_dir(targets.targets[current["target"]])
        requests = self._requests()
        git_ok = scanning.git_attr_probe()
        return {
            "git_ok": git_ok,
            "git_error": None if git_ok else scanning.GIT_TOO_OLD,
            "running": running,
            "current": current,
            "log": scanning.log_tail(self.state_dir, clone),
            "global_remaining": self.global_remaining(targets, requests) if targets else 0,
            "targets": [
                {
                    "name": t.name,
                    "branch": t.branch,
                    "enabled": t.enabled,
                    "cooldown_remaining": self.cooldown_remaining(targets, t.name, requests),
                }
                for t in (targets.targets.values() if targets else [])
            ],
            "triggers": read_triggers(),
        }

    # ------------------------------------------------------------ starting a scan

    def start(
        self, name: object, read_triggers, trigger: str = "dashboard", run_id: int | None = None, who: str | None = None
    ) -> tuple[int, dict]:
        """Validate the request and spawn the worker. Returns an HTTP status and a JSON body.

        `trigger` is "dashboard" (a fresh scan), "rescan" (the branch's tip
        again) or "rescan-commit" (the commit of `run_id`, which the caller has
        checked belongs to this repository)."""
        if trigger not in ("dashboard", "rescan", "rescan-commit") or (trigger == "rescan-commit") != (
            run_id is not None
        ):
            return 400, {"error": "invalid scan request"}
        if not scanning.valid_name(name):
            return 400, {"error": "invalid target name"}
        targets = self.targets()
        if targets is None:
            return 404, {"error": "scans are not enabled"}
        target = targets.targets.get(name)
        if target is None:
            return 404, {"error": "no such scan target"}
        if not target.enabled:
            return 409, {"error": "this target is disabled"}
        if not scanning.git_attr_probe():
            return 503, {"error": scanning.GIT_TOO_OLD}
        with self._lock:
            if self.running():
                return 409, {"error": "a scan is already running", "status": self.status(read_triggers)}
            requests = self._requests()
            wait = self.cooldown_remaining(targets, name, requests)
            if wait:
                return 429, {
                    "error": f"this target was scanned recently; try again in {wait} seconds",
                    "retry_after": wait,
                }
            wait = self.global_remaining(targets, requests)
            if wait:
                return 429, {
                    "error": (
                        f"the hourly limit of {targets.max_scans_per_hour} scans is reached; try again in {wait} "
                        "seconds"
                    ),
                    "retry_after": wait,
                }
            self._spawn(target.name, trigger, run_id, who)
            now = time.time()
            requests["targets"][target.name] = now
            requests["recent"].append(now)
            scanning.write_requests(self.state_dir, requests)
        return 202, {"started": target.name, "status": self.status(read_triggers)}

    def _spawn(self, name: str, trigger: str = "dashboard", run_id: int | None = None, who: str | None = None) -> None:
        env = {k: os.environ[k] for k in ENV_ALLOW if k in os.environ}
        env.setdefault("PATH", "/usr/bin:/bin")
        # The worker imports this same Shoalscan, wherever it is installed.
        env["PYTHONPATH"] = str(Path(shoalscan.__file__).resolve().parents[1])
        # -P and a neutral working directory: nothing in the state directory can be imported as a module.
        argv = [
            sys.executable,
            "-P",
            "-m",
            "shoalscan.scanjob",
            "--state-dir",
            str(self.state_dir),
            "--trigger",
            trigger,
            f"--target={name}",
        ]
        if run_id is not None:
            argv.append(f"--run-id={int(run_id)}")
        if who is not None:
            # The person who asked, for the audit; checked again by the worker.
            argv.append(f"--who={users.normalise_email(who)}")
        log_path = self.state_dir / scanning.LOG_FILE
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            self._worker = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=fd,
                stderr=fd,
                env=env,
                cwd="/",
                start_new_session=True,
                close_fds=True,
            )
        finally:
            os.close(fd)
