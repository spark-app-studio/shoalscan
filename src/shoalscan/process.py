"""Run a scanner binary: an allowlisted environment, its own process group, and a deadline.

A scanner that cannot start, times out or is killed by a signal is a failed
scan (ScanError), never an empty result.
"""

from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path

from shoalscan.errors import ScanError

ENV_ALLOWED = ("PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "USER", "LOGNAME", "TZ")


def scanner_env() -> dict[str, str]:
    """An allowlisted environment: nothing else reaches the scanner.

    Variables such as SEMGREP_RULES, GITLEAKS_CONFIG or proxy settings could
    change the rules, the output or the network behaviour, so only these
    pass: PATH, HOME, temporary directories, locale (LANG, LC_*), user name
    and time zone.
    """
    return {k: v for k, v in os.environ.items() if k in ENV_ALLOWED or k.startswith("LC_")}


def run_scanner(name: str, cmd: list[str], cwd: Path, timeout: int, stderr_chars: int = 2000) -> tuple[int, bytes, str]:
    """Run `cmd` and return its exit code, standard output and the last `stderr_chars` of its standard error."""
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            env=scanner_env(),
            start_new_session=True,
        )
    except OSError as exc:
        raise ScanError(f"{name} could not start: {exc}") from None
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            proc.kill()
        proc.communicate()
        raise ScanError(f"{name} timed out after {timeout}s") from None
    tail = stderr.decode("utf-8", errors="replace").strip()[-stderr_chars:]
    if proc.returncode < 0:
        raise ScanError(f"{name} was killed by signal {-proc.returncode}\n{tail}")
    return proc.returncode, stdout, tail
