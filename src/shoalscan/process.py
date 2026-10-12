"""Run a scanner binary: an allowlisted environment, its own process group, and a deadline.

A scanner that cannot start, times out, is killed by a signal or writes more
than it is allowed to is a failed scan (ScanError), never an empty result.

Every run gets an empty home directory of its own (mode 0700, removed when
the run ends), so nothing in the real home directory (SSH keys, git
credential helpers, cloud credentials, tool configuration) can reach a
scanner. Git is told to read no system or global configuration and to allow
no transport at all, and every proxy variable points at a closed local port,
so a scanner that tries to fetch something (Trivy downloads remote Terraform
modules, and cannot be told not to) fails instead. Where the operating
system offers it, the scanner also runs without network access: under
`sandbox-exec` on macOS, or in a new network namespace (`unshare --net`) on
Linux. When neither works, Shoalscan says so once and relies on the
environment alone.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from shoalscan.errors import ScanError

ENV_ALLOWED = ("PATH", "LANG", "LC_ALL", "USER", "LOGNAME", "TZ")
# A closed port on the loopback interface: anything sent through a proxy fails at once.
CLOSED_PROXY = "http://127.0.0.1:9"
_PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
DEFAULT_MAX_STDOUT = 16 * 1024 * 1024
DEFAULT_MAX_STDERR = 16 * 1024 * 1024
_CHUNK = 64 * 1024

# macOS: everything is allowed except IP networking and DNS (which goes through mDNSResponder's socket).
_MACOS_PROFILE = (
    "(version 1)(allow default)"
    "(deny network-outbound (remote ip))(deny network-inbound (local ip))(deny network-bind (local ip))"
    '(deny network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))'
)
_TRUE = next((p for p in ("/usr/bin/true", "/bin/true") if os.path.isfile(p)), "true")
_sandbox: tuple[tuple[str, ...], str] | None = None
_sandbox_lock = threading.Lock()


def scanner_env(home: Path) -> dict[str, str]:
    """An allowlisted environment: nothing else reaches the scanner.

    Variables such as SEMGREP_RULES, GITLEAKS_CONFIG, cloud credentials or
    proxy settings could change the rules, the output or the network
    behaviour, so only these pass: PATH, the locale (LANG, LC_*), the user
    name and the time zone. HOME and the temporary directory are the run's
    own empty directory. Git reads no configuration and allows no transport,
    the proxies point at a closed port, and the cloud metadata services are
    turned off.
    """
    env = {k: v for k, v in os.environ.items() if k in ENV_ALLOWED or k.startswith("LC_")}
    tmp = str(home / "tmp")
    env.update(
        {
            "HOME": str(home),
            "TMPDIR": tmp,
            "TMP": tmp,
            "TEMP": tmp,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_SSH_COMMAND": "false",
            "AWS_EC2_METADATA_DISABLED": "true",
            "GCE_METADATA_HOST": "127.0.0.1:9",
            "NO_PROXY": "",
            "no_proxy": "",
        }
    )
    env.update({name: CLOSED_PROXY for name in _PROXY_VARS})
    return env


def _works(prefix: tuple[str, ...]) -> bool:
    try:
        proc = subprocess.run(
            [*prefix, _TRUE],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin"},
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def _candidates() -> list[tuple[tuple[str, ...], str]]:
    if sys.platform == "darwin" and os.path.isfile("/usr/bin/sandbox-exec"):
        return [(("/usr/bin/sandbox-exec", "-p", _MACOS_PROFILE), "sandbox-exec")]
    if sys.platform.startswith("linux"):
        unshare = next((p for p in ("/usr/bin/unshare", "/bin/unshare") if os.path.isfile(p)), None)
        if unshare:
            return [
                ((unshare, "--net", "--map-current-user", "--"), "unshare --net"),
                ((unshare, "--net", "--map-root-user", "--"), "unshare --net"),
            ]
    return []


def network_sandbox() -> tuple[tuple[str, ...], str]:
    """The command prefix that cuts a scanner off the network, and what it is.

    Worked out once per process: the first candidate that can run `true`.
    Without one, the prefix is empty, the name is "environment only", and a
    warning is printed once.
    """
    global _sandbox
    with _sandbox_lock:
        if _sandbox is None:
            found = next(((p, n) for p, n in _candidates() if _works(p)), None)
            if found is None:
                _sandbox = ((), "environment only")
                print(
                    "shoalscan: WARNING: no operating-system network sandbox is available here (sandbox-exec on "
                    "macOS, unshare --net with user namespaces on Linux), so scanners are kept off the network by "
                    "their environment only. See docs/security-model.md.",
                    file=sys.stderr,
                )
            else:
                _sandbox = found
        return _sandbox


# A line of a code frame, as Rust and Haskell tools print them: `  12 |   the code`.
_CODE_FRAME = re.compile(r"^\s*\d*\s*[|\u2502]")
# Quoted text, or a quote that is never closed and so runs to the end of its line.
# An apostrophe inside a word (can't) does not open a quote.
_QUOTED = re.compile(r"(?<![A-Za-z])'[^'\n]*'|\"[^\"\n]*\"|`[^`\n]*`|((?<![A-Za-z])'|[\"`])[^\n]*")


def error_summary(text: str, limit: int = 1000) -> str:
    """A scanner's error text, safe to keep in errors, logs and the history.

    Scanners quote the file they could not read in their errors, and that
    file is the scanned repository's. Lines of a code frame (`12 | code`)
    are dropped, quoted text is replaced with `...`, and only the last
    `limit` characters are kept. What went wrong, and where, is left.
    """
    lines = [line for line in text.splitlines() if not _CODE_FRAME.match(line)]
    text = _QUOTED.sub(
        lambda m: m.group(1) + "..." if m.group(1) else f"{m.group(0)[0]}...{m.group(0)[0]}", "\n".join(lines)
    )
    text = text.strip()
    return text[-limit:]


class _Reader(threading.Thread):
    """Reads one pipe to its end, keeping at most `cap` bytes; past that, calls `overflow` and stops.

    The reader owns its pipe and closes it when it stops, so no other thread
    ever closes a descriptor this one may still be reading."""

    def __init__(self, stream, cap: int, overflow) -> None:
        super().__init__(daemon=True)
        self.stream, self.cap, self.overflow = stream, cap, overflow
        self.chunks: list[bytes] = []
        self.size = 0
        self.exceeded = False

    def run(self) -> None:
        try:
            fd = self.stream.fileno()
            while True:
                try:
                    block = os.read(fd, _CHUNK)
                except OSError:
                    break
                if not block:
                    break
                self.size += len(block)
                if self.size > self.cap:
                    self.exceeded = True
                    self.overflow()
                    break
                self.chunks.append(block)
        finally:
            self.stream.close()

    def data(self) -> bytes:
        return b"".join(self.chunks)


def _kill(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        try:
            proc.kill()
        except OSError:
            pass


def run_scanner(
    name: str,
    cmd: list[str],
    cwd: Path,
    timeout: int,
    max_stdout: int = DEFAULT_MAX_STDOUT,
    max_stderr: int = DEFAULT_MAX_STDERR,
) -> tuple[int, bytes, str]:
    """Run `cmd` and return its exit code, its standard output and its standard error.

    Both streams are read as the scanner writes them; one that grows past its
    cap kills the scanner, and the scan fails.
    """
    home = Path(tempfile.mkdtemp(prefix="shoalscan-home-"))
    try:
        (home / "tmp").mkdir(mode=0o700)
        prefix, _ = network_sandbox()
        try:
            proc = subprocess.Popen(
                [*prefix, *cmd],
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                env=scanner_env(home),
                start_new_session=True,
            )
        except OSError as exc:
            raise ScanError(f"{name} could not start: {exc}") from None
        readers = [
            _Reader(proc.stdout, max_stdout, lambda: _kill(proc)),
            _Reader(proc.stderr, max_stderr, lambda: _kill(proc)),
        ]
        for reader in readers:
            reader.start()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill(proc)
            proc.wait()
            for reader in readers:
                reader.join(timeout=10)
            raise ScanError(f"{name} timed out after {timeout}s") from None
        for reader in readers:
            # A child that left the process group may still hold a pipe open. Its reader is
            # left to finish on its own (it closes its pipe then); the scan fails.
            reader.join(timeout=10)
            if reader.is_alive():
                _kill(proc)
                raise ScanError(f"{name} exited, but something it started kept its output open")
        out, err = readers
        if out.exceeded:
            raise ScanError(f"{name} wrote more than {max_stdout} bytes of output; it was stopped")
        if err.exceeded:
            raise ScanError(f"{name} wrote more than {max_stderr} bytes to its error stream; it was stopped")
        stderr = err.data().decode("utf-8", errors="replace").strip()
        if proc.returncode < 0:
            raise ScanError(f"{name} was killed by signal {-proc.returncode}\n{error_summary(stderr)}")
        return proc.returncode, out.data(), stderr
    finally:
        shutil.rmtree(home, ignore_errors=True)
