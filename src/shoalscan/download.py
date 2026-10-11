"""HTTPS downloads with size and time limits. Used only by `shoalscan install`."""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from pathlib import Path

from shoalscan import __version__
from shoalscan.errors import SetupError

MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
SOCKET_TIMEOUT_SECONDS = 60
TOTAL_TIMEOUT_SECONDS = 900


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise urllib.error.URLError(f"refusing a redirect to a non-HTTPS URL: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _set_read_timeout(response, seconds: float) -> None:
    """Make the next socket read wait no longer than `seconds`, so the overall
    deadline holds even when the server trickles data."""
    sock = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
    if sock is not None:
        sock.settimeout(max(seconds, 0.001))


def fetch(url: str, dest: Path, *, max_bytes: int = MAX_DOWNLOAD_BYTES) -> None:
    """Download `url` to `dest`. Only HTTPS is allowed, also for redirects.

    The caller verifies the SHA-256 of `dest` before using it.
    """
    if not url.startswith("https://"):
        raise SetupError(f"refusing a non-HTTPS download: {url}")
    opener = urllib.request.build_opener(_HttpsOnlyRedirects())
    request = urllib.request.Request(url, headers={"User-Agent": f"shoalscan/{__version__}"})
    deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
    written = 0
    try:
        with opener.open(request, timeout=SOCKET_TIMEOUT_SECONDS) as response, open(dest, "wb") as out:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SetupError(f"download took longer than {TOTAL_TIMEOUT_SECONDS}s: {url}")
                _set_read_timeout(response, min(SOCKET_TIMEOUT_SECONDS, remaining))
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise SetupError(f"download is larger than {max_bytes} bytes: {url}")
                if time.monotonic() > deadline:
                    raise SetupError(f"download took longer than {TOTAL_TIMEOUT_SECONDS}s: {url}")
                out.write(chunk)
    except SetupError:
        raise
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        hint = ""
        if "CERTIFICATE_VERIFY_FAILED" in str(exc):
            hint = (
                "\nPython has no trusted CA certificates. Point SSL_CERT_FILE at your system CA bundle, "
                "or on a python.org macOS install run its `Install Certificates.command`."
            )
        raise SetupError(f"download failed: {url}: {exc}{hint}") from None
