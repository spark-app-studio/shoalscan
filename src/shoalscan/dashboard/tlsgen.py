"""`shoalscan serve init-tls`: a single-use, name-constrained CA and a server certificate.

Python's standard library cannot create certificates, so this runs the
`openssl` command (argument lists only, never a shell). It works with
OpenSSL 3 and with LibreSSL (the `openssl` that macOS ships). The steps:

1. Make a CA key and a self-signed CA certificate. Its name constraints
   cover both name types a server certificate can carry, DNS names and IP
   addresses, because a type the constraints leave out is not restricted at
   all (RFC 5280). DNS names are limited to the names given; with none, to
   `shoalscan.invalid`, which can never be a real name. IP addresses are
   limited to the addresses given; an address family with no address given
   (IPv4 or IPv6) is excluded entirely. The CA may also only vouch for TLS
   servers (extended key usage `serverAuth`).
2. Make a server key and have the CA sign a certificate for those names.
3. Delete the CA key, so the CA can never sign anything else. The
   constraints are a second line of defence: a client that enforces name
   constraints (current browsers and TLS libraries do) rejects any
   certificate from this CA for a name that was not given.

Subjects are plain labels that do not look like host names, so a verifier
that checks the subject's common name as a host name (LibreSSL does when a
certificate has no DNS name) never trips over them.

Private files are created with mode 0600 inside a 0700 directory. The
certificates are public and are written with mode 0644.
"""

from __future__ import annotations

import ipaddress
import os
import re
import secrets
import shutil
import subprocess
from pathlib import Path

from shoalscan.errors import SetupError

SERVER_DAYS = 397  # the longest validity browsers accept for a server certificate
OPENSSL_TIMEOUT = 60
CA_FILE, CERT_FILE, KEY_FILE = "ca.pem", "server.pem", "server.key"
WORK_PREFIX = ".init-tls-"
NO_DNS_NAME = "shoalscan.invalid"  # .invalid is reserved and never resolves (RFC 2606)

_DNS = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_EXTENSIONS = (
    "[ca_ext]\nbasicConstraints = critical,CA:TRUE,pathlen:0\n"
    "keyUsage = critical,keyCertSign,cRLSign\nextendedKeyUsage = serverAuth\nsubjectKeyIdentifier = hash\n"
    "nameConstraints = critical,{constraints}\n"
    "[server_ext]\nbasicConstraints = critical,CA:FALSE\n"
    "keyUsage = critical,digitalSignature\nextendedKeyUsage = serverAuth\n"
    "subjectAltName = {san}\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n"
)


def find_openssl() -> str | None:
    return shutil.which("openssl")


def _openssl(openssl: str, args: list[str], cwd: Path) -> str:
    try:
        proc = subprocess.run(
            [openssl, *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=OPENSSL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise SetupError(f"openssl {args[0]} timed out") from None
    except OSError as exc:
        raise SetupError(f"openssl could not run: {exc}") from None
    if proc.returncode != 0:
        raise SetupError(f"openssl {args[0]} failed: {proc.stderr.strip()[-500:]}")
    return proc.stdout


def check_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        raise SetupError(f"not an IP address: {value!r}") from None
    if ip.is_unspecified or ip.is_multicast:
        raise SetupError(f"{value} cannot be a server address; name the address clients connect to")
    return str(ip)


def check_dns(value: str) -> str:
    name = value.lower().rstrip(".")
    # The name goes into an openssl configuration file, so only plain
    # hostname characters are allowed (no wildcards, commas or newlines).
    if not _DNS.match(name):
        raise SetupError(f"not a usable DNS name: {value!r}")
    return name


def name_constraints(ips: list[str], names: list[str]) -> str:
    """The CA's nameConstraints value: both name types are always constrained."""
    parts = [f"permitted;DNS:{name}" for name in names] or [f"permitted;DNS:{NO_DNS_NAME}"]
    addresses = [ipaddress.ip_address(v) for v in ips]
    for ip in addresses:
        mask = "255.255.255.255" if ip.version == 4 else "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"
        parts.append(f"permitted;IP:{ip}/{mask}")
    # An excluded subtree wins over a permitted one, so a family is excluded
    # only when no address of that family was given.
    if not any(ip.version == 4 for ip in addresses):
        parts.append("excluded;IP:0.0.0.0/0.0.0.0")
    if not any(ip.version == 6 for ip in addresses):
        parts.append("excluded;IP:::/::")
    return ",".join(parts)


def subject_alt_name(ips: list[str], names: list[str]) -> str:
    return ",".join([f"DNS:{n}" for n in names] + [f"IP:{ipaddress.ip_address(v)}" for v in ips])


def _write_configs(work: Path, constraints: str, san: str) -> None:
    extensions = _EXTENSIONS.format(constraints=constraints, san=san)
    # Separate files, because LibreSSL ignores -subj when the configuration
    # names a subject; each file carries its own.
    for name, subject in (
        ("ca.cnf", f"Shoalscan dashboard CA {secrets.token_hex(4)}"),
        ("leaf.cnf", "Shoalscan dashboard"),
    ):
        (work / name).write_text(
            f"[req]\ndistinguished_name = subject\nprompt = no\n[subject]\nCN = {subject}\n{extensions}",
            encoding="ascii",
        )


def make_ca(openssl: str, work: Path, ips: list[str], names: list[str]) -> None:
    """Write ca.key, ca.pem and the configurations into `work`."""
    _write_configs(work, name_constraints(ips, names), subject_alt_name(ips, names))
    _openssl(openssl, ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ca.key"], work)
    _openssl(
        openssl,
        [
            "req",
            "-new",
            "-x509",
            "-sha256",
            "-days",
            str(SERVER_DAYS + 1),
            "-key",
            "ca.key",
            "-config",
            "ca.cnf",
            "-extensions",
            "ca_ext",
            "-out",
            CA_FILE,
        ],
        work,
    )


def sign_leaf(
    openssl: str, work: Path, key_file: str, cert_file: str, extfile: str = "leaf.cnf", section: str = "server_ext"
) -> None:
    """Make a key and have the CA in `work` sign a server certificate for it."""
    _openssl(openssl, ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key_file], work)
    _openssl(
        openssl, ["req", "-new", "-sha256", "-key", key_file, "-config", "leaf.cnf", "-out", f"{key_file}.csr"], work
    )
    _openssl(
        openssl,
        [
            "x509",
            "-req",
            "-sha256",
            "-days",
            str(SERVER_DAYS),
            "-in",
            f"{key_file}.csr",
            "-CA",
            CA_FILE,
            "-CAkey",
            "ca.key",
            "-set_serial",
            str(int.from_bytes(secrets.token_bytes(15), "big") | 1),
            "-extfile",
            extfile,
            "-extensions",
            section,
            "-out",
            cert_file,
        ],
        work,
    )
    (work / f"{key_file}.csr").unlink()


def _remove_tree(path: Path) -> None:
    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            _remove_tree(child)
        else:
            child.unlink()
    path.rmdir()


def generate(out_dir: Path, ips: list[str], names: list[str], force: bool = False, openssl: str | None = None) -> dict:
    """Write ca.pem, server.pem and server.key into `out_dir`. Returns their paths and the CA fingerprint."""
    ips = [check_ip(v) for v in ips]
    names = [check_dns(v) for v in names]
    if not ips and not names:
        raise SetupError("name at least one --ip or --dns that clients will use to reach the dashboard")
    openssl = openssl or find_openssl()
    if not openssl:
        raise SetupError("the openssl command is not installed; install it, or bring your own certificate and key")
    out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)
    # A run that was killed part-way leaves its work directory behind; it may hold a CA key.
    for stale in out_dir.glob(WORK_PREFIX + "*"):
        if stale.is_dir() and not stale.is_symlink():
            _remove_tree(stale)
    existing = [n for n in (CA_FILE, CERT_FILE, KEY_FILE) if (out_dir / n).exists()]
    if existing and not force:
        raise SetupError(f"{out_dir} already has {', '.join(existing)} (pass --force to replace them)")
    work = out_dir / f"{WORK_PREFIX}{secrets.token_hex(6)}"
    old_umask = os.umask(0o077)
    try:
        work.mkdir(mode=0o700)
        make_ca(openssl, work, ips, names)
        sign_leaf(openssl, work, KEY_FILE, CERT_FILE)
        # The CA has signed its one certificate: its key goes before anything else happens.
        (work / "ca.key").unlink()
        os.chmod(work / KEY_FILE, 0o600)
        os.chmod(work / CA_FILE, 0o644)
        os.chmod(work / CERT_FILE, 0o644)
        for name in (KEY_FILE, CERT_FILE, CA_FILE):
            os.replace(work / name, out_dir / name)
    finally:
        os.umask(old_umask)
        if work.exists():
            _remove_tree(work)
    fingerprint = _openssl(openssl, ["x509", "-in", CA_FILE, "-noout", "-fingerprint", "-sha256"], out_dir)
    return {
        "ca": out_dir / CA_FILE,
        "cert": out_dir / CERT_FILE,
        "key": out_dir / KEY_FILE,
        "ca_sha256": fingerprint.strip().split("=", 1)[-1],
        "names": names + ips,
    }
