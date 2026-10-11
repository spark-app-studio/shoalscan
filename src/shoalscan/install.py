"""`shoalscan install`: download, verify and install the pinned tools."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath

from shoalscan import download
from shoalscan.errors import SetupError, VerificationError
from shoalscan.lockfile import (
    Lock,
    OpengrepSignature,
    PinnedTool,
    current_platform,
    sha256_file,
    verify_sha256,
)

RULES_DIR_NAME = "opengrep-rules"
COSIGN_TIMEOUT_SECONDS = 180
MAX_RULE_FILE_BYTES = 2 * 1024 * 1024
MAX_RULES_TOTAL_BYTES = 200 * 1024 * 1024
MAX_BINARY_BYTES = 512 * 1024 * 1024

Fetch = Callable[[str, Path], None]


VERIFIED_RECORD = "opengrep.verified.json"


def verified_record_path(tools_dir: Path) -> Path:
    return tools_dir / VERIFIED_RECORD


def _expected_record(lock: Lock, plat: str) -> dict:
    entry = lock.opengrep[plat]
    sig = lock.opengrep_signature
    return {
        "verified": "cosign verify-blob",
        "opengrep_version": lock.opengrep_version,
        "binary_sha256": entry.binary.sha256,
        "signature_sha256": entry.signature.sha256,
        "certificate_sha256": entry.certificate.sha256,
        "certificate_identity": sig.certificate_identity,
        "certificate_oidc_issuer": sig.certificate_oidc_issuer,
        "github_workflow_repository": sig.github_workflow_repository,
        "github_workflow_sha": sig.github_workflow_sha,
        "cosign_version": lock.cosign_version,
    }


def write_verified_record(tools_dir: Path, lock: Lock, plat: str) -> None:
    """Record, after a successful cosign check, exactly what was verified."""
    path = verified_record_path(tools_dir)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(_expected_record(lock, plat), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def signature_verified(tools_dir: Path, lock: Lock, plat: str) -> bool:
    """True only with a positive record of a cosign check for the pinned binary,
    and the installed binary still matching that pin. A binary copied in by
    hand has no record and counts as not verified."""
    try:
        record = json.loads(verified_record_path(tools_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if plat not in lock.opengrep or record != _expected_record(lock, plat):
        return False
    binary = opengrep_path(tools_dir)
    return binary.is_file() and sha256_file(binary) == lock.opengrep[plat].binary.sha256


def opengrep_path(tools_dir: Path) -> Path:
    return tools_dir / "opengrep"


def cosign_path(tools_dir: Path) -> Path:
    return tools_dir / "cosign"


def community_rules_path(tools_dir: Path) -> Path:
    return tools_dir / "rules" / RULES_DIR_NAME


def tool_path(tools_dir: Path, name: str) -> Path:
    """Where a scanner pinned in its own [<name>] table is installed."""
    return tools_dir / name


def tool_file_path(tools_dir: Path, name: str, extra: str) -> Path:
    """Where one of a pinned scanner's extra files, such as `gitleaks` `config`, is installed."""
    return tools_dir / f"{name}-{extra}"


def _log(message: str) -> None:
    print(message, file=sys.stderr)


def _place(src: Path, dest: Path, mode: int) -> None:
    """Move a verified file into place atomically, with the given mode."""
    os.chmod(src, mode)
    os.replace(src, dest)


def _identity_args(identity: OpengrepSignature) -> list[str]:
    return [
        "--certificate-identity",
        identity.certificate_identity,
        "--certificate-oidc-issuer",
        identity.certificate_oidc_issuer,
        "--certificate-github-workflow-repository",
        identity.github_workflow_repository,
        "--certificate-github-workflow-sha",
        identity.github_workflow_sha,
    ]


def _verify_blob(cosign: Path, blob: Path, args: list[str]) -> None:
    """Run `cosign verify-blob` with these arguments on `blob`; anything but success is a VerificationError."""
    cmd = [str(cosign), "verify-blob", *args, str(blob)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=COSIGN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        raise VerificationError(f"cosign verify-blob timed out after {COSIGN_TIMEOUT_SECONDS}s") from None
    except OSError as exc:
        raise VerificationError(f"cosign could not run: {exc}") from None
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()[-1500:]
        raise VerificationError(f"cosign signature verification failed for {blob.name}:\n{detail}")


def run_cosign(cosign: Path, blob: Path, signature: Path, certificate: Path, identity: OpengrepSignature) -> None:
    """Verify `blob` against a detached signature and certificate, and the pinned workflow identity."""
    _verify_blob(
        cosign, blob, ["--certificate", str(certificate), "--signature", str(signature), *_identity_args(identity)]
    )


def run_cosign_bundle(cosign: Path, blob: Path, bundle: Path, identity: OpengrepSignature) -> None:
    """Verify `blob` against a Sigstore bundle and the pinned workflow identity."""
    _verify_blob(cosign, blob, ["--bundle", str(bundle), *_identity_args(identity)])


def _fetch_verified(fetch: Fetch, url: str, sha256: str, dest: Path) -> None:
    fetch(url, dest)
    verify_sha256(dest, sha256)


def install_cosign(tools_dir: Path, lock: Lock, plat: str, fetch: Fetch, tmp: Path) -> Path:
    asset = lock.cosign.get(plat)
    if asset is None:
        raise SetupError(f"tools.lock pins no cosign for {plat}")
    dest = cosign_path(tools_dir)
    if dest.is_file():
        try:
            verify_sha256(dest, asset.sha256)
            _log(f"cosign {lock.cosign_version}: already installed, SHA-256 verified")
            return dest
        except VerificationError:
            _log("cosign: the installed file does not match tools.lock; replacing it")
    staged = tmp / "cosign"
    _fetch_verified(fetch, asset.url, asset.sha256, staged)
    _place(staged, dest, 0o755)
    _log(f"cosign {lock.cosign_version}: installed, SHA-256 verified")
    return dest


def install_opengrep(
    tools_dir: Path,
    lock: Lock,
    plat: str,
    fetch: Fetch,
    tmp: Path,
    cosign: Path | None,
    verify_signature: Callable[..., None],
) -> None:
    entry = lock.opengrep.get(plat)
    if entry is None:
        raise SetupError(f"tools.lock pins no Opengrep binary for {plat}")
    dest = opengrep_path(tools_dir)
    if dest.is_file():
        try:
            verify_sha256(dest, entry.binary.sha256)
            present = True
        except VerificationError:
            _log("opengrep: the installed file does not match tools.lock; replacing it")
            present = False
        if present:
            _log(f"opengrep {lock.opengrep_version}: already installed, SHA-256 verified")
            if signature_verified(tools_dir, lock, plat):
                return
            if cosign is None:
                _log("WARNING: the installed Opengrep's signature has not been verified")
                return
            # No record of a signature check (a skipped check, or a binary
            # copied in by hand): check it now.
            sig, cert = tmp / "opengrep.sig", tmp / "opengrep.cert"
            _fetch_verified(fetch, entry.signature.url, entry.signature.sha256, sig)
            _fetch_verified(fetch, entry.certificate.url, entry.certificate.sha256, cert)
            verify_signature(cosign, dest, sig, cert, lock.opengrep_signature)
            _place(sig, tools_dir / "opengrep.sig", 0o644)
            _place(cert, tools_dir / "opengrep.cert", 0o644)
            write_verified_record(tools_dir, lock, plat)
            _log(f"opengrep {lock.opengrep_version}: cosign signature verified (no earlier record)")
            return
    verified_record_path(tools_dir).unlink(missing_ok=True)
    binary, sig, cert = tmp / "opengrep", tmp / "opengrep.sig", tmp / "opengrep.cert"
    _fetch_verified(fetch, entry.binary.url, entry.binary.sha256, binary)
    _fetch_verified(fetch, entry.signature.url, entry.signature.sha256, sig)
    _fetch_verified(fetch, entry.certificate.url, entry.certificate.sha256, cert)
    if cosign is not None:
        verify_signature(cosign, binary, sig, cert, lock.opengrep_signature)
        _log(f"opengrep {lock.opengrep_version}: cosign signature verified")
    _place(sig, tools_dir / "opengrep.sig", 0o644)
    _place(cert, tools_dir / "opengrep.cert", 0o644)
    _place(binary, dest, 0o755)
    if cosign is not None:
        write_verified_record(tools_dir, lock, plat)
    _log(f"opengrep {lock.opengrep_version}: installed, SHA-256 verified")


def extract_member(archive: Path, member: str, dest: Path) -> None:
    """Extract the one regular file `member` from a .tar.gz archive to `dest`.

    Nothing else is written. A member that is a link or a device, or appears
    twice, is refused, and so is an archive without it.
    """
    found = None
    with tarfile.open(archive, mode="r:gz") as tar:
        for info in tar:
            if info.name.lstrip("./") != member:
                continue
            if found is not None:
                raise VerificationError(f"{archive.name} holds {member} more than once")
            if not info.isreg() or info.size > MAX_BINARY_BYTES:
                raise VerificationError(f"{member} in {archive.name} is not a regular file of an allowed size")
            handle = tar.extractfile(info)
            if handle is None:
                raise VerificationError(f"{member} in {archive.name} cannot be read")
            with open(dest, "wb") as out:
                shutil.copyfileobj(handle, out)
            found = info
    if found is None:
        raise VerificationError(f"{archive.name} has no {member}")


def install_pinned_tool(
    tools_dir: Path,
    tool: PinnedTool,
    plat: str,
    fetch: Fetch,
    tmp: Path,
    cosign: Path | None = None,
    verify_bundle: Callable[..., None] = run_cosign_bundle,
) -> None:
    """Install a scanner pinned by SHA-256 and its extra files.

    Files already in place are verified, not downloaded again.

    For a tool whose lock entry has a signature, the download's Sigstore
    bundle is checked with cosign before anything is extracted; without
    cosign (--skip-signature-check) the install says loudly that it was not.
    """
    entry = tool.platforms.get(plat)
    if entry is None:
        raise SetupError(f"tools.lock pins no {tool.name} for {plat}")
    for extra, asset in sorted(tool.files.items()):
        dest = tool_file_path(tools_dir, tool.name, extra)
        if dest.is_file() and sha256_file(dest) == asset.sha256:
            continue
        staged = tmp / f"{tool.name}-{extra}"
        _fetch_verified(fetch, asset.url, asset.sha256, staged)
        _place(staged, dest, 0o644)
    dest = tool_path(tools_dir, tool.name)
    if dest.is_file() and sha256_file(dest) == entry.binary_sha256:
        _log(f"{tool.name} {tool.version}: already installed, SHA-256 verified")
        return
    download_path = tmp / f"{tool.name}.download"
    _fetch_verified(fetch, entry.download.url, entry.download.sha256, download_path)
    if tool.signature is not None and entry.bundle is not None:
        if cosign is None:
            _log(
                f"WARNING: --skip-signature-check: the {tool.name} signature is NOT verified; only its SHA-256 pins "
                "protect it."
            )
        else:
            bundle = tmp / f"{tool.name}.sigstore.json"
            _fetch_verified(fetch, entry.bundle.url, entry.bundle.sha256, bundle)
            verify_bundle(cosign, download_path, bundle, tool.signature)
            _log(f"{tool.name} {tool.version}: cosign signature verified")
    if tool.member is None:
        binary = download_path
    else:
        binary = tmp / tool.name
        extract_member(download_path, tool.member, binary)
        verify_sha256(binary, entry.binary_sha256)
    _place(binary, dest, 0o755)
    _log(f"{tool.name} {tool.version}: installed, SHA-256 verified")


def _selected(rel: PurePosixPath, languages: tuple[str, ...]) -> bool:
    if str(rel) == "LICENSE":
        return True
    if len(rel.parts) < 2 or rel.parts[0] not in languages:
        return False
    name = rel.name
    if not name.endswith((".yaml", ".yml")):
        return False
    # Rule tests and autofix fixtures are not rules.
    return not any(marker in name for marker in (".test.", ".fixed."))


def extract_rules(archive: Path, dest: Path, languages: tuple[str, ...]) -> dict[str, str]:
    """Extract the rule files for `languages` and the LICENSE from the snapshot.

    Only regular files are written. Links, devices and paths that would leave
    `dest` are refused. Returns {relative path: sha256}.
    """
    files: dict[str, str] = {}
    total = 0
    top: str | None = None
    with tarfile.open(archive, mode="r:gz") as tar:
        for member in tar:
            parts = PurePosixPath(member.name).parts
            if not parts:
                continue
            if top is None:
                top = parts[0]
            if parts[0] != top or member.name.startswith("/") or ".." in parts:
                raise VerificationError(f"unexpected path in the rules archive: {member.name!r}")
            if len(parts) < 2 or not member.isreg():
                continue
            rel = PurePosixPath(*parts[1:])
            if not _selected(rel, languages):
                continue
            if member.size > MAX_RULE_FILE_BYTES:
                raise VerificationError(f"rules archive member is too large: {member.name}")
            total += member.size
            if total > MAX_RULES_TOTAL_BYTES:
                raise VerificationError("the rules archive is larger than allowed")
            handle = tar.extractfile(member)
            if handle is None:
                continue
            data = handle.read(MAX_RULE_FILE_BYTES + 1)
            target = dest.joinpath(*rel.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "wb") as out:
                out.write(data)
            os.chmod(target, 0o644)
            files[str(rel)] = hashlib.sha256(data).hexdigest()
    if "LICENSE" not in files:
        raise VerificationError("the rules archive has no LICENSE file")
    return files


def files_digest(files: dict[str, str]) -> str:
    """One SHA-256 over the sorted list of (relative path, file SHA-256)."""
    listing = "".join(f"{path}\t{digest}\n" for path, digest in sorted(files.items()))
    return hashlib.sha256(listing.encode("utf-8")).hexdigest()


def hash_tree(rules_dir: Path) -> dict[str, str]:
    """Hash every file under `rules_dir`. Links and special files are refused."""
    files: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(rules_dir, followlinks=False):
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            rel = path.relative_to(rules_dir).as_posix()
            if path.is_symlink():
                raise VerificationError(f"unexpected link in the community rules: {rel}")
            if name in filenames:
                if not path.is_file():
                    raise VerificationError(f"unexpected special file in the community rules: {rel}")
                files[rel] = sha256_file(path)
    return files


def verify_rules_dir(rules_dir: Path, lock: Lock) -> int:
    """Check an installed rules snapshot against `tools.lock`.

    Nothing inside the tools directory is trusted: every file is hashed, and
    the digest of the sorted (path, SHA-256) list must equal
    `rules.files_sha256` in the lock. Any extra, missing or changed file fails.
    Returns the number of rule files.
    """
    if not rules_dir.is_dir():
        raise VerificationError(f"community rules are not installed: {rules_dir} (run `shoalscan install`)")
    files = hash_tree(rules_dir)
    if files_digest(files) != lock.rules.files_sha256:
        raise VerificationError(
            "the installed community rules do not match tools.lock (files were added, removed or changed); "
            "run `shoalscan install` to reinstall them"
        )
    return sum(1 for rel in files if rel != "LICENSE")


def install_rules(tools_dir: Path, lock: Lock, fetch: Fetch, tmp: Path) -> None:
    dest = community_rules_path(tools_dir)
    if dest.is_dir():
        try:
            count = verify_rules_dir(dest, lock)
            _log(f"{lock.rules.name} {lock.rules.commit[:12]}: already installed, {count} rule files verified")
            return
        except VerificationError as exc:
            _log(f"{lock.rules.name}: {exc}; reinstalling")
    archive = tmp / "rules.tar.gz"
    _fetch_verified(fetch, lock.rules.archive.url, lock.rules.archive.sha256, archive)
    dest.parent.mkdir(parents=True, exist_ok=True)
    staged = Path(tempfile.mkdtemp(prefix=".rules-", dir=dest.parent))
    try:
        files = extract_rules(archive, staged, lock.rules.languages)
        if files_digest(files) != lock.rules.files_sha256:
            raise VerificationError("the extracted community rules do not match rules.files_sha256 in tools.lock")
        old = None
        if dest.exists():
            old = Path(tempfile.mkdtemp(prefix=".rules-old-", dir=dest.parent))
            os.replace(dest, old / "previous")
        os.replace(staged, dest)
        if old is not None:
            shutil.rmtree(old)
    finally:
        if staged.exists():
            shutil.rmtree(staged)
    count = verify_rules_dir(dest, lock)
    _log(f"{lock.rules.name} {lock.rules.commit[:12]}: installed, SHA-256 verified, {count} rule files")


def install(
    tools_dir: Path,
    lock: Lock,
    *,
    skip_signature_check: bool = False,
    with_rules: bool = True,
    fetch: Fetch = download.fetch,
    verify_signature: Callable[..., None] = run_cosign,
    verify_bundle: Callable[..., None] = run_cosign_bundle,
    plat: str | None = None,
) -> None:
    plat = plat or current_platform()
    tools_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(tools_dir, 0o755)
    with tempfile.TemporaryDirectory(prefix=".install-", dir=tools_dir) as tmp_name:
        tmp = Path(tmp_name)
        cosign: Path | None = None
        if skip_signature_check:
            _log(
                "WARNING: --skip-signature-check: the Opengrep signature is NOT verified. "
                "Only the SHA-256 pins in tools.lock protect this install."
            )
        else:
            try:
                cosign = install_cosign(tools_dir, lock, plat, fetch, tmp)
            except VerificationError as exc:
                # A cosign download that does not match its pin is a possible
                # tampering, never a reason to skip the signature check.
                raise VerificationError(
                    f"the cosign download does not match tools.lock: {exc}\n"
                    "This can mean the download was tampered with. Install stops here."
                ) from None
            except SetupError as exc:
                raise SetupError(
                    f"cosign is unavailable, so the Opengrep signature cannot be verified: {exc}\n"
                    "Install stops here. Pass --skip-signature-check to install with SHA-256 checks only."
                ) from None
        install_opengrep(tools_dir, lock, plat, fetch, tmp, cosign, verify_signature)
        if with_rules:
            install_rules(tools_dir, lock, fetch, tmp)
        for _name, tool in sorted(lock.tools.items()):
            install_pinned_tool(tools_dir, tool, plat, fetch, tmp, cosign, verify_bundle)
    _log(f"tools are ready in {tools_dir}")
