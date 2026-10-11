import copy
import hashlib
import io
import json
import os
import tarfile
import tempfile
import tomllib
import unittest
from contextlib import redirect_stderr
from pathlib import Path

import helpers

from shoalscan import install as inst
from shoalscan.errors import SetupError, VerificationError
from shoalscan.lockfile import load_lock, parse_lock, verify_sha256

LOCK_PATH = helpers.ROOT / "tools.lock"
PLAT = "linux-x86_64"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def rules_tarball(extra_members=()) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:

        def add(name, data=b"", kind=tarfile.REGTYPE, linkname=""):
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = len(data) if kind == tarfile.REGTYPE else 0
            info.linkname = linkname
            tar.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)

        add("opengrep-rules-abc/LICENSE", b"license text")
        add("opengrep-rules-abc/README.md", b"readme")
        add("opengrep-rules-abc/python/lang/eval.yaml", b"rules: []\n")
        add("opengrep-rules-abc/python/lang/eval.py", b"eval(x)\n")
        add("opengrep-rules-abc/python/lang/eval.test.yaml", b"x: 1\n")
        add("opengrep-rules-abc/java/lang/x.yaml", b"rules: []\n")
        add("opengrep-rules-abc/python/link.yaml", kind=tarfile.SYMTYPE, linkname="/etc/passwd")
        for member in extra_members:
            add(*member)
    return buf.getvalue()


class Assets:
    """Serves bytes by URL in place of the network, and lets a test build a matching lock."""

    def __init__(self):
        self.files: dict[str, bytes] = {}
        self.requests: list[str] = []

    def fetch(self, url: str, dest: Path) -> None:
        self.requests.append(url)
        if url not in self.files:
            raise SetupError(f"download failed: {url}")
        dest.write_bytes(self.files[url])


def tool_tarball(members: dict[str, bytes], links: dict[str, str] | None = None) -> bytes:
    """A .tar.gz with these regular files (and symbolic links), as a scanner release ships."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for name, target in (links or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tar.addfile(info)
    return buf.getvalue()


GITLEAKS_BINARY = b"gitleaks-binary"
GITLEAKS_CONFIG = b'[[rules]]\nid = "test-rule"\nregex = "x"\n'


def make_lock(assets: Assets, tarball: bytes, binary=b"opengrep-binary", cosign=b"cosign-binary"):
    data = tomllib.loads(LOCK_PATH.read_text(encoding="utf-8"))
    data = copy.deepcopy(data)
    og = data["opengrep"]["platforms"][PLAT]
    blobs = {og["url"]: binary, og["signature_url"]: b"sig", og["certificate_url"]: b"cert"}
    og["sha256"], og["signature_sha256"], og["certificate_sha256"] = sha(binary), sha(b"sig"), sha(b"cert")
    co = data["cosign"]["platforms"][PLAT]
    blobs[co["url"]] = cosign
    co["sha256"] = sha(cosign)
    blobs[data["rules"]["url"]] = tarball
    data["rules"]["sha256"] = sha(tarball)
    data["rules"]["languages"] = ["python"]
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "r.tar.gz"
        archive.write_bytes(tarball)
        data["rules"]["files_sha256"] = inst.files_digest(inst.extract_rules(archive, Path(tmp) / "x", ("python",)))
    gl = data["gitleaks"]
    archive = tool_tarball({"LICENSE": b"MIT", "gitleaks": GITLEAKS_BINARY})
    blobs[gl["platforms"][PLAT]["url"]] = archive
    gl["platforms"][PLAT]["sha256"], gl["platforms"][PLAT]["binary_sha256"] = sha(archive), sha(GITLEAKS_BINARY)
    blobs[gl["config"]["url"]] = GITLEAKS_CONFIG
    gl["config"]["sha256"] = sha(GITLEAKS_CONFIG)
    hl = data["hadolint"]["platforms"][PLAT]
    blobs[hl["url"]] = b"hadolint-binary"
    hl["sha256"] = hl["binary_sha256"] = sha(b"hadolint-binary")
    zz = data["zizmor"]["platforms"][PLAT]
    archive = tool_tarball({"zizmor": b"zizmor-binary"})
    blobs[zz["url"]] = archive
    zz["sha256"], zz["binary_sha256"] = sha(archive), sha(b"zizmor-binary")
    tv = data["trivy"]["platforms"][PLAT]
    archive = tool_tarball({"trivy": b"trivy-binary"})
    blobs[tv["url"]], blobs[tv["bundle_url"]] = archive, b"bundle"
    tv["sha256"], tv["binary_sha256"], tv["bundle_sha256"] = sha(archive), sha(b"trivy-binary"), sha(b"bundle")
    assets.files.update(blobs)
    return parse_lock(data)


class LockTests(unittest.TestCase):
    def test_shipped_lock_is_valid_and_complete(self):
        lock = load_lock(LOCK_PATH)
        self.assertEqual(lock.opengrep_version, "1.30.2")
        for plat in ("darwin-x86_64", "darwin-arm64", "linux-x86_64", "linux-arm64"):
            self.assertIn(plat, lock.opengrep)
            self.assertIn(plat, lock.cosign)
        self.assertTrue(
            lock.opengrep_signature.certificate_identity.startswith(
                "https://github.com/opengrep/opengrep/.github/workflows/"
            )
        )
        self.assertEqual(lock.opengrep_signature.certificate_oidc_issuer, "https://token.actions.githubusercontent.com")

    def test_lock_rejects_bad_entries(self):
        base = tomllib.loads(LOCK_PATH.read_text(encoding="utf-8"))
        mutations = [
            lambda d: d["opengrep"]["platforms"][PLAT].__setitem__("sha256", "abc"),
            lambda d: d["opengrep"]["platforms"][PLAT].__setitem__("url", "http://example.com/x"),
            lambda d: d["opengrep"]["platforms"][PLAT].__setitem__("extra", "x"),
            lambda d: d["opengrep"]["platforms"].__setitem__("windows-x86_64", {}),
            lambda d: d["rules"].__setitem__("commit", "main"),
            lambda d: d.__setitem__("lock_version", 2),
            lambda d: d["opengrep"]["signature"].pop("certificate_identity"),
        ]
        for mutate in mutations:
            data = copy.deepcopy(base)
            mutate(data)
            with self.assertRaises(SetupError):
                parse_lock(data)

    def test_wrong_sha256_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "file"
            path.write_bytes(b"content")
            verify_sha256(path, sha(b"content"))
            with self.assertRaises(VerificationError):
                verify_sha256(path, sha(b"other content"))


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "tools"
        self.assets = Assets()
        self.lock = make_lock(self.assets, rules_tarball())
        self.signature_checks = []
        self.bundle_checks = []

    def tearDown(self):
        self.tmp.cleanup()

    def accept_signature(self, cosign, blob, sig, cert, identity):
        self.signature_checks.append((cosign.name, blob.read_bytes(), identity.certificate_identity))

    def accept_bundle(self, cosign, blob, bundle, identity):
        self.bundle_checks.append((cosign.name, bundle.read_bytes(), identity.certificate_identity))

    def reject_signature(self, *args):
        raise VerificationError("cosign signature verification failed")

    def run_install(self, **kwargs):
        kwargs.setdefault("verify_signature", self.accept_signature)
        kwargs.setdefault("verify_bundle", self.accept_bundle)
        with redirect_stderr(io.StringIO()) as err:
            inst.install(self.dir, self.lock, fetch=self.assets.fetch, plat=PLAT, **kwargs)
        return err.getvalue()

    def test_install_verifies_and_is_idempotent(self):
        self.run_install()
        binary = self.dir / "opengrep"
        self.assertEqual(binary.read_bytes(), b"opengrep-binary")
        self.assertEqual(os.stat(binary).st_mode & 0o777, 0o755)
        self.assertEqual(os.stat(self.dir / "cosign").st_mode & 0o777, 0o755)
        self.assertEqual(
            self.signature_checks, [("cosign", b"opengrep-binary", self.lock.opengrep_signature.certificate_identity)]
        )
        rules = inst.community_rules_path(self.dir)
        files = sorted(p.relative_to(rules).as_posix() for p in rules.rglob("*") if p.is_file())
        self.assertEqual(files, ["LICENSE", "python/lang/eval.yaml"])
        self.assertEqual(inst.verify_rules_dir(rules, self.lock), 1)

        count = len(self.assets.requests)
        out = self.run_install()
        self.assertEqual(len(self.assets.requests), count, "a second install must not download again")
        self.assertIn("already installed", out)

    def test_wrong_sha256_download_is_refused_and_not_installed(self):
        url = self.lock.opengrep[PLAT].binary.url
        self.assets.files[url] = b"tampered binary"
        with self.assertRaises(VerificationError):
            self.run_install()
        self.assertFalse((self.dir / "opengrep").exists())

    def test_tampered_installed_binary_is_replaced(self):
        self.run_install()
        (self.dir / "opengrep").write_bytes(b"tampered")
        out = self.run_install()
        self.assertIn("does not match tools.lock", out)
        self.assertEqual((self.dir / "opengrep").read_bytes(), b"opengrep-binary")

    def test_bad_signature_fails_and_nothing_is_installed(self):
        with self.assertRaises(VerificationError):
            self.run_install(verify_signature=self.reject_signature)
        self.assertFalse((self.dir / "opengrep").exists())

    def test_cosign_unavailable_fails_closed(self):
        del self.assets.files[self.lock.cosign[PLAT].url]
        with self.assertRaises(SetupError) as ctx:
            self.run_install()
        self.assertIn("--skip-signature-check", str(ctx.exception))
        self.assertFalse((self.dir / "opengrep").exists())

    def test_skip_signature_check_warns(self):
        del self.assets.files[self.lock.cosign[PLAT].url]
        out = self.run_install(skip_signature_check=True)
        self.assertIn("WARNING", out)
        self.assertEqual(self.signature_checks, [])
        self.assertTrue((self.dir / "opengrep").exists())

    def test_cosign_mismatch_is_tampering_not_a_skip_hint(self):
        self.assets.files[self.lock.cosign[PLAT].url] = b"tampered cosign"
        with self.assertRaises(VerificationError) as ctx:
            self.run_install()
        self.assertIn("tampered", str(ctx.exception))
        self.assertNotIn("--skip-signature-check", str(ctx.exception))
        self.assertFalse((self.dir / "opengrep").exists())

    def test_verified_needs_a_positive_record(self):
        self.run_install()
        self.assertTrue(inst.signature_verified(self.dir, self.lock, PLAT))
        record = json.loads(inst.verified_record_path(self.dir).read_text())
        self.assertEqual(record["binary_sha256"], self.lock.opengrep[PLAT].binary.sha256)
        self.assertEqual(record["certificate_identity"], self.lock.opengrep_signature.certificate_identity)
        # Without the record, the binary is not verified, whatever else is absent.
        inst.verified_record_path(self.dir).unlink()
        self.assertFalse(inst.signature_verified(self.dir, self.lock, PLAT))

    def test_skipped_signature_is_verified_later(self):
        self.run_install(skip_signature_check=True)
        self.assertFalse(inst.signature_verified(self.dir, self.lock, PLAT))
        self.assertEqual(self.signature_checks, [])
        out = self.run_install()
        self.assertEqual([c[1] for c in self.signature_checks], [b"opengrep-binary"])
        self.assertTrue(inst.signature_verified(self.dir, self.lock, PLAT))
        self.assertIn("no earlier record", out)

    def test_hand_copied_binary_counts_as_not_verified(self):
        self.dir.mkdir(parents=True)
        (self.dir / "opengrep").write_bytes(b"opengrep-binary")
        self.assertFalse(inst.signature_verified(self.dir, self.lock, PLAT))
        with self.assertRaises(VerificationError):
            self.run_install(verify_signature=self.reject_signature)
        self.assertFalse(inst.signature_verified(self.dir, self.lock, PLAT))
        self.run_install()
        self.assertTrue(inst.signature_verified(self.dir, self.lock, PLAT))

    def test_modified_rules_are_detected(self):
        self.run_install()
        rules = inst.community_rules_path(self.dir)
        (rules / "python" / "lang" / "eval.yaml").write_text("rules: [changed]\n")
        with self.assertRaises(VerificationError):
            inst.verify_rules_dir(rules, self.lock)
        (rules / "python" / "lang" / "eval.yaml").write_text("rules: []\n")
        inst.verify_rules_dir(rules, self.lock)
        (rules / "python" / "planted.yaml").write_text("rules: []\n")
        with self.assertRaises(VerificationError):
            inst.verify_rules_dir(rules, self.lock)

    def test_forged_manifest_is_not_trusted(self):
        # Before the fix, a MANIFEST.json inside the tools directory was the
        # reference; a planted rule plus a matching manifest passed.
        self.run_install()
        rules = inst.community_rules_path(self.dir)
        planted = rules / "python" / "planted.yaml"
        planted.write_text("rules: []\n")
        listing = {p.relative_to(rules).as_posix(): sha(p.read_bytes()) for p in rules.rglob("*") if p.is_file()}
        (rules / "MANIFEST.json").write_text(json.dumps({"files": listing}))
        with self.assertRaises(VerificationError):
            inst.verify_rules_dir(rules, self.lock)

    def test_extracted_rules_must_match_the_pinned_digest(self):
        lock = make_lock(self.assets, rules_tarball())
        object.__setattr__(lock.rules, "files_sha256", "0" * 64)
        with self.assertRaises(VerificationError):
            with redirect_stderr(io.StringIO()):
                inst.install(
                    self.dir,
                    lock,
                    fetch=self.assets.fetch,
                    plat=PLAT,
                    verify_signature=self.accept_signature,
                    verify_bundle=self.accept_bundle,
                )
        self.assertFalse(inst.community_rules_path(self.dir).exists())

    def test_archive_path_escape_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "r.tar.gz"
            archive.write_bytes(rules_tarball([("opengrep-rules-abc/../evil.yaml", b"x")]))
            with self.assertRaises(VerificationError):
                inst.extract_rules(archive, Path(tmp) / "out", ("python",))


if __name__ == "__main__":
    unittest.main()
