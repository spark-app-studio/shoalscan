"""Helm charts: rendered offline by the pinned Helm, never changed, blocked when they render an ignore marker,
checked by Trivy and mapped back to their templates."""

import contextlib
import io
import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import helpers

from shoalscan import helm
from shoalscan import install as inst
from shoalscan.check import compare
from shoalscan.cli import main
from shoalscan.config import parse_config
from shoalscan.errors import ScanError, SetupError
from shoalscan.lockfile import load_lock, parse_lock, sha256_file

LOCK_PATH = helpers.ROOT / "tools.lock"
TOOLS = helpers.tools_dir()
MARK = "trivy" + ":ignore"

CHART = "apiVersion: v2\nname: web\nversion: 0.1.0\n"
# A privileged pod, with the `lookup` and `tpl` functions, which must work without a cluster.
POD = (
    "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ .Release.Name }}-web\n"
    "spec:\n  containers:\n"
    "    - name: web\n"
    "      image: {{ .Values.image }}\n"
    "      securityContext:\n        privileged: true\n"
    '{{- $secret := lookup "v1" "Secret" "default" "db" }}\n'
    '{{- $_ := tpl "{{ .Values.image }}" . }}\n'
)


def tools_ready() -> bool:
    lock = load_lock(LOCK_PATH)
    try:
        return all(
            sha256_file(inst.tool_path(TOOLS, name))
            == lock.tools[name].platforms[inst.current_platform()].binary_sha256
            for name in ("helm", "trivy")
        )
    except (OSError, KeyError):
        return False


def write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")


class PinTests(unittest.TestCase):
    def test_helm_is_pinned_with_a_member_per_platform(self):
        tool = load_lock(LOCK_PATH).tools["helm"]
        self.assertEqual((tool.version, tool.license, tool.member), ("4.2.4", "Apache-2.0", None))
        self.assertEqual(set(tool.platforms), {"darwin-x86_64", "darwin-arm64", "linux-x86_64", "linux-arm64"})
        for plat, pin in tool.platforms.items():
            self.assertTrue(pin.download.url.startswith("https://get.helm.sh/helm-v4.2.4-"), plat)
            self.assertTrue(pin.member.endswith("/helm"), plat)

    def test_a_member_must_stay_inside_the_archive(self):
        import tomllib

        data = tomllib.loads(LOCK_PATH.read_text(encoding="utf-8"))
        data["helm"]["platforms"]["linux-arm64"]["member"] = "../helm"
        with self.assertRaises(SetupError):
            parse_lock(data)


class ConfigTests(unittest.TestCase):
    def test_extra_values_files_are_repository_relative(self):
        config = parse_config({"trivy": {"helm_values": {"deploy/web": ["deploy/ci.yaml"], ".": ["v.yaml"]}}})
        self.assertEqual(config.trivy.helm_values_map(), {".": ("v.yaml",), "deploy/web": ("deploy/ci.yaml",)})
        for bad in ({"web": ["/etc/passwd"]}, {"web": ["../x.yaml"]}, {"/abs": ["x.yaml"]}, ["x.yaml"]):
            with self.subTest(bad=bad), self.assertRaises(SetupError):
                parse_config({"trivy": {"helm_values": bad}})


class RenderUnitTests(unittest.TestCase):
    def test_charts_are_found_but_not_their_subcharts_libraries_or_excluded_ones(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root,
                {
                    "deploy/web/Chart.yaml": CHART,
                    "deploy/web/charts/db/Chart.yaml": CHART,
                    "lib/Chart.yaml": CHART + "type: library\n",
                    "vendor/x/Chart.yaml": CHART,
                    ".git/y/Chart.yaml": CHART,
                },
            )
            self.assertEqual(helm.find_charts(root, ("vendor",)), ["deploy/web"])

    def test_only_helm_s_own_header_names_a_document_s_template(self):
        text = (
            "---\n# Source: web/templates/pod.yaml\napiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n"
            "---\n# Source: web/templates/pod.yaml\n# Source: web/templates/other.yaml\nkind: Pod\n"
            "---\n# Source: web/charts/db/templates/cm.yaml\nkind: ConfigMap\nmetadata:\n  name: b\n"
            "---\nkind: Secret\n---\n# only a comment\n"
        )
        docs = helm.split_documents(text)
        self.assertEqual(
            [s for s, _ in docs],
            ["web/templates/pod.yaml", "web/templates/pod.yaml", "web/charts/db/templates/cm.yaml", None],
        )
        self.assertEqual(helm.resource(docs[0][1]), "Pod/a")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(
                root,
                {
                    "deploy/web/templates/pod.yaml": "x",
                    "deploy/web/charts/db/templates/cm.yaml": "x",
                    "deploy/web/fixtures/a.yaml": "x",
                    "deploy/web/templates/skip/x.yaml": "x",
                },
            )
            path = lambda s, ex=(): helm.template_path(root, "deploy/web", s, ex)  # noqa: E731
            self.assertEqual(path(docs[0][0]), "deploy/web/templates/pod.yaml")
            self.assertEqual(path(docs[2][0]), "deploy/web/charts/db/templates/cm.yaml")
            # Outside templates/, missing, malformed or excluded: the chart's Chart.yaml, never dropped.
            for odd in (None, "web/fixtures/a.yaml", "web/../../etc/passwd", "web/templates/missing.yaml", "x"):
                self.assertEqual(path(odd), "deploy/web/Chart.yaml", odd)
            self.assertEqual(path("web/templates/skip/x.yaml", ("deploy/web/templates/skip",)), "deploy/web/Chart.yaml")

    def test_anything_like_a_marker_is_found(self):
        for text in (
            f"a: b # {MARK}:*",
            "x: 'TRIVY : exp:1:IGNORE:KSV-0001'",
            "#tf sec:ignore:x",
            "tfsec:ignore:AWS-1",
        ):
            self.assertTrue(helm.holds_marker(text), text)
        self.assertFalse(helm.holds_marker("image: aquasec/trivy:0.74.0\nnote: ignore this"))

    def test_values_files_are_never_reached_through_a_link(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            write(root, {"web/values-ci.yaml": "a: 1\n"})
            outside = Path(tmp) / "outside"
            write(outside, {"secret.yaml": "a: 1\n"})
            (root / "vals").symlink_to(outside)
            self.assertEqual(
                helm._values_files(root, "web", {"web": ("web/values-ci.yaml",)}), [root / "web/values-ci.yaml"]
            )
            for rel in ("vals/secret.yaml", "web/missing.yaml", "web"):
                with self.subTest(rel=rel), self.assertRaises(ValueError):
                    helm._values_files(root, "web", {"web": (rel,)})

    def test_a_chart_too_big_to_list_fails_the_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, {f"web/templates/{n}.yaml": "x" for n in range(4)})
            with mock.patch.object(helm, "MAX_LISTED_FILES", 3), self.assertRaises(ScanError):
                helm._chart_files(root, "web")

    def test_helm_keeps_its_directories_in_the_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = helm.helm_env(Path(tmp))
        self.assertEqual(env["KUBECONFIG"], os.devnull)
        self.assertEqual(env["GOMEMLIMIT"], "512MiB")
        for var in ("HELM_CACHE_HOME", "HELM_CONFIG_HOME", "HELM_DATA_HOME", "HELM_PLUGINS"):
            self.assertTrue(env[var].startswith(tmp), var)


@unittest.skipUnless(tools_ready(), f"helm and trivy are not installed in {TOOLS}; run `shoalscan install`")
class EndToEndTests(unittest.TestCase):
    def scan(self, repo: Path, out: Path) -> dict:
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = main(["scan", "--repo", str(repo), "--out", str(out), "--tools-dir", str(TOOLS)])
        self.assertEqual(code, 0, err.getvalue())
        return json.loads((out / "findings.json").read_text())

    def chart(self, root: Path, extra: dict[str, str] | None = None) -> None:
        write(
            root,
            {
                "deploy/web/Chart.yaml": CHART,
                "deploy/web/values.yaml": "image: nginx:1.27\n",
                "deploy/web/templates/pod.yaml": POD,
                ".shoalscan.toml": 'scanners = ["trivy"]\n',
                **(extra or {}),
            },
        )

    def test_a_privileged_pod_is_found_at_its_template(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            self.chart(repo)
            doc = self.scan(repo, Path(tmp) / "out")
        privileged = [f for f in doc["findings"] if f["rule"] == "trivy.KSV-0017"]
        self.assertEqual([(f["path"], f["line"]) for f in privileged], [("deploy/web/templates/pod.yaml", 1)])
        self.assertIn("as Helm renders it", privileged[0]["message"])
        self.assertIn("Pod/release-web", privileged[0]["message"])
        self.assertEqual(doc["unscanned"], {"skipped": [], "errors": []})
        self.assertEqual(doc["suppressions"]["suppressed_findings"], 0)
        self.assertEqual(doc["scanners"]["trivy"]["helm"]["version"], "4.2.4")

    def test_fingerprints_survive_unrelated_template_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            self.chart(repo)
            before = {(f["rule"], f["fingerprint"]) for f in self.scan(repo, Path(tmp) / "a")["findings"]}
            self.chart(
                repo,
                {
                    "deploy/web/templates/pod.yaml": "{{/* a note */}}\n\n" + POD.replace("spec:\n", "spec:\n\n"),
                    "deploy/web/templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n",
                },
            )
            after = {(f["rule"], f["fingerprint"]) for f in self.scan(repo, Path(tmp) / "b")["findings"]}
        self.assertTrue(before)
        self.assertLessEqual(before, after)

    def test_charts_that_cannot_render_are_unscanned_and_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            self.chart(
                repo,
                {
                    "deploy/broken/Chart.yaml": CHART.replace("web", "broken"),
                    "deploy/broken/templates/x.yaml": "{{ .Values.missing.deeply }}\n",
                    "deploy/deps/Chart.yaml": CHART.replace("web", "deps")
                    + "dependencies:\n  - name: sub\n    version: 1.0.0\n    repository: https://charts.example.com\n",
                    "deploy/deps/templates/x.yaml": "kind: ConfigMap\n",
                },
            )
            doc = self.scan(repo, Path(tmp) / "out")
        errors = {e["path"]: e["type"] for e in doc["unscanned"]["errors"]}
        self.assertEqual(errors["deploy/broken/templates/x.yaml"], helm.RENDER_FAILED)
        self.assertEqual(errors["deploy/deps/Chart.yaml"], helm.DEPENDENCIES_MISSING)
        self.assertIn("trivy.KSV-0017", {f["rule"] for f in doc["findings"]}, "the good chart is still checked")
        # A change to such a chart fails the check like any change to a file that was not scanned.
        result = compare(
            [], [], ("ERROR",), unscanned=doc["unscanned"], changed_files=["deploy/broken/templates/x.yaml"]
        )
        self.assertEqual([e["path"] for e in result.changed_unscanned], ["deploy/broken/templates/x.yaml"])

    def test_a_chart_with_a_link_is_not_rendered(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            self.chart(repo)
            (repo / "deploy/web/files").mkdir()
            (repo / "deploy/web/files/key").symlink_to("/etc/hosts")
            doc = self.scan(repo, Path(tmp) / "out")
        self.assertIn(helm.LINK_IN_CHART, {e["type"] for e in doc["unscanned"]["errors"]})
        self.assertFalse([f for f in doc["findings"] if f["path"].startswith("deploy/web/")])

    def test_rendering_reaches_no_network(self):
        hits = []
        with socket.socket() as server, tempfile.TemporaryDirectory() as tmp:
            server.bind(("127.0.0.1", 0))
            server.listen(5)
            server.settimeout(0.2)
            port = server.getsockname()[1]
            stop = threading.Event()

            def accept():
                while not stop.is_set():
                    try:
                        conn, _ = server.accept()
                        hits.append(1)
                        conn.close()
                    except OSError:
                        continue

            thread = threading.Thread(target=accept, daemon=True)
            thread.start()
            repo = Path(tmp) / "repo"
            self.chart(
                repo,
                {
                    "deploy/web/Chart.yaml": CHART
                    + f"dependencies:\n  - name: sub\n    version: 1.0.0\n    repository: http://127.0.0.1:{port}/c\n",
                },
            )
            doc = self.scan(repo, Path(tmp) / "out")
            stop.set()
            thread.join()
        self.assertEqual(hits, [])
        self.assertIn(helm.DEPENDENCIES_MISSING, {e["type"] for e in doc["unscanned"]["errors"]})


class FailClosedTests(unittest.TestCase):
    def test_charts_without_a_pinned_helm_fail_the_scan(self):
        from shoalscan import trivy

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, {"web/Chart.yaml": CHART})
            with self.assertRaises(SetupError):
                trivy._scan_charts(Path("/t/trivy"), root, root / "s", {}, (), (), None, {}, 1e12)


@unittest.skipUnless(tools_ready(), f"helm and trivy are not installed in {TOOLS}; run `shoalscan install`")
class BypassTests(unittest.TestCase):
    """The re-review's repros, on the real Helm and Trivy."""

    scan = EndToEndTests.scan
    chart = EndToEndTests.chart

    def privileged(self, doc: dict) -> list:
        return [(f["path"], f["line"]) for f in doc["findings"] if f["rule"] == "trivy.KSV-0017"]

    def test_a_crd_file_cannot_forge_a_header(self):
        crd = (
            '{"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition"}\n---\n'
            "# Source: web/templates/other.yaml\n"
            + POD.split("{{-")[0].replace("{{ .Release.Name }}", "x").replace("{{ .Values.image }}", "nginx:1.27")
        )
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            self.chart(
                repo,
                {
                    "deploy/web/templates/pod.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n",
                    "deploy/web/crds/x.json": crd,
                    "deploy/web/templates/other.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: o\n",
                },
            )
            doc = self.scan(repo, Path(tmp) / "out")
        # CRD files are not rendered (Trivy reads them as plain files), so nothing lands at the forged path.
        self.assertFalse([f for f in doc["findings"] if f["path"] == "deploy/web/templates/other.yaml"])
        self.assertNotIn("--include-crds", helm.build_command(Path("/h"), repo, []))

    def test_a_template_cannot_forge_a_header(self):
        forged = (
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n---\n# Source: web/templates/other.yaml\n" + POD
        )
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            self.chart(
                repo,
                {
                    "deploy/web/templates/pod.yaml": forged,
                    "deploy/web/templates/other.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: o\n",
                    ".shoalscan.toml": 'scanners = ["trivy"]\nexcludes = ["deploy/web/templates/other.yaml"]\n',
                },
            )
            doc = self.scan(repo, Path(tmp) / "out")
        self.assertEqual(self.privileged(doc), [("deploy/web/templates/pod.yaml", 1)])

    def test_an_excluded_template_reports_at_chart_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            self.chart(repo, {".shoalscan.toml": 'scanners = ["trivy"]\nexcludes = ["deploy/web/templates"]\n'})
            doc = self.scan(repo, Path(tmp) / "out")
        self.assertEqual(self.privileged(doc), [("deploy/web/Chart.yaml", 1)])

    def test_a_comment_line_inside_a_quoted_scalar_is_left_alone(self):
        quoted = POD.replace(
            "metadata:\n  name: {{ .Release.Name }}-web\n",
            "metadata:\n  name: {{ .Release.Name }}-web\n  annotations:\n"
            '    note: "first\n# not a comment\n    last"\n',
        )
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            self.chart(repo, {"deploy/web/templates/pod.yaml": quoted})
            doc = self.scan(repo, Path(tmp) / "out")
        self.assertEqual(self.privileged(doc), [("deploy/web/templates/pod.yaml", 1)])

    def test_a_template_that_renders_a_marker_is_blocked(self):
        marked = POD.replace(
            "    - name: web\n", '    - name: web  {{ printf "#%s:%s:KSV-0017" "tri" "vy:ignore" }}\n'
        ).replace("spec:\n", '  # {{ printf "%s%s:%s:*" "tri" "vy" "ignore" }}\nspec:\n')
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            self.chart(repo, {"deploy/web/templates/pod.yaml": marked})
            doc = self.scan(repo, Path(tmp) / "out")
        self.assertEqual(self.privileged(doc), [])
        errors = {e["path"]: e["type"] for e in doc["unscanned"]["errors"]}
        self.assertEqual(errors.get("deploy/web/templates/pod.yaml"), helm.MARKER_IN_OUTPUT)
        result = compare([], [], ("ERROR",), unscanned=doc["unscanned"], changed_files=["deploy/web/values.yaml"])
        self.assertEqual([e["path"] for e in result.changed_unscanned], ["deploy/web/values.yaml"])

    def test_a_render_that_needs_too_much_memory_or_time_is_not_scanned(self):
        for patch, template in (
            ({"MAX_RENDER_MEMORY": 64 * 1024 * 1024}, '{{ $s := repeat 400000000 "x" }}{{ len $s }}\n'),
            ({"RENDER_TIMEOUT_SECONDS": 1}, "{{ range $i := until 50000000 }}{{ end }}\n"),
        ):
            with self.subTest(patch=patch), tempfile.TemporaryDirectory() as tmp, mock.patch.multiple(helm, **patch):
                repo = Path(tmp) / "repo"
                self.chart(repo, {"deploy/web/templates/big.yaml": template})
                doc = self.scan(repo, Path(tmp) / "out")
                errors = {e["path"]: e["type"] for e in doc["unscanned"]["errors"]}
                self.assertEqual(errors.get("deploy/web/templates/big.yaml"), helm.RENDER_FAILED)


if __name__ == "__main__":
    unittest.main()
