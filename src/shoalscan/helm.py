"""Render Helm charts for Trivy, so that their Kubernetes manifests are checked.

Trivy's own Helm scanner is turned off (see `shoalscan.trivy`): it reads
ignore comments from the rendered chart, and a template can produce one at
render time where no check of the source can see it. Instead, Shoalscan
renders each chart itself with the pinned Helm, offline, and gives Trivy the
manifests with every comment line removed and every inline ignore marker
defused, so nothing a template writes can silence a check.

Each chart is a directory with a `Chart.yaml`, outside `.git` and the
excludes. Subcharts in a chart's `charts/` directory are rendered by their
parent, not on their own; library charts are not rendered. `helm template`
runs in the scanners' isolated environment, with Helm's cache, config, data
and plugin directories in the scan's private stage and no Kubernetes
configuration, so `lookup` finds nothing and no plugin or post-renderer
runs. Dependencies are never fetched: a chart whose dependencies are not in
its `charts/` directory is listed as not fully scanned, and so is a chart
that does not render, a chart that holds a symbolic link (Helm would follow
it out of the repository), or one with a values file that cannot be used.
Every file of such a chart is listed, so a pull request that changes one
fails the check, as for any file that was not scanned.

The values are the chart's own `values.yaml` and the files named for the
chart under `[trivy] helm_values` in `.shoalscan.toml`, which is policy.

Helm marks each rendered document with `# Source: <chart>/templates/<file>`;
findings are reported at that template, on its first line, and are
fingerprinted by the rule, the template and the resource's kind and name,
so they stay stable when unrelated template lines change.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from shoalscan import process
from shoalscan.errors import ScanError, SetupError
from shoalscan.excludes import ExcludeMatcher
from shoalscan.lockfile import verify_sha256
from shoalscan.suppressions import neutralise_trivy_markers, parse_trivy_line

TOOL = "helm"
CHART_FILE = "Chart.yaml"
MAX_RENDER_BYTES = 64 * 1024 * 1024
MAX_LISTED_FILES = 5000
RENDER_FAILED = "helm render failed"
DEPENDENCIES_MISSING = "helm chart dependencies missing"
LINK_IN_CHART = "helm chart holds a symbolic link"
BAD_VALUES = "helm values file unusable"
_LIBRARY = re.compile(r"^type:\s*['\"]?library['\"]?\s*$", re.MULTILINE)
_SOURCE = re.compile(r"^# Source: (\S.*?)\s*$")
_KIND = re.compile(r"^kind:\s*['\"]?([A-Za-z0-9]+)['\"]?\s*$")
_NAME = re.compile(r"^  name:\s*['\"]?([^'\"\s#]+)['\"]?\s*$")


@dataclass(frozen=True)
class Rendered:
    """Where a rendered document came from: its template in the repository, and its resource."""

    path: str
    resource: str
    chart: str


def find_charts(root: Path, excludes: tuple[str, ...]) -> list[str]:
    """The chart directories to render, repository-relative ("" for the root), outside .git and the excludes."""
    matcher = ExcludeMatcher(list(excludes))
    found = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        is_chart = CHART_FILE in filenames and not matcher.excluded(_join(rel_dir, CHART_FILE))
        # A chart's subcharts are rendered with it.
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d != ".git" and not (is_chart and d == "charts") and not matcher.excluded(_join(rel_dir, d))
        )
        if is_chart:
            try:
                text = (root / rel_dir / CHART_FILE).read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            if not _LIBRARY.search(text):
                found.append(rel_dir)
    return found


def _join(rel_dir: str, name: str) -> str:
    return f"{rel_dir}/{name}" if rel_dir else name


def _chart_files(root: Path, chart: str) -> tuple[list[str], bool]:
    """Every regular file of a chart (up to MAX_LISTED_FILES), and whether it holds a symbolic link."""
    files, link = [], False
    for dirpath, dirnames, filenames in os.walk(root / chart, followlinks=False):
        for name in [*dirnames, *filenames]:
            if os.path.islink(os.path.join(dirpath, name)):
                link = True
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if not os.path.islink(full) and len(files) < MAX_LISTED_FILES:
                files.append(Path(full).relative_to(root).as_posix())
        dirnames.sort()
    return sorted(files), link


def _values_files(root: Path, chart: str, values: dict[str, tuple[str, ...]]) -> list[Path]:
    out = []
    for rel in values.get(chart or ".", ()):
        path = root / rel
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"{rel} is not a regular file in the repository")
        out.append(path)
    return out


def helm_env(stage: Path) -> dict[str, str]:
    """Helm's own directories, all in the private stage; no Kubernetes configuration."""
    env = {}
    for var, sub in (
        ("HELM_CACHE_HOME", "cache"),
        ("HELM_CONFIG_HOME", "config"),
        ("HELM_DATA_HOME", "data"),
        ("HELM_PLUGINS", "plugins"),
    ):
        (stage / sub).mkdir(parents=True, exist_ok=True)
        env[var] = str(stage / sub)
    env["HELM_REGISTRY_CONFIG"] = str(stage / "config" / "registry.json")
    env["HELM_REPOSITORY_CONFIG"] = str(stage / "config" / "repositories.yaml")
    env["HELM_REPOSITORY_CACHE"] = str(stage / "cache" / "repository")
    env["KUBECONFIG"] = os.devnull
    env["HELM_KUBECONTEXT"] = ""
    return env


def build_command(binary: Path, chart_dir: Path, values: list[Path]) -> list[str]:
    cmd = [str(binary), "template", "release", str(chart_dir), "--namespace", "default", "--include-crds"]
    for path in values:
        cmd += ["--values", str(path)]
    return cmd


def split_documents(text: str) -> list[tuple[str | None, list[str]]]:
    """The rendered output as (source template, lines) per YAML document."""
    docs: list[tuple[str | None, list[str]]] = []
    source, lines = None, []
    for line in text.split("\n"):
        if line.rstrip() == "---":
            docs.append((source, lines))
            source, lines = None, []
            continue
        match = _SOURCE.match(line)
        if match and source is None:
            source = match.group(1)
        lines.append(line)
    docs.append((source, lines))
    return [(s, ls) for s, ls in docs if any(ln.strip() and not ln.lstrip().startswith("#") for ln in ls)]


def clean(lines: list[str]) -> str:
    """A document Trivy may read: no comment lines, and no inline ignore marker left working."""
    kept = [neutralise_trivy_markers(line) for line in lines if not line.lstrip().startswith("#")]
    if any(parse_trivy_line(line) for line in kept):
        raise ScanError("a rendered Helm chart still holds a Trivy marker after cleaning")
    return "\n".join(kept).strip("\n") + "\n"


def resource(lines: list[str]) -> str:
    kind, name, in_metadata = "", "", False
    for line in lines:
        if match := _KIND.match(line):
            kind = kind or match.group(1)
        if line.startswith("metadata:"):
            in_metadata = True
            continue
        if in_metadata and line and not line.startswith(" "):
            in_metadata = False
        if in_metadata and not name and (match := _NAME.match(line)):
            name = match.group(1)
    return f"{kind}/{name}" if kind or name else ""


def template_path(root: Path, chart: str, source: str | None) -> str:
    """The repository path of a document's template, or the chart's Chart.yaml when it cannot be told."""
    fallback = _join(chart, CHART_FILE)
    if not source:
        return fallback
    parts = source.split("/")
    if len(parts) < 2 or any(p in ("", ".", "..") for p in parts):
        return fallback
    rel = _join(chart, "/".join(parts[1:]))
    path = root / rel
    return rel if path.is_file() and not path.is_symlink() else fallback


def render(
    binary: Path,
    binary_sha256: str,
    root: Path,
    stage: Path,
    charts: list[str],
    values: dict[str, tuple[str, ...]],
    timeout: int,
) -> tuple[Path, dict[str, Rendered], list[dict]]:
    """Render every chart into `stage/rendered`.

    Returns that directory, where each rendered document came from (by its
    path under the directory), and the unscanned entries of charts that
    could not be rendered.
    """
    if not binary.is_file():
        raise SetupError(f"helm is not installed: {binary} (run `shoalscan install`)")
    verify_sha256(binary, binary_sha256)
    out = stage / "rendered"
    out.mkdir(parents=True)
    env = helm_env(stage / "home")
    mapping: dict[str, Rendered] = {}
    errors: list[dict] = []
    for index, chart in enumerate(charts):
        files, link = _chart_files(root, chart)

        def unscanned(kind: str, message: str, files: list[str] = files) -> None:
            errors.extend({"path": f, "type": kind, "message": message[:400]} for f in files)

        if link:
            unscanned(LINK_IN_CHART, "Helm follows links out of the chart, so the chart is not rendered")
            continue
        try:
            value_files = _values_files(root, chart, values)
        except ValueError as exc:
            unscanned(BAD_VALUES, str(exc))
            continue
        code, stdout, stderr = process.run_scanner(
            TOOL,
            build_command(binary, root / chart if chart else root, value_files),
            stage,
            timeout,
            max_stdout=MAX_RENDER_BYTES,
            extra_env=env,
        )
        if code != 0:
            summary = process.error_summary(stderr.replace(f"{root}/", ""), 400)
            missing = "missing in charts/" in stderr or ("dependencies" in stderr and "charts/" in stderr)
            unscanned(DEPENDENCIES_MISSING if missing else RENDER_FAILED, summary)
            continue
        try:
            text = stdout.decode("utf-8")
        except UnicodeDecodeError:
            raise ScanError(f"helm rendered {chart or 'the root chart'} as text that is not UTF-8") from None
        chart_dir = out / str(index)
        chart_dir.mkdir()
        for number, (source, lines) in enumerate(split_documents(text)):
            name = f"{index}/{number}.yaml"
            (out / name).write_text(clean(lines), encoding="utf-8")
            mapping[name] = Rendered(template_path(root, chart, source), resource(lines), chart)
    return out, mapping, errors
