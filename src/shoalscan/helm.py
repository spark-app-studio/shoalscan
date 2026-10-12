"""Render Helm charts for Trivy, so that their Kubernetes manifests are checked.

Trivy's own Helm scanner is turned off (see `shoalscan.trivy`): it reads
ignore comments from the rendered chart, and a template can produce one at
render time where no check of the source can see it. Instead, Shoalscan
renders each chart itself with the pinned Helm, offline, and gives Trivy the
manifests unchanged (there is no YAML parser here to edit them safely). A
chart whose output holds anything like an inline ignore marker, in a
comment or in data, is not scanned at all; it is listed as not fully
scanned, which blocks a change to it. So nothing a template writes can
silence a check. CRDs are not rendered: Helm prints `crds/` files verbatim,
and Trivy reads them directly instead.

Each chart is a directory with a `Chart.yaml`, outside `.git` and the
excludes. Subcharts in a chart's `charts/` directory are rendered by their
parent, not on their own; library charts are not rendered. `helm template`
runs in the scanners' isolated environment, with Helm's cache, config, data
and plugin directories in the scan's private stage and no Kubernetes
configuration, so `lookup` finds nothing and no plugin or post-renderer
runs. Dependencies are never fetched: a chart whose dependencies are not in
its `charts/` directory is listed as not fully scanned, and so is a chart
that does not render (or not within RENDER_TIMEOUT_SECONDS and
MAX_RENDER_MEMORY), a chart that holds a symbolic link (Helm would follow
it out of the repository), or one with a values file that cannot be used.
Every file of such a chart is listed, so a pull request that changes one
fails the check, as for any file that was not scanned.

The values are the chart's own `values.yaml` and the files named for the
chart under `[trivy] helm_values` in `.shoalscan.toml`, which is policy.

Helm puts `# Source: <chart>/templates/<file>` on the first line of every
rendered document, and only that line is trusted. Findings are reported at
that template (under the chart's or a subchart's `templates/`, and not
excluded; otherwise at the chart's Chart.yaml), on its first line, and are
fingerprinted by the rule, the template path and the resource's kind and
name, so they stay stable when unrelated template lines change.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from shoalscan import process
from shoalscan.errors import ScanError, SetupError
from shoalscan.excludes import ExcludeMatcher
from shoalscan.lockfile import verify_sha256
from shoalscan.suppressions import parse_trivy_line

TOOL = "helm"
CHART_FILE = "Chart.yaml"
MAX_RENDER_BYTES = 64 * 1024 * 1024
MAX_LISTED_FILES = 5000
RENDER_FAILED = "helm render failed"
DEPENDENCIES_MISSING = "helm chart dependencies missing"
LINK_IN_CHART = "helm chart holds a symbolic link"
BAD_VALUES = "helm values file unusable"
MARKER_IN_OUTPUT = "rendered output contains an inline-ignore marker"
# Each chart renders within these, or it is not scanned. Overridable for tests.
RENDER_TIMEOUT_SECONDS = 60
MAX_RENDER_MEMORY = 512 * 1024 * 1024
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
    """Every regular file of a chart, and whether it holds a symbolic link.

    A chart with more files than can be listed fails the scan, so a chart
    that is not scanned is never only partly listed.
    """
    files, link = [], False
    for dirpath, dirnames, filenames in os.walk(root / chart, followlinks=False):
        for name in [*dirnames, *filenames]:
            if os.path.islink(os.path.join(dirpath, name)):
                link = True
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if not os.path.islink(full):
                files.append(Path(full).relative_to(root).as_posix())
        dirnames.sort()
    if len(files) > MAX_LISTED_FILES:
        raise ScanError(f"the Helm chart {chart or '.'} has more than {MAX_LISTED_FILES} files; exclude it or split it")
    return sorted(files), link


def _inside_without_links(root: Path, rel: str) -> Path:
    """`root/rel` if it is a regular file reached without following any link, else ValueError."""
    path = root
    for part in Path(rel).parts:
        path = path / part
        try:
            st = os.lstat(path)
        except OSError:
            raise ValueError(f"{rel} is not a regular file in the repository") from None
        if stat.S_ISLNK(st.st_mode):
            raise ValueError(f"{rel} is reached through a symbolic link")
    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise ValueError(f"{rel} is not a regular file in the repository")
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        raise ValueError(f"{rel} is outside the repository") from None
    return path


def _values_files(root: Path, chart: str, values: dict[str, tuple[str, ...]]) -> list[Path]:
    return [_inside_without_links(root, rel) for rel in values.get(chart or ".", ())]


def helm_env(stage: Path) -> dict[str, str]:
    """Helm's own directories, all in the private stage; no Kubernetes configuration; a soft memory limit."""
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
    env["GOMEMLIMIT"] = f"{MAX_RENDER_MEMORY // (1024 * 1024)}MiB"
    return env


def build_command(binary: Path, chart_dir: Path, values: list[Path]) -> list[str]:
    # No --include-crds: Helm prints CRD files verbatim, so they could forge a document header.
    # Trivy reads the chart's crds/ files directly, as plain files of the repository.
    cmd = [str(binary), "template", "release", str(chart_dir), "--namespace", "default"]
    for path in values:
        cmd += ["--values", str(path)]
    return cmd


def split_documents(text: str) -> list[tuple[str | None, str]]:
    """The rendered output as (source template, text) per YAML document.

    Helm splits every template's output at each `---` and puts its own
    `# Source:` header on the first line of every piece, so only that first
    line is trusted; a `# Source:` line further down is the template's own text.
    """
    docs: list[tuple[str | None, str]] = []
    for chunk in re.split(r"(?m)^---[ \t]*$\n?", text):
        lines = chunk.split("\n")
        first = next((line for line in lines if line.strip()), "")
        match = _SOURCE.match(first)
        if any(line.strip() and not line.lstrip().startswith("#") for line in lines):
            docs.append((match.group(1) if match else None, chunk))
    return docs


# A deliberate superset of what Trivy 0.74.0 reads as an inline ignore: either prefix, then
# "ignore" anywhere later on the line, in any case and with any spacing.
_MARKER_LIKE = re.compile(r"(?i)(?:trivy|tf\s*sec)\s*:.*?ignore")


def holds_marker(text: str) -> bool:
    return any(_MARKER_LIKE.search(line) or parse_trivy_line(line) for line in text.split("\n"))


def resource(text: str) -> str:
    kind, name, in_metadata = "", "", False
    for line in text.split("\n"):
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


_TEMPLATE = re.compile(r"^[^/]+/((?:charts/[^/]+/)*templates/.+)$")


def template_path(root: Path, chart: str, source: str | None, excludes: tuple[str, ...] = ()) -> str:
    """The repository path of a document's template: a file under the chart's (or a subchart's)
    `templates/`, not excluded. Anything else, or no header, is the chart's Chart.yaml."""
    fallback = _join(chart, CHART_FILE)
    match = _TEMPLATE.match(source or "")
    if not match or any(p in ("", ".", "..") for p in match.group(1).split("/")):
        return fallback
    rel = _join(chart, match.group(1))
    path = root / rel
    if ExcludeMatcher(list(excludes)).excluded(rel) or path.is_symlink() or not path.is_file():
        return fallback
    return rel


def render(
    binary: Path,
    binary_sha256: str,
    root: Path,
    stage: Path,
    charts: list[str],
    values: dict[str, tuple[str, ...]],
    timeout: int,
    excludes: tuple[str, ...] = (),
) -> tuple[Path, dict[str, Rendered], list[dict]]:
    """Render every chart into `stage/rendered`, unchanged.

    Returns that directory, where each rendered document came from (by its
    path under the directory), and the unscanned entries of charts that
    could not be rendered or whose output holds anything like an ignore marker.
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
        try:
            code, stdout, stderr = process.run_scanner(
                TOOL,
                build_command(binary, root / chart if chart else root, value_files),
                stage,
                min(timeout, RENDER_TIMEOUT_SECONDS),
                max_stdout=MAX_RENDER_BYTES,
                extra_env=env,
                max_memory=MAX_RENDER_MEMORY,
            )
        except ScanError as exc:
            # Too slow, too big or killed: this chart is not scanned, and says why.
            unscanned(RENDER_FAILED, process.error_summary(str(exc).replace(f"{root}/", ""), 400))
            continue
        if code != 0:
            summary = process.error_summary(stderr.replace(f"{root}/", ""), 400)
            missing = "missing in charts/" in stderr or ("dependencies" in stderr and "charts/" in stderr)
            unscanned(DEPENDENCIES_MISSING if missing else RENDER_FAILED, summary)
            continue
        try:
            text = stdout.decode("utf-8")
        except UnicodeDecodeError:
            unscanned(RENDER_FAILED, "Helm rendered text that is not UTF-8")
            continue
        if holds_marker(text):
            unscanned(
                MARKER_IN_OUTPUT, "the rendered output contains an inline-ignore marker, so Trivy is not run on it"
            )
            continue
        (out / str(index)).mkdir()
        for number, (source, doc) in enumerate(split_documents(text)):
            name = f"{index}/{number}.yaml"
            (out / name).write_text(doc, encoding="utf-8")
            mapping[name] = Rendered(template_path(root, chart, source, excludes), resource(doc), chart)
    return out, mapping, errors
