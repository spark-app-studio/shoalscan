"""Load and strictly validate `.shoalscan.toml`.

Unknown keys are errors, so a typo never silently turns a setting off.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from shoalscan.errors import SetupError

CONFIG_NAME = ".shoalscan.toml"
SEVERITIES = ("ERROR", "WARNING", "INFO")
KNOWN_SCANNERS = ("opengrep", "gitleaks", "hadolint", "zizmor", "trivy")
_CATEGORY_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_RULE_PATTERN_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-/]*(\.\*)?$")
# parse_warn_only globs: plain path characters and the * ? wildcards only.
_PARSE_GLOB_RE = re.compile(r"^[A-Za-z0-9_.\-/*?]+$")
# The file name part of a parse_warn_only glob: a plain file name
# (`Dockerfile`), a name with any extension (`Dockerfile.*`), or any name
# with one extension (`*.sh`, `*.min.js`).
_FILE_NAME_RE = re.compile(r"^(?:[A-Za-z0-9_][A-Za-z0-9_.\-]*(?:\.\*)?|\*(?:\.[A-Za-z0-9_\-]+)+)$")
_DIR_SEGMENT_RE = re.compile(r"^(?:\*\*|\*|[A-Za-z0-9_.\-]+)$")
_HADOLINT_RULE_RE = re.compile(r"^(?:DL|SC)\d{4}$")
_ZIZMOR_AUDIT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,99}$")
_TRIVY_CHECK_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d{3,5}$")


@dataclass(frozen=True)
class OpengrepSettings:
    community_rules: bool = True
    shoalscan_rules: bool = True
    rule_dirs: tuple[str, ...] = ()
    # Applied to the community snapshot only. Rules without a category count
    # as "uncategorised".
    categories: tuple[str, ...] = ("security",)
    # Exact rule ids, or `prefix.*`. Applied to every rule source.
    exclude_rules: tuple[str, ...] = ()


@dataclass(frozen=True)
class HadolintSettings:
    # Hadolint and ShellCheck rule codes to leave out, such as DL3008.
    ignore: tuple[str, ...] = ()


@dataclass(frozen=True)
class ZizmorSettings:
    # zizmor audits to leave out, such as artipacked.
    ignore: tuple[str, ...] = ()


@dataclass(frozen=True)
class TrivySettings:
    # Trivy check ids to leave out, such as AWS-0089 or KSV-0011.
    ignore: tuple[str, ...] = ()
    # Extra values files for Helm, by chart directory ("." for a chart at the root); repository-relative.
    helm_values: tuple[tuple[str, tuple[str, ...]], ...] = ()

    def helm_values_map(self) -> dict[str, tuple[str, ...]]:
        return dict(self.helm_values)


@dataclass(frozen=True)
class TestScopeSettings:
    """Rules whose findings in proven test-only Rust code do not block (see docs/test-scope.md)."""

    __test__ = False  # not a unittest class

    # Exact Opengrep rule ids, or `prefix.*`, as in opengrep.exclude_rules. Empty: the feature is off.
    non_blocking: tuple[str, ...] = ()


# Rule id namespaces whose findings can be test-scoped: Opengrep's rule sources.
TEST_SCOPE_NAMESPACES = ("community", "shoalscan", "repo")


@dataclass(frozen=True)
class Limits:
    scan_timeout_seconds: int = 1800
    rule_timeout_seconds: int = 30
    max_target_bytes: int = 1_000_000
    jobs: int = 4


@dataclass(frozen=True)
class Config:
    scanners: tuple[str, ...] = ("opengrep",)
    excludes: tuple[str, ...] = ()
    blocking: tuple[str, ...] = ("ERROR", "WARNING")
    baseline: str = ".shoalscan/baseline.toml"
    non_blocking_paths: tuple[str, ...] = ()
    # Globs of changed files whose PartialParsing gaps only warn, for
    # languages whose Opengrep parser is experimental.
    parse_warn_only: tuple[str, ...] = ()
    components: dict[str, str] = field(default_factory=dict)
    opengrep: OpengrepSettings = OpengrepSettings()
    hadolint: HadolintSettings = HadolintSettings()
    zizmor: ZizmorSettings = ZizmorSettings()
    trivy: TrivySettings = TrivySettings()
    test_scope: TestScopeSettings = TestScopeSettings()
    limits: Limits = Limits()
    source: str = "defaults"


def _check_keys(table: dict, allowed: set[str], where: str) -> None:
    unknown = set(table) - allowed
    if unknown:
        raise SetupError(f"{CONFIG_NAME}: unknown keys in {where}: {', '.join(sorted(unknown))}")


def _str_list(value: object, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(x, str) and x.strip() for x in value):
        raise SetupError(f"{CONFIG_NAME}: {where} must be a list of non-empty strings")
    for item in value:
        if any(ch in item for ch in "\n\r\0"):
            raise SetupError(f"{CONFIG_NAME}: {where} contains a control character")
    return tuple(value)


def _bool(value: object, where: str) -> bool:
    if not isinstance(value, bool):
        raise SetupError(f"{CONFIG_NAME}: {where} must be true or false")
    return value


def _int(value: object, where: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise SetupError(f"{CONFIG_NAME}: {where} must be an integer from {low} to {high}")
    return value


def relative_repo_path(value: str, where: str) -> str:
    """Accept only a relative path that stays inside the repository."""
    path = PurePosixPath(value)
    if path.is_absolute() or "\\" in value or ".." in path.parts or not path.parts:
        raise SetupError(f"{CONFIG_NAME}: {where} must be a relative path inside the repository: {value!r}")
    return path.as_posix()


_LITERAL_RUN = re.compile(r"[A-Za-z0-9_.\-]{4,}")


def _anchors(segment: str) -> bool:
    """Does this path segment pin a pattern down? A plain name does, and so does a
    wildcard with a literal prefix or suffix (`*.h`, `build*`) or a long literal
    part (`*redteam*`); `*`, `**`, `?` and `*e*` do not."""
    if not re.search(r"[A-Za-z0-9]", segment):
        return False
    if not any(c in segment for c in "*?["):
        return True
    if not (segment.startswith(("*", "?")) and segment.endswith(("*", "?"))):
        return True
    return bool(_LITERAL_RUN.search(segment))


def _exclude_pattern(value: str) -> str:
    """An exclude must name something: a pattern such as ** or *e* would turn the scan off."""
    if any(c in value for c in "[]{}"):
        raise SetupError(
            f"{CONFIG_NAME}: the exclude {value!r} uses [ ] or {{ }}; character classes and alternatives are not "
            "allowed, "
            "because patterns such as [a-z]* or [!0]* match almost everything. List each pattern explicitly instead"
        )
    if ".." in value.split("/"):
        raise SetupError(
            f"{CONFIG_NAME}: the exclude {value!r} has a .. segment; excludes are paths inside the repository"
        )
    segments = [s for s in value.strip().strip("/").split("/") if s]
    if not any(_anchors(s) for s in segments):
        raise SetupError(
            f"{CONFIG_NAME}: the exclude {value!r} could match every file, which would turn scanning off; "
            "name the directories or files it covers, such as vendor, **/fixtures/** or *.min.js"
        )
    return value


def _parse_glob(value: str) -> str:
    """A parse_warn_only glob: a relative path pattern that cannot match everything."""
    where = f"parse_warn_only entry {value!r}"
    if not _PARSE_GLOB_RE.match(value):
        raise SetupError(f"{CONFIG_NAME}: {where} may use only letters, digits, . _ - / and the wildcards * and ?")
    if value.startswith("/") or ".." in value.split("/") or "//" in value or "***" in value:
        raise SetupError(f"{CONFIG_NAME}: {where} must be a relative path pattern inside the repository")
    *dirs, name = value.split("/")
    if not _FILE_NAME_RE.match(name) or not re.search(r"[A-Za-z0-9]", name):
        raise SetupError(
            f"{CONFIG_NAME}: {where} must end in a file name or extension, such as Dockerfile, Dockerfile.*, *.sh "
            "or deploy/**/templates/*.yaml; patterns such as *e* or ** could cover any file"
        )
    if any(not _DIR_SEGMENT_RE.match(d) or d in (".", "..") for d in dirs):
        raise SetupError(f"{CONFIG_NAME}: {where} has a directory part that is not a plain name, * or **")
    return value


def parse_config(data: dict, source: str = CONFIG_NAME) -> Config:
    _check_keys(
        data,
        {
            "scanners",
            "excludes",
            "blocking",
            "baseline",
            "non_blocking_paths",
            "parse_warn_only",
            "components",
            "opengrep",
            "hadolint",
            "zizmor",
            "trivy",
            "test_scope",
            "limits",
        },
        "the top level",
    )
    defaults = Config()

    scanners = _str_list(data.get("scanners", list(defaults.scanners)), "scanners")
    for name in scanners:
        if name not in KNOWN_SCANNERS:
            raise SetupError(f"{CONFIG_NAME}: unknown scanner {name!r} (known: {', '.join(KNOWN_SCANNERS)})")
    if not scanners:
        raise SetupError(f"{CONFIG_NAME}: scanners must not be empty")

    excludes = tuple(_exclude_pattern(p) for p in _str_list(data.get("excludes", []), "excludes"))

    blocking = _str_list(data.get("blocking", list(defaults.blocking)), "blocking")
    for sev in blocking:
        if sev not in SEVERITIES:
            raise SetupError(f"{CONFIG_NAME}: blocking severity must be one of {', '.join(SEVERITIES)}: {sev!r}")
    if "INFO" in blocking:
        raise SetupError(f"{CONFIG_NAME}: INFO findings never block; remove INFO from blocking")
    if "ERROR" not in blocking:
        raise SetupError(f"{CONFIG_NAME}: blocking must include ERROR")

    baseline = data.get("baseline", defaults.baseline)
    if not isinstance(baseline, str):
        raise SetupError(f"{CONFIG_NAME}: baseline must be a string path")
    baseline = relative_repo_path(baseline, "baseline")

    non_blocking_paths = tuple(
        relative_repo_path(p, "non_blocking_paths")
        for p in _str_list(data.get("non_blocking_paths", []), "non_blocking_paths")
    )

    parse_warn_only = tuple(_parse_glob(g) for g in _str_list(data.get("parse_warn_only", []), "parse_warn_only"))

    components_raw = data.get("components", {})
    if not isinstance(components_raw, dict):
        raise SetupError(f"{CONFIG_NAME}: [components] must be a table of path prefix = name")
    components: dict[str, str] = {}
    for prefix, name in components_raw.items():
        if not isinstance(name, str) or not name.strip():
            raise SetupError(f"{CONFIG_NAME}: component name for {prefix!r} must be a non-empty string")
        components[relative_repo_path(prefix, f"components key {prefix!r}")] = name

    og_raw = data.get("opengrep", {})
    if not isinstance(og_raw, dict):
        raise SetupError(f"{CONFIG_NAME}: [opengrep] must be a table")
    _check_keys(
        og_raw, {"community_rules", "shoalscan_rules", "rule_dirs", "categories", "exclude_rules"}, "[opengrep]"
    )
    categories = _str_list(og_raw.get("categories", list(OpengrepSettings().categories)), "opengrep.categories")
    for cat in categories:
        if not _CATEGORY_RE.match(cat):
            raise SetupError(f"{CONFIG_NAME}: opengrep.categories has an invalid category: {cat!r}")
    exclude_rules = _str_list(og_raw.get("exclude_rules", []), "opengrep.exclude_rules")
    for pattern in exclude_rules:
        if not _RULE_PATTERN_RE.match(pattern) or "*" in pattern[:-2]:
            raise SetupError(
                f"{CONFIG_NAME}: opengrep.exclude_rules entries must be a rule id or `prefix.*`: {pattern!r}"
            )
    rule_dirs = tuple(
        relative_repo_path(d, "opengrep.rule_dirs")
        for d in _str_list(og_raw.get("rule_dirs", []), "opengrep.rule_dirs")
    )
    opengrep = OpengrepSettings(
        community_rules=_bool(og_raw.get("community_rules", True), "opengrep.community_rules"),
        shoalscan_rules=_bool(og_raw.get("shoalscan_rules", True), "opengrep.shoalscan_rules"),
        rule_dirs=rule_dirs,
        categories=tuple(c.lower() for c in categories),
        exclude_rules=exclude_rules,
    )
    if opengrep.community_rules and not opengrep.categories:
        raise SetupError(f"{CONFIG_NAME}: opengrep.categories is empty; set community_rules = false instead")
    if not (opengrep.community_rules or opengrep.shoalscan_rules or opengrep.rule_dirs):
        raise SetupError(f"{CONFIG_NAME}: [opengrep] enables no rules")

    ha_raw = data.get("hadolint", {})
    if not isinstance(ha_raw, dict):
        raise SetupError(f"{CONFIG_NAME}: [hadolint] must be a table")
    _check_keys(ha_raw, {"ignore"}, "[hadolint]")
    ignore = _str_list(ha_raw.get("ignore", []), "hadolint.ignore")
    for code in ignore:
        if not _HADOLINT_RULE_RE.match(code):
            raise SetupError(
                f"{CONFIG_NAME}: hadolint.ignore entries must be rule codes such as DL3008 or SC2086: {code!r}"
            )
    hadolint = HadolintSettings(ignore=tuple(sorted(set(ignore))))

    zi_raw = data.get("zizmor", {})
    if not isinstance(zi_raw, dict):
        raise SetupError(f"{CONFIG_NAME}: [zizmor] must be a table")
    _check_keys(zi_raw, {"ignore"}, "[zizmor]")
    audits = _str_list(zi_raw.get("ignore", []), "zizmor.ignore")
    for audit in audits:
        if not _ZIZMOR_AUDIT_RE.match(audit):
            raise SetupError(f"{CONFIG_NAME}: zizmor.ignore entries must be audit names such as artipacked: {audit!r}")
    zizmor = ZizmorSettings(ignore=tuple(sorted(set(audits))))

    tr_raw = data.get("trivy", {})
    if not isinstance(tr_raw, dict):
        raise SetupError(f"{CONFIG_NAME}: [trivy] must be a table")
    _check_keys(tr_raw, {"ignore", "helm_values"}, "[trivy]")
    checks = _str_list(tr_raw.get("ignore", []), "trivy.ignore")
    for check in checks:
        if not _TRIVY_CHECK_RE.match(check):
            raise SetupError(
                f"{CONFIG_NAME}: trivy.ignore entries must be check ids such as AWS-0089 or KSV-0011: {check!r}"
            )
    hv_raw = tr_raw.get("helm_values", {})
    if not isinstance(hv_raw, dict):
        raise SetupError(f"{CONFIG_NAME}: [trivy.helm_values] must be a table of chart directory = [values files]")
    helm_values = []
    for chart, files in sorted(hv_raw.items()):
        chart_dir = "." if chart == "." else relative_repo_path(chart, f"trivy.helm_values key {chart!r}")
        paths = tuple(
            relative_repo_path(f, f"trivy.helm_values.{chart}") for f in _str_list(files, f"trivy.helm_values.{chart}")
        )
        helm_values.append((chart_dir, paths))
    trivy = TrivySettings(ignore=tuple(sorted(set(checks))), helm_values=tuple(helm_values))

    test_scope = _test_scope(data.get("test_scope", {}))

    lim_raw = data.get("limits", {})
    if not isinstance(lim_raw, dict):
        raise SetupError(f"{CONFIG_NAME}: [limits] must be a table")
    _check_keys(lim_raw, {"scan_timeout_seconds", "rule_timeout_seconds", "max_target_bytes", "jobs"}, "[limits]")
    lim_default = Limits()
    limits = Limits(
        scan_timeout_seconds=_int(
            lim_raw.get("scan_timeout_seconds", lim_default.scan_timeout_seconds),
            "limits.scan_timeout_seconds",
            10,
            86_400,
        ),
        rule_timeout_seconds=_int(
            lim_raw.get("rule_timeout_seconds", lim_default.rule_timeout_seconds),
            "limits.rule_timeout_seconds",
            1,
            3_600,
        ),
        max_target_bytes=_int(
            lim_raw.get("max_target_bytes", lim_default.max_target_bytes), "limits.max_target_bytes", 1_000, 100_000_000
        ),
        jobs=_int(lim_raw.get("jobs", lim_default.jobs), "limits.jobs", 1, 64),
    )

    return Config(
        scanners=scanners,
        excludes=excludes,
        blocking=blocking,
        baseline=baseline,
        non_blocking_paths=non_blocking_paths,
        parse_warn_only=parse_warn_only,
        components=components,
        opengrep=opengrep,
        hadolint=hadolint,
        zizmor=zizmor,
        trivy=trivy,
        test_scope=test_scope,
        limits=limits,
        source=source,
    )


def _test_scope(raw: object) -> TestScopeSettings:
    """`[test_scope]`: Opengrep rules only. A secret is a leak wherever it is, so Gitleaks rules are refused."""
    from shoalscan.suppressions import LINT_RULE

    if not isinstance(raw, dict):
        raise SetupError(f"{CONFIG_NAME}: [test_scope] must be a table")
    _check_keys(raw, {"non_blocking"}, "[test_scope]")
    rules = _str_list(raw.get("non_blocking", []), "test_scope.non_blocking")
    for pattern in rules:
        namespace = pattern.split(".", 1)[0]
        if namespace == "gitleaks" or pattern.startswith("gitleaks"):
            raise SetupError(
                f"{CONFIG_NAME}: test_scope.non_blocking cannot list the Gitleaks rule {pattern!r}: a real secret in "
                "test code is still a leaked secret. Rotate it, or record a false positive in the baseline"
            )
        if not _RULE_PATTERN_RE.match(pattern) or "*" in pattern[:-2]:
            raise SetupError(
                f"{CONFIG_NAME}: test_scope.non_blocking entries must be a rule id or `prefix.*`: {pattern!r}"
            )
        if namespace not in TEST_SCOPE_NAMESPACES or "." not in pattern:
            raise SetupError(
                f"{CONFIG_NAME}: test_scope.non_blocking lists {pattern!r}, which is not an Opengrep rule; only "
                f"Opengrep rules ({', '.join(n + '.' for n in TEST_SCOPE_NAMESPACES)}...) are eligible, and only "
                "their findings in Rust files"
            )
        if pattern == LINT_RULE:
            raise SetupError(
                f"{CONFIG_NAME}: test_scope.non_blocking cannot list {LINT_RULE}: an inline suppression must name a "
                "rule and an issue in test code too"
            )
    return TestScopeSettings(non_blocking=tuple(sorted(set(rules))))


def config_from_bytes(data: bytes, source: str) -> Config:
    try:
        parsed = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError) as exc:
        raise SetupError(f"{source}: not valid TOML: {exc}") from None
    return parse_config(parsed, source=source)


def load_config(path: Path) -> Config:
    """Load the configuration. A missing file means the defaults."""
    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError:
        return Config()
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        raise SetupError(f"{path}: not valid TOML: {exc}") from None
    return parse_config(data, source=str(path))


def under_prefix(path: str, prefixes: tuple[str, ...]) -> bool:
    """True if a repository-relative path is one of the prefixes or inside one."""
    for prefix in prefixes:
        stem = prefix.rstrip("/")
        if path == stem or path.startswith(stem + "/"):
            return True
    return False


def component_for(path: str, components: dict[str, str]) -> str:
    """Map a repository-relative path to a component by the longest matching prefix."""
    best = ""
    best_name = "other"
    for prefix, name in components.items():
        stem = prefix.rstrip("/")
        if (path == stem or path.startswith(stem + "/")) and len(stem) > len(best):
            best, best_name = stem, name
    return best_name
