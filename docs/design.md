# Shoalscan design

## Goals

1. Run several security scanners over a repository as one CI step, on every pull request.
2. Fail a pull request only on findings it introduces, compared with a recorded baseline.
3. Record every run so a dashboard can tell the story of the codebase's security over time.
4. Help people triage and fix findings, and produce a security report.
5. Work with any repository, on any CI system, including self-hosted runners.

## Principles

- **Pinned and verified.** Every scanner binary is pinned by version and SHA-256 in `tools.lock`. Where the project publishes signatures (Opengrep signs with cosign), the signature is checked against the project's release workflow identity. There is no `curl | bash`.
- **Offline at scan time.** Scans use local rules and local binaries only. Nothing is fetched while scanning.
- **No credentials on the runner.** Shoalscan never needs a GitHub token or any other secret to scan, record or serve the dashboard. Triage and fixing happen on a developer machine.
- **Fail closed.** A scanner that crashes, times out or cannot parse its output fails the run. It is never read as "no findings".
- **No silent suppression.** An inline suppression must name the rule and an issue. Suppressions are counted and shown on the dashboard, so silencing never looks like fixing.
- **Python standard library only** for the CLI and the dashboard, so it installs anywhere Python 3.11 or later runs.

## Repository configuration: `.shoalscan.toml`

Each repository that uses Shoalscan keeps one configuration file at its root. It sets:

- **Scanners:** which ones run, and their rule directories. For Opengrep, these are the vendored snapshot that Shoalscan ships plus the repository's own rules.
- **Excludes:** paths every scanner skips, such as build output, vendored code, and test fixtures that contain attack patterns on purpose.
- **Blocking:** which severities block a pull request. The default is ERROR and WARNING.
- **Baseline:** the path of the baseline file.
- **Components:** a map from path prefixes to component names, used to group findings on the dashboard.

## Finding format

Every scanner's output is turned into one record:

| Field | Meaning |
|---|---|
| `tool` | The scanner, for example `opengrep` |
| `rule` | The scanner's rule ID |
| `severity` | `ERROR`, `WARNING` or `INFO` |
| `path`, `line` | Where the finding is |
| `fingerprint` | A stable ID from the scanner, or a hash of the rule, path and normalised matched code. It does not change when lines shift. |
| `component` | From the path, using `components` in the configuration |
| `message` | The scanner's explanation |

## Baseline

- **Format:** a TOML file of `[[finding]]` entries keyed by `tool`, `rule`, `path` and `fingerprint`. Each entry carries `issue` (for example `#123`) and `reason`.
- **New findings:** a finding that is not in the baseline fails the run if its severity is blocking.
- **Stale entries:** an entry that no longer reproduces fails the run until it is removed. This keeps the baseline honest and means it can only shrink.
- **Creating it:** `shoalscan baseline init` writes the first baseline from a full scan, with every entry pointing at one triage issue.

## Commands

- `shoalscan install`: download, verify and install the pinned scanners into a tools directory.
- `shoalscan scan`: run the configured scanners and write the normalised findings as JSON. It also writes a SARIF file.
- `shoalscan check`: compare the findings with the baseline. It prints new and stale entries, emits a one-line JSON summary, and exits non-zero on a blocking result.
- `shoalscan baseline init`: write the baseline from a full scan.
- `shoalscan record`: store a run's summary and findings in the history database.
- `shoalscan serve`: start the dashboard over HTTPS with token login.
- `shoalscan triage`: write a prioritised work list grouped by rule family and component.
- `shoalscan report`: write a dated Markdown security report from the history and the baseline.

## Dashboard

- **Server:** a small standard-library HTTPS server. It serves TLS only and uses a token login, CSRF protection, a same-origin Content Security Policy and rate-limited login.
- **Trend data:** comes from a scheduled full scan of the default branch. Pull-request runs show what each change introduced.
- **Repositories:** one history database can hold several, so one dashboard can serve them all.

### Branding

The icon is `assets/shoalscan-icon.svg`: a cheerful cartoon steamship at night sails straight toward a shoal where a little bug hides just under the waves. A lighthouse beam from off the edge lights up the danger, under a warning sign. The ship has not seen it yet; Shoalscan has. The dashboard uses it in three places:
- **Header:** as the logo, beside the name.
- **Favicon:** as the browser tab icon. It is served from the dashboard's own origin, so the Content Security Policy stays same-origin.
- **About page:** large, at the top.

### About page

The dashboard has a small About page that explains the name, the idea and the limits in plain words:

> **Why "Shoalscan"?** A shoal is a stretch of shallow water hiding sand banks or rocks just under the surface. Ships run aground on shoals because, from above, the water looks open and safe. Lighthouses exist mainly to warn ships away from hazards like these.
>
> Security flaws behave the same way. Code can look fine at a glance while the danger sits just below. Shoalscan maps those hidden hazards. The baseline is a chart of the shoals you already know about, so a change is flagged only when it sails into new ones.

The page also lists:
- the scanners in use and their pinned versions;
- the rule sources and their licences;
- the limits of static analysis;
- links to the project and its licence.

## Remediation loop

1. `shoalscan triage` groups the open findings and links each group to its rule's explanation.
2. Someone, or an agent on a developer machine, fixes one rule family per pull request. Each fix removes the finding from the baseline and adds a test or a rule that stops it coming back. Every fix pull request is reviewed; nothing merges on its own.
3. False positives are suppressed inline with the rule and an issue. Accepted risks stay in the baseline with a reason.
4. `shoalscan report` summarises the posture, the trend, what was fixed and what was accepted.

## Rules

- **Opengrep community rules:** `shoalscan install` downloads a snapshot of the archived [opengrep-rules](https://github.com/opengrep/opengrep-rules) repository, pinned by commit and SHA-256 in `tools.lock`, like the scanner binaries. Those rules are licensed LGPL-2.1 with the Commons Clause and are not bundled in this repository, so Shoalscan's own licence stays clean. Users can turn them off.
- **Shoalscan rules:** these ship in this repository under its licence. Each has tests, and they cover common risk patterns: TLS verification turned off, plain HTTP, secrets written to logs, and error handlers that fail open.
- **Repository-specific rules:** these stay in the repository that uses them.
- **Semgrep registry:** not used. Its licence covers the Semgrep tool.

## Phases

1. Opengrep: install, scan, baseline and check, with CI examples for GitHub Actions and a plain shell runner.
2. History, `record` and the dashboard, fed by a nightly scan of the default branch.
3. Triage and report, and the first triage pass.
4. More scanners: gitleaks, zizmor, hadolint and trivy config. Clippy's security lints are left out: running them compiles the scanned crate, which executes its build scripts and procedural macros, and fetches its dependencies.
