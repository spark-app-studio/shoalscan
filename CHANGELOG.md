# Changelog

All notable changes to Shoalscan are recorded here.

## Unreleased

### Added

- `shoalscan triage` prints a prioritised work list of the last scan's findings, offline, from `findings.json` and the baseline: stale baseline entries first, then one group per rule family (the CWE a rule names, or the rule itself), each with its rules' messages, fix hints, CWE and OWASP labels, references and a link to the rule file, and its findings by component, marked new and blocking, new, or baselined with their issue and reason. Groups follow the dashboard's Fix priority. `--format json` lists every finding for scripts and agents; `--blocking-only`, `--output` and `--max-per-group` shape the list. It warns when the tree, HEAD or configuration changed after the scan. `triage export` is unchanged.
- `shoalscan report` writes a dated security report on one repository from the run history, for a period of up to 366 whole UTC days (`--since`, `--until`; the last 30 days by default): the posture at the end of the period and its change since the start, blocking and untriaged findings, the weekly new and fixed findings with the lists behind them, the time to fix, what the baseline accepts grouped by issue and reason, dashboard review changes with who made them, components, coverage (runs by outcome, deleted runs, unscanned files, suppressions, scanner versions and signature checks) and the limits of static analysis. Markdown by default, or `--format json`.
- `shoalscan scan` records each reporting rule's metadata (CWE, OWASP, confidence, likelihood, impact, fix hint, references and rule file) under `rules` in `findings.json`. Values are bounded and only http(s) links are kept.

### Security

- `findings.sarif` no longer copies the scanned code: the `snippet` of every Opengrep result (its region, context region, related locations and code flows) is removed. A snippet held the whole matched line, so a rule that finds hard-coded secrets put the secret itself into a file that CI uploads or keeps as an artifact. Locations, messages and fingerprints are unchanged.
- Text from the scanned repository (paths, messages, rule metadata, baseline reasons, component names, review descriptions) is escaped in the work list and the report, so it cannot add links, images, HTML or headings.

## 0.1.1 (2026-10-11)

### Fixed

- `shoalscan scan`, then `shoalscan baseline init`, then `shoalscan check` no longer exits with 2. `check` refused the findings because writing the baseline changed the working tree. The baseline file `check` reads (the `baseline` key, or `--baseline` inside the repository) is now left out of the tree binding, since editing it cannot change what was scanned. Every other edit, the configuration included, still makes `check` refuse the findings; so does any finding, suppression or unscanned entry the scan reported in the baseline file itself. Under `--policy-ref` the binding is unchanged. The quickstart runs in its natural order again.

### Project

- Contributor guide (`CONTRIBUTING.md`) with the Developer Certificate of Origin sign-off, the Contributor Covenant 2.1 code of conduct, and a security policy (`SECURITY.md`) for private vulnerability reports.
- Issue forms, a pull request template, `CODEOWNERS`, Dependabot updates for GitHub Actions, and CodeQL and OpenSSF Scorecard workflows with actions pinned by commit SHA.

## 0.1.0 (2026-10-11)

The first release: Opengrep install, scan, baseline and check, plus the run history and the dashboard.

### Run history and dashboard

### Added

- `shoalscan record` stores a run in a SQLite history database: the findings, the check summary (counts by severity, the blocking and non-blocking split, new and stale findings, the baseline size, suppressions and files not fully scanned), and the repository, ref, commit, time and kind (`pr` or `scheduled`). The database has a schema version and migrations, uses WAL mode, and is created with mode 0600. Recording is idempotent per repository, commit and kind. Findings are stored by their identity, so the dashboard can tell when each was first seen and when it was fixed. Runs are capped in size and old runs are pruned.
- `shoalscan serve` starts a dashboard over HTTPS for one or more repositories. The Overview page shows open findings by severity over time, the baseline burn-down, new and fixed findings per week, the mean time to fix, the age of open findings, findings by component, suppressions and files not fully scanned over time, and the latest run's result. The Findings page has a filterable table that links each rule to its message; the Runs page lists the history; the About page explains the name, lists the pinned scanners and rule sources with their licences, and states the limits of static analysis. The Shoalscan icon is the logo and the favicon. The pages are plain HTML, CSS and JavaScript with inline SVG charts, in a light and a dark theme.
- `shoalscan serve token` makes a 256-bit login token and stores only its SHA-256.
- `shoalscan serve init-tls` uses the `openssl` command to make a single-use certificate authority, name-constrained to the dashboard's addresses and host names, which signs one server certificate and then has its key deleted. You can also bring your own certificate and key.
- `examples/scheduled-scan.sh` scans the head of the default branch in a temporary worktree each night and records it, with example launchd and systemd timer units.
- `parse_warn_only` in `.shoalscan.toml`: globs of changed files whose partial parses only warn, for languages whose Opengrep parser is experimental (Dockerfiles, shell scripts, YAML templates). Skipped files, timeouts and other errors still fail. Under `--policy-ref` the list comes from the base branch. Each such file is listed loudly and counted in the summary.
- `parse_warn_only` also covers whole-file syntax errors of template files (Helm templates, Jinja YAML): they warn as SYNTAX ERROR (warn-only by policy) instead of failing; skips, timeouts and other errors still fail.
- `shoalscan check` writes `check.json` next to the findings: the new and new blocking findings, the stale baseline entries and what happened to each changed file. The findings file lists the inline suppressions.
- `shoalscan record` stores the check's outcome and exit status (`--check-exit`) and the lists from `check.json`, findings, suppressions and unscanned files, in schema version 3. Older runs stay readable. A run whose check could not run is recorded as a scan error, without results; it feeds no trend and never replaces a run with results.
- `shoalscan history list-runs` and `shoalscan history delete-run --yes` to find and remove a run, for example one recorded with a temporary configuration.
- The dashboard says what each run's result means: Passed, Blocked with its reasons, or Scan error, with a link to the new blocking findings. Every number with a list behind it is a link: the tiles, the severity chart's points and legend, the weekly and age bars, and the cells of a new component heatmap ranked by heat score. New pages list a run's stale baseline entries, unscanned files and suppressions, and the findings behind each week's new and fixed counts. Filters live in the address, so views can be bookmarked and shared.
- `examples/scheduled-scan.sh` takes `SHOALSCAN_PYTHON` and refuses a Python older than 3.11; it passes the check's exit status to `record`.
- The Overview's **Blocking findings** panel: the findings the policy treats as blocking, split into new (fail pull requests) and baselined (the backlog), a line of the count over the scheduled runs, and the ten to fix first. The Findings page has a Blocking only filter and a Fix priority sort: new blocking first, ERROR before WARNING, the hottest component, then the oldest. `check.json` lists the blocking class and `record` stores it (schema version 4); older runs show it as unknown.
- `shoalscan history delete-run` records each deletion (schema version 5), and the Runs page says how many runs were deleted.
- Finding reviews (schema version 10): mark findings as false positive, accepted risk, won't fix or fixed, one by one or in bulk, always with a description; scheduled runs verify fixes and flag regressions; every change is kept with its time and author. Baselined findings show their baseline reason until reviewed. The Overview counts untriaged blocking findings and regressions. `shoalscan triage export` prints reviewed findings as baseline entries for a reviewed change; reviews alone never change what blocks CI.
- Scanning from the dashboard, off until repositories are registered in `scan_targets.toml`: **Run a fresh scan** on the Runs page, **Rescan** of a repository's tip or of exactly one run's commit, and a **Configuration** page that edits the registered repositories under strict rules. Scans run in a detached worker (`shoalscan scanjob`) with a lock, a deadline, cooldowns and an hourly cap, and are audited (schema versions 6 and 7), as are configuration changes (schema version 8). `shoalscan scanjob --nightly` scans every nightly repository, with example launchd and systemd units.

### Security

- `parse_warn_only` entries must name files: a file name, a name with any extension, or an extension, optionally under a path. Catch-alls such as `*e*` or `**` are refused, and an entry without `/` never matches a directory. The setting binds a pull request only under `--policy-ref`.
- `record` binds a run to the commit that was scanned, which `scan` now writes into `findings.json`; findings from a `--no-git` scan need `--allow-no-git`. It also refuses a `check.json` whose lists do not agree with the summary's counts.
- Control characters in rule ids and component names are replaced when a run is recorded, and a bad recorded value shows as plain text instead of breaking a dashboard page.
- The dashboard serves TLS only. Login is a rate-limited form POST compared in constant time; sessions use a `__Host-` cookie that is `Secure`, `HttpOnly` and `SameSite=Strict`; every POST must be same-origin and logout needs a CSRF token. Responses carry a strict same-origin Content Security Policy with no inline code and no framing, `nosniff`, a referrer policy and HSTS. Unknown `Host` headers are refused. Static files come from a fixed list. The database is opened read-only with parameterised queries, and untrusted text is only ever inserted as text.

### Install, scan, baseline and check

### Added

- `tools.lock` pins Opengrep 1.30.2 for Linux and macOS on x86_64 and arm64, cosign 3.1.3, and the final commit of the archived opengrep-rules repository, each by URL and SHA-256.
- `shoalscan install` downloads the pinned tools over HTTPS, checks every SHA-256, checks the Opengrep signature with `cosign verify-blob` against the Opengrep release workflow identity, and moves files into place atomically. It installs only the rule languages Shoalscan uses and keeps the rules' licence file next to them. Running it again verifies what is installed. Without cosign it stops, unless `--skip-signature-check` is given.
- `shoalscan scan` runs Opengrep offline with local rules only and writes `findings.json` and `findings.sarif`. Any scanner failure fails the scan. Fingerprints survive line shifts.
- `shoalscan check` compares the findings with the baseline. New blocking findings and stale baseline entries fail; INFO findings never block. It prints a report and a one-line `SHOALSCAN_SUMMARY` JSON summary, and exits 0, 1 or 2.
- `shoalscan baseline init` writes a sorted, deterministic baseline from a full scan and refuses to overwrite one without `--force`.
- The suppression lint: an inline suppression must name a rule id and an issue, or it becomes a blocking finding. Suppressions are counted.
- `.shoalscan.toml` configuration with strict validation.
- Rule selection: `[opengrep] categories` (default `["security"]`) picks community rules by their category, and `[opengrep] exclude_rules` leaves out rules by id or `prefix.*`. The selected rules are copied to a temporary directory; the installed snapshot is never changed.
- `non_blocking_paths`: findings under these path prefixes are reported but never fail the check.
- Shoalscan's own Opengrep rules, with tests: TLS verification turned off, plain `http://` URLs, secrets passed to log calls, and broad exception handlers that swallow security-check failures.
- CI examples for GitHub Actions and for a self-hosted runner.
- `--policy-ref` for `scan` and `check`: on pull requests the configuration, the baseline and the repository's rule directories come from the base branch. The baseline may only shrink, policy edits are shown as a diff, and `blocking` must include ERROR.
- Files Opengrep skipped or reported errors for are listed; a changed file that was not fully scanned fails a pull request.
- `shoalscan baseline rename-path OLD NEW` for moved files.
- `examples/CODEOWNERS`.

### Hardening

- The installed community rules are checked against a digest pinned in `tools.lock`, not against a manifest in the tools directory.
- The tools and output directories must be outside the repository; their defaults are now the user's cache directory and a private temporary directory.
- The suppression lint uses Opengrep's own grammar, reports bare suppressions as bare, and covers every scanned file, prose included.
- Fingerprints include the enclosing function or class and no longer include the path.
- Rule selection refuses YAML it cannot read with certainty, checks that the split text reassembles exactly, and checks the rules Opengrep ran against the staged ones.
- Opengrep runs with an allowlisted environment; downloads respect their deadline on every read; unexpected errors exit with 2.
- A cosign mismatch is reported as possible tampering; an install without a signature check is recorded and verified on the next install.
- Rules: more secret-in-log forms; `http://localhost@host` is reported; constants are reported once.
- The GitHub Actions example's SARIF upload now runs, and the self-hosted script reinstalls on a new pin.
- `--policy-ref` accepts only a full commit SHA or a fully qualified `refs/heads/...` or `refs/remotes/...` ref, so a tag cannot shadow the base branch; the workflow passes the base commit SHA.
- The suppression lint uses ASCII word boundaries, as Opengrep does.
- Fingerprint contexts are qualified (`class:A/def:run`), and line numbers follow newlines only.
- The rule reader refuses duplicate or continued category values and unclosed quotes; a PyYAML-generated list of the pinned snapshot's categories is checked in and tested.
- `check` refuses findings for a different tree; scans record the HEAD tree and a dirty flag.
- A signature counts as verified only with a positive record of the cosign check.
- Unscanned changed files are graded (partial parses near added lines or covering most of a file fail); pure baseline moves are allowed under strict conditions; first-time adoption is supported.
- Rules: more secret-in-log forms (Python `extra` keys and `getLogger(...)`, Node object fields, Rust `%field` and `println!`).
- The suppression lint folds the long s as Opengrep does; changed files under excludes are listed; `check` needs a git work tree unless `--no-git`; quoted rule ids and categories may not contain backslashes; secret-in-log covers keyword arguments and `creds`.
