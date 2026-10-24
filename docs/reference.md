# Command and file reference

What Shoalscan reads and writes, in one place. Each entry links to the guide that explains it. Every command has `--help`, which lists its options; `shoalscan --version` prints the version.

## Commands

| Command | What it does | Guide |
| --- | --- | --- |
| `shoalscan install` | Downloads the pinned scanners and rules, checks their SHA-256 and signatures, and installs them. | [Getting started](getting-started.md#install-the-pinned-scanners) |
| `shoalscan scan` | Runs the scanners over a repository and writes `findings.json` and `findings.sarif`. Makes no network calls. `--require-network-sandbox` makes it fail unless the scanners run in an operating-system network sandbox. `--rules-commit <commit>`, with `--config`, reads the repository rule directories from that commit instead of the scanned tree. | [Getting started](getting-started.md#the-first-scan), [Scanners](scanners.md) |
| `shoalscan check` | Compares the findings with the baseline and the policy, prints a report and a `SHOALSCAN_SUMMARY` line, and writes `check.json`. `--changed-since <commit>`, with an explicit configuration and baseline, also fails on changed files (against the merge base with that commit) that were not fully scanned. | [Baseline and check](baseline-and-check.md#the-check) |
| `shoalscan baseline init` | Writes the baseline from a full scan, with an issue and a reason. | [Baseline and check](baseline-and-check.md#the-baseline-file) |
| `shoalscan baseline accept --test-code` | Adds baseline entries for findings labelled as test code that a person accepts, recording who, when and the reason "test code". | [Test code labels](test-code.md#accepting-a-finding-in-test-code) |
| `shoalscan baseline rename-path` | Points baseline entries for a moved file or directory at its new path. | [Baseline and check](baseline-and-check.md#moving-and-renaming-files) |
| `shoalscan record` | Stores a run's findings and check result in the history database (`--embed` also embeds them). | [Dashboard](dashboard.md#recording-a-run) |
| `shoalscan triage` | Prints the last scan's findings as a prioritised work list. | [Triage](triage.md) |
| `shoalscan triage export` | Prints baseline entries for findings reviewed as false positive, accepted risk or won't fix. | [Reviewing findings](reviewing-findings.md) |
| `shoalscan triage embed` | Embeds a repository's findings with a local Ollama model, and works out suggestions. | [Triage](triage.md#similar-findings-with-a-local-embedding-model) |
| `shoalscan triage suggest-similar` | Lists the findings most like one finding, with their decisions. | [Triage](triage.md#similar-findings-with-a-local-embedding-model) |
| `shoalscan report` | Writes a dated security report on one repository from the history. | [Report](report.md) |
| `shoalscan history list-runs`, `delete-run` | Lists a repository's runs, or deletes one. | [Dashboard](dashboard.md#correcting-the-history) |
| `shoalscan serve` | Serves the dashboard over HTTPS; `serve init-tls`, `serve user` and `serve oidc` manage its certificate, users and sign-in. | [Dashboard](dashboard.md#serving-the-dashboard) |
| `shoalscan scanjob` | Scans a target registered in `scan_targets.toml`, all nightly targets (`--nightly`), or the new heads of the open pull requests of targets with `pull_requests = true` (`--pull-requests`). | [Scanning from the dashboard](dashboard-scanning.md), [Scheduled scans](scheduled-scans.md) |

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success. For `check`, the check passed. |
| 1 | `check` only: the check failed, for example on new blocking findings or stale baseline entries. |
| 2 | Shoalscan could not do its job: invalid configuration, a missing or unverified tool, a scanner error or timeout, or an internal error. A run that exits 2 is never a pass. |
| 130 | Interrupted (Ctrl-C). |

## Files Shoalscan reads

| File | Where | Guide |
| --- | --- | --- |
| `.shoalscan.toml` | The scanned repository; on a pull request, from the base branch. | [Configuration](configuration.md) |
| The baseline (`.shoalscan/baseline.toml` by default) | The scanned repository. | [Baseline and check](baseline-and-check.md#the-baseline-file) |
| `tools.lock` | Shipped with Shoalscan, or `--lock`. Pins every scanner and the rules by SHA-256. | [Security model](security-model.md) |
| `scan_targets.toml` | The dashboard's state directory: repositories the dashboard and scheduled scans can scan. | [Scanning from the dashboard](dashboard-scanning.md) |
| `oidc.toml`, `oidc-ca.pem` | The dashboard's state directory: its sign-in settings, written by the setup wizard (mode 0600). | [Dashboard](dashboard.md#signing-in) |

## Files Shoalscan writes

| File | Written by | What it holds | Guide |
| --- | --- | --- | --- |
| `findings.json` | `scan` | The normalised findings of every scanner, with rule metadata, what was not fully scanned, the suppressions, each scanner's version and how it was verified, and how the scanners were isolated (`isolation`). | [Getting started](getting-started.md#the-first-scan), [Triage](triage.md#rule-metadata-in-findingsjson), [Security model](security-model.md#scanner-isolation) |
| `findings.sarif` | `scan` | SARIF 2.1.0 for code scanning, without code snippets. | [Getting started](getting-started.md#the-first-scan) |
| `check.json` | `check` | The lists behind the check's counts: new, new blocking and stale. | [Baseline and check](baseline-and-check.md#the-check) |
| `setup-code`, in the dashboard's state directory (mode 0600) | `serve`, while sign-in is not set up | The one-time setup code for the wizard; it works for 30 minutes, and saving the settings deletes it. | [Dashboard](dashboard.md#signing-in) |
| The history database (SQLite) | `record`, the dashboard | Runs (with the scanners each used), findings, reviews, embeddings and suggestions. | [Dashboard](dashboard.md) |
| `opengrep.verified.json`, `<scanner>.verified.json` | `install` | In the tools directory: a record that a scanner's cosign signature was checked, written only after a successful check. `scan` reports the signature as verified only when the record matches the installed binary. | [Scanners](scanners.md) |

## Environment

Shoalscan reads `XDG_CACHE_HOME` (the tools go under it, in `~/.cache/shoalscan` by default) and `XDG_DATA_HOME` (where the history database is by default, under `~/.local/share`).

Scanners run with an allowlisted environment: only `PATH`, the locale, the user name and the time zone pass through. Shoalscan sets the rest itself for each scanner run: `HOME` and the temporary directory are an empty private directory, git reads no configuration and allows no transport (`GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_GLOBAL`, `GIT_ALLOW_PROTOCOL`, `GIT_TERMINAL_PROMPT`, `GIT_SSH_COMMAND`), the proxy variables point at a closed local port with `NO_PROXY` empty, and the cloud metadata services are off. Where it can, it also runs each scanner under `sandbox-exec` (macOS) or `unshare --net` (Linux), and warns once when neither is available; see [Scanner isolation](security-model.md#scanner-isolation).
