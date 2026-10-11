<p align="center"><img src="assets/shoalscan-icon.svg" alt="Shoalscan" width="160"></p>

# Shoalscan

Shoalscan runs several security scanners over a repository as one CI step. It compares their findings against a baseline and records each run, so a small dashboard can show how the codebase's security changes over time.

A shoal is a hidden hazard under the water. A lighthouse warns ships about it; Shoalscan warns a codebase about the vulnerabilities under its surface.

## Who it's for

- **Teams that don't host on GitHub:** GitLab, Bitbucket, Gitea or Forgejo, with CI on GitLab CI, Jenkins, Buildkite, Drone or plain cron, where GitHub's code scanning is not available.
- **Regulated and air-gapped organisations**, where code may not leave the network: scans run offline, with pinned and signature-verified scanners and a self-hosted dashboard.
- **Startups working towards SOC 2 or ISO 27001**, which need evidence of security testing and a trend over time.
- **Agencies and consultancies** that look after many client repositories, where client code cannot go to a third-party service.
- **Teams adopting static analysis on an existing codebase**: record today's findings as a baseline, block only new ones, and watch the baseline shrink.
- **Teams using AI coding agents**: a gate on every pull request for the insecure shortcuts agents tend to take (TLS verification turned off, hard-coded secrets, plain HTTP), with JSON output an agent can read to fix its own findings.
- **Platform and DevSecOps engineers** standardising one pinned scanner and one dashboard across many repositories on self-hosted runners.

## When to use something else

- A public repository on GitHub may be better served by GitHub's free code scanning with CodeQL, which analyses data flow across files.
- If you need deep cross-file analysis, or a large maintained rule set with support, consider a commercial platform. Shoalscan runs open rules and does not replace code review, tests or dependency audits.

## What it does

- **One scan, many tools.** Shoalscan runs [Opengrep](https://github.com/opengrep/opengrep) first. Later it will add gitleaks for secrets, zizmor for GitHub Actions, hadolint for Dockerfiles, trivy config for Helm and Kubernetes, and clippy's security lints for Rust. It turns every tool's output into one finding format.
- **Pinned, verified tools.** Each scanner's version and SHA-256 are pinned in `tools.lock`, and so is the community rules snapshot. Signatures are checked where the tool publishes them. A scan makes no network calls.
- **A baseline that only shrinks.** The first full scan records every existing finding. After that, a pull request fails only on findings it introduces. A baseline entry that no longer reproduces also fails, so fixed findings must leave the baseline. Every entry names an issue and a reason.
- **History and a dashboard.** Each run is stored in a local SQLite database. The dashboard shows:
  - open findings by severity;
  - the baseline burning down;
  - new and fixed findings each week;
  - how old findings are;
  - findings by component;
  - suppressions over time;
  - files that were not fully scanned.
- **Triage and reports.** `shoalscan triage` groups findings into a work list for fixing, one rule family at a time. `shoalscan report` writes a dated security report.

Available now: `install`, `scan`, `check` and `baseline init` with Opengrep, and the run history with `record` and the `serve` dashboard. Triage and reports come in a later phase.

## Install

Shoalscan needs Python 3.11 or later and has no Python dependencies. It runs on Linux and macOS, on x86_64 and arm64.

Install the command from a commit you have reviewed:

```sh
python3 -m pip install "shoalscan @ git+https://github.com/spark-app-studio/shoalscan@<commit-sha>"
```

Then install the pinned scanners. By default they go into `$XDG_CACHE_HOME/shoalscan/tools`, or `~/.cache/shoalscan/tools` when `XDG_CACHE_HOME` is not set:

```sh
shoalscan install
```

This downloads Opengrep 1.30.2, cosign and a snapshot of the community rules, over HTTPS only. Every file is checked against its SHA-256 in `tools.lock` before it is used, and each download has a time limit that every read respects. The Opengrep binary is also checked with `cosign verify-blob` against the identity of the Opengrep release workflow. The extracted rules are checked against one digest of all their files, pinned in `tools.lock`; nothing stored in the tools directory is trusted for that check. Files are moved into place atomically, so an interrupted install never leaves a half-written tool behind. Running `install` again verifies what is already there and downloads only what is missing or does not match.

If cosign cannot be installed, `shoalscan install` stops. You can pass `--skip-signature-check` to install with the SHA-256 checks only; Shoalscan prints a warning. After a successful cosign check, install writes `opengrep.verified.json` in the tools directory: a local install record of what this machine checked (the binary, signature and certificate hashes, the identity, the issuer and the workflow commit). It is not an attestation and proves nothing to anyone else; anyone who can write the tools directory can edit it. Shoalscan calls the binary verified only when that record matches `tools.lock` and the installed binary. Without it (a skipped check, or a binary copied in by hand), every scan warns loudly, and the next `shoalscan install` with cosign verifies the signature. A cosign download that does not match its pin is reported as possible tampering, and the install stops. Pass `--no-community-rules` to skip the rules snapshot.

On a python.org build of Python for macOS, HTTPS downloads can fail with `CERTIFICATE_VERIFY_FAILED`. Run the `Install Certificates.command` that came with Python, or point `SSL_CERT_FILE` at your system's CA bundle.

## Usage

Scan the repository in the current directory:

```sh
shoalscan scan
```

The scan runs Opengrep with local rules only and writes two files to the output directory. `findings.json` holds the normalised findings. `findings.sarif` holds Opengrep's SARIF output, with repository-relative paths and Shoalscan's fingerprints added, so you can upload it to a code scanning service. A scan that fails in any way (the scanner crashes, times out, exits with an error, reports an error, runs a rule that was not selected, or writes output that cannot be read) fails the command. It is never read as "no findings", and no findings file is left behind. Opengrep gets only an allowlisted environment: `PATH`, `HOME`, the temporary directory variables, the locale, the user name and the time zone.

The tools directory and the output directory must be outside the repository: a pull request could plant files inside it. Shoalscan refuses either one inside `--repo`. Unless you pass `--out`, the output goes to a private per-repository directory under the system temporary directory, and `check` finds it there.

Compare the findings with the baseline:

```sh
shoalscan check
```

`check` prints a readable report and then one line that starts with `SHOALSCAN_SUMMARY `, followed by JSON with the counts by severity, by component and by rule, the number of new findings, stale baseline entries, the baseline size, the suppressions and the files that were not fully scanned. It exits with 0 when the check passes, 1 when the check fails, and 2 when the setup is broken, the scan failed or Shoalscan itself hit an unexpected error.

- A new finding fails the check when its severity is blocking. By default ERROR and WARNING block.
- A new INFO finding is reported but never blocks.
- A baseline entry that no longer matches any finding is stale and fails the check, so the baseline can only shrink.
- Files that Opengrep skipped (for example because they are larger than `max_target_bytes`) or reported an error for (a parse error or a timeout) are listed. With `--policy-ref`, for a file the change touched and the configuration does not exclude:
  - a skipped file, a timeout, running out of memory, or any error other than a partial parse fails the check;
  - a partial parse fails when an unparsed span overlaps a line the change added, or covers more than half the file, and is otherwise reported as a warning;
  - a file that matches `parse_warn_only` only warns about a partial parse, whatever its size or place. It is listed loudly as `PARTIALLY PARSED (warn-only by policy)` with the share of the file left unparsed and whether that overlaps the added lines, and counted in the summary. A skipped file, a timeout or any other error still fails;
  - a syntax error that Opengrep does not report (some Python parse errors) is not seen.
- `check` refuses findings that do not match the current tree: `scan` records the HEAD tree hash and whether the working tree had changes, and any edit or commit after the scan means scanning again. `check` refuses a directory that is not a git work tree unless you pass `--no-git`; the findings are then not tied to a commit.
- With `--policy-ref`, changed files that the configured excludes skip are listed loudly as CHANGED BUT NOT SCANNED. They do not fail the check, but reviewers should confirm the exclusion is intended.

When a file moves, point its baseline entries at the new path; fingerprints do not contain the path, so they stay valid:

```sh
shoalscan baseline rename-path src/old_name.py src/new_name.py
```

Write the first baseline from a full scan:

```sh
shoalscan baseline init --issue "#123" --reason "Existing findings at adoption, triaged in #123"
```

The issue can be `#123` or a URL. `baseline init` refuses to overwrite an existing baseline unless you pass `--force`. The file is sorted and deterministic, so the same scan always writes the same baseline.

Every command takes `--repo`, `--config`, `--tools-dir` and `--out` where they apply. Run `shoalscan <command> --help` for the details.

## Pull requests: the policy comes from the base branch

On a pull request, run both commands with `--policy-ref` set to the base commit's full SHA. In GitHub Actions that is `github.event.pull_request.base.sha`:

```sh
shoalscan scan  --policy-ref "$BASE_SHA" --out "$OUT"
shoalscan check --policy-ref "$BASE_SHA" --out "$OUT"
```

Shoalscan accepts only a full commit SHA or a fully qualified `refs/remotes/...` or `refs/heads/...` ref that exists. It refuses short names such as `origin/main`: git prefers a tag of the same name over the branch, so anyone who can push a tag could otherwise choose the policy.

With a policy ref, `.shoalscan.toml`, the baseline and the repository's own rule directories are read from that ref with `git show` and `git archive`, not from the pull request's checkout. A pull request therefore cannot exclude its own files, turn off rules or accept its own findings. On top of that:

- The pull request's baseline may only remove entries compared with the base branch. An added or changed entry fails, with a message that a baseline addition needs a separate, reviewed change on the base branch. The one exception is a pure move made with `baseline rename-path`: git must report the rename (at least 90% similar), every entry of the old path must move one-to-one with the same tool, rule, fingerprint, issue and reason, and the component and non-blocking status must not change. Moves are listed loudly in the report.
- Any change the pull request makes to the configuration, the baseline or the rule directories is printed as a loud diff, so reviewers see it, even though it is not applied.
- `check` refuses findings that `scan` produced under a different policy.
- `blocking` must include ERROR.
- First-time adoption: when the base ref has neither a configuration nor a baseline, the pull request's own configuration and baseline are used and reported as ADOPTION, so reviewers know they are setting the policy. ERROR findings still block. A base ref with a configuration but no baseline file, or the other way round, is refused; commit both (`shoalscan baseline init` writes an empty baseline when there are no findings).

Put `.shoalscan.toml`, the baseline, your rule directories and the CI workflow under CODEOWNERS, so that changes to the policy on the base branch need a review from the people who own security. `examples/CODEOWNERS` shows the lines to add.

## Configuration

Each repository keeps a `.shoalscan.toml` at its root. Every key is optional, and an unknown key is an error, so a typo never turns a setting off silently.

```toml
scanners = ["opengrep"]

# Paths every scanner skips, in gitignore style. Opengrep receives them as
# --exclude patterns; the repository's own .semgrepignore files are ignored.
excludes = ["target", "node_modules", "vendor", "**/fixtures/**"]
# A pattern that could match every file (such as **, * or *e*) is refused:
# each must name a directory or file, or have a literal prefix, suffix or
# part of at least four characters.

# Severities that fail a pull request. INFO never blocks.
blocking = ["ERROR", "WARNING"]

# Path prefixes whose findings are recorded and reported but never fail the
# check, for example demo or example code. Stale baseline entries still fail.
non_blocking_paths = ["demo/", "examples/"]

# Changed files whose partial parses only warn (see "Partial parses" below).
# Use it only for languages whose Opengrep parser is experimental.
parse_warn_only = ["**/Dockerfile", "deploy/charts/**/templates/*.yaml"]

baseline = ".shoalscan/baseline.toml"

[opengrep]
community_rules = true    # the pinned opengrep-rules snapshot
shoalscan_rules = true    # the rules in this repository's rules/ directory
rule_dirs = ["security/rules"]   # your own rules, relative to the repository
# Categories of community rules to run (their metadata.category). Rules with
# no category count as "uncategorised". This applies to the community
# snapshot only; Shoalscan's own rules and yours always run.
categories = ["security"]
# Rules to leave out, by exact id or by prefix ending in ".*".
exclude_rules = ["community.python.lang.security.audit.dangerous-subprocess-use-audit"]

[limits]
scan_timeout_seconds = 1800
rule_timeout_seconds = 30       # per rule and file
max_target_bytes = 1000000      # larger files are skipped
jobs = 4

# Path prefixes to component names. The longest prefix wins; anything else
# is "other".
[components]
"services/api/" = "api"
"web/" = "web"
```

Rule selection happens before the scan: Shoalscan copies only the selected rules into a temporary directory and runs Opengrep on that copy, so the installed snapshot is never changed and left-out rules cost nothing. The community snapshot has the categories security, correctness, best-practice, compatibility, maintainability, performance, portability and caching. `exclude_rules` cannot turn off the suppression lint.

Rule ids get a prefix that says where they come from: `community.` for the community snapshot, `shoalscan.` for Shoalscan's own rules, and `repo.` for your rule directories.

### Partial parses

Opengrep's parsers for some languages are experimental. Its Dockerfile and Bash parsers, and its YAML parser when it meets Helm templates, often leave more than half of a real file unparsed. Under the normal rule, any change to such a file then fails the check, even though nothing is wrong with the change. `parse_warn_only` lists globs (the same syntax as `excludes`) for changed files whose partial parses are reported as warnings instead. Their unparsed lines are not checked by any rule, so the report lists each one loudly.

Template files are a special case. A Helm template is a Go template, not YAML, so Opengrep cannot parse it at all and reports a syntax error for the whole file. For a changed file that matches `parse_warn_only`, such a syntax error is also only a warning, listed loudly as `SYNTAX ERROR (warn-only by policy)` and counted in the summary. Opengrep's generic (text) rules still scan the file; the language-aware rules cannot. A skipped file, a timeout, running out of memory or any other error still fails. List only template-language files this way: Helm templates, Jinja-templated YAML and the like. Be aware of the trade-off: a change that deliberately breaks a listed template's syntax keeps the language-aware rules away from it (the generic rules still run). That is acceptable only because, under `--policy-ref`, the list comes from the base branch, so a change cannot add its own files to it.

Use it only for languages whose parser is experimental: Dockerfiles, shell scripts and YAML templates. Never use it for Rust, Python, JavaScript or TypeScript. Their parsers are mature, so a partial parse there usually means the code is broken or is hiding something.

Each entry must name the files it covers. It is a file name (`Dockerfile`), a file name with any extension (`Dockerfile.*`), an extension (`*.sh`, `*.yaml`), or a path with `/` whose last part is one of those (`deploy/**/templates/*.yaml`). An entry without `/` matches a file's own name only, never a directory on its path. Patterns that could cover any file, such as `*e*`, `**` or `src/*`, are refused.

The setting only protects pull requests that run under `--policy-ref`: then the list comes from the base branch, like the rest of the policy, and a change cannot make its own files warn-only. Without `--policy-ref`, or in adoption mode (the first run, before the base branch has a configuration), the configuration in the change itself applies, including its `parse_warn_only`.

## Findings and fingerprints

Every finding has a `tool`, `rule`, `severity` (ERROR, WARNING or INFO), `path`, `line`, `fingerprint`, `component` and `message`. The fingerprint is a hash of the tool, the rule, the enclosing function or class, and the matched code with its whitespace collapsed. Identical matches in the same function of one file get an occurrence number. The fingerprint holds neither the line number nor the path, so moving code up or down keeps it, and `baseline rename-path` follows a moved file. Opengrep's own match ID is not used, because it changes with the directory the rules are loaded from.

The enclosing context is found by reading lines, not syntax: walking up from the match, every `def`, `fn`, `function`, `class` (and similar) line indented less than what came before encloses it, giving a qualified name such as `class:Svc/def:run`. Line numbers follow newlines only, as Opengrep counts them. That has limits you should know:

- Changing the matched code, renaming the enclosing function, or moving the code into another function changes the fingerprint. The finding then shows up as new, and its old baseline entry as stale.
- Moving or renaming a file without `baseline rename-path` does the same.
- Code at the left margin, or in a language whose definitions this heuristic does not recognise, has no context; identical matches there are told apart only by their order in the file.

## The baseline file

The baseline is a TOML file with one `[[finding]]` table per accepted finding:

```toml
version = 1

[[finding]]
tool = "opengrep"
rule = "community.python.lang.security.audit.eval-detected"
path = "src/tools/calc.py"
fingerprint = "59301fe727479b07bc9d8054f41ca694:0"
issue = "#123"
reason = "Input is a constant expression; fix tracked in #123"
```

Every key is required, and `issue` must be `#123` or a URL.

## Inline suppressions

Opengrep skips a finding on a line that carries a suppression comment, or on the line after one. Shoalscan requires every such comment to name the rule and an issue, with the colon right after the marker and one space before the rule id:

```python
requests.get(url, verify=CA_BUNDLE)  # nosemgrep: community.python.requests.security.disabled-cert-validation #123 private CA
```

Shoalscan reads these comments with the same expression Opengrep uses, with ASCII-only word boundaries as in Opengrep, so a marker next to a letter such as `é` still counts. Like Opengrep, it matches the marker's letters with Unicode case folding, so a marker spelled with a long s (`ſ`) counts too. If the colon is missing, is preceded by a space, or is followed by more than one space, Opengrep ignores the rule id and silences every rule on the line; Shoalscan reports that as a bare suppression, which blocks. A comment with no valid rule id or no issue also blocks. Opengrep matches the marker anywhere on a line, even inside a string, so Shoalscan checks every file that Opengrep scanned, prose files such as Markdown included. Suppressions are counted in the summary, together with the number of findings they silence, so silencing never looks like fixing.

## Shoalscan's own rules

The `rules/` directory holds Shoalscan's rules. Each rule has metadata with its CWE, severity, confidence and a short fix hint, and each has Opengrep tests next to it.

- **TLS verification turned off:** Python (`verify=False`, `CERT_NONE`, unverified contexts), Node (`rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`) and Rust (`danger_accept_invalid_certs(true)` and friends). A custom rustls certificate verifier is reported separately as a warning to review.
- **Plain `http://` URLs in code:** loopback addresses (only when the host is followed by a port, a path or the end, so `http://localhost@host` is reported), the cloud metadata address, reserved example and test domains, XML namespace identifiers and test files are not reported. A constant is reported once, where its literal is.
- **Secrets passed to log calls:** Python (`logging`, `extra={...}`, `print`), Node (including object shorthand such as `{ token }`) and Rust (`log` and `tracing` macros, inline format arguments such as `"{token}"`, and `?field` shorthand) with an argument named like a password, token, secret key, API key, private key or credential.
- **Broad exception handlers on security paths:** a Python `try` that calls a verification, authentication or authorization function, with a bare `except`, `except Exception` or `except BaseException` that only passes, continues or logs.

The rules are deliberately conservative: fewer false positives matter more than coverage. Run their tests with:

```sh
~/.cache/shoalscan/tools/opengrep scan --test rules/
```

## History and the dashboard

Shoalscan keeps a history of runs in a SQLite database and serves a small dashboard over it. The dashboard has four pages:

- **Overview:** the latest run's result, tiles with the key numbers, open findings by severity over time, the baseline burning down, new and fixed findings per week, the mean time to fix, how old the open findings are, a heatmap of findings by component, inline suppressions over time, and files that were not fully scanned.
- **Findings:** a table you can filter by run, severity, rule, component, path, age, and whether a finding is new or new and blocking. Each rule links to its message and every place it was found.
- **Runs:** every recorded run with its status and counts. Select a run to see its detail and links to everything behind its numbers: its findings, the new and new blocking ones, stale baseline entries, inline suppressions and files that were not fully scanned.
- **About:** what Shoalscan is, who it is for, the scanners and rule sources with their pinned versions and licences, and the limits of static analysis.

A run's status says what happened in words. **Passed** means the check passed. **Blocked** names the first reason, such as "Blocked: 3 new blocking findings", and lists the others: stale baseline entries, changed files that were not fully scanned, or added baseline entries. A short explanation links to the new blocking findings. **Scan error** means the check could not run, so the run has no results.

Near the top of the Overview, the **Blocking findings** panel answers "what should we fix first?". It counts the findings the policy treats as blocking (a blocking severity outside `non_blocking_paths`, as the check decided), split into **new** ones, which fail pull requests, and **baselined** ones, the backlog accepted at adoption. Both numbers are links. A small line shows the count over the scheduled runs, so the burn-down of what matters is visible. Below it are the ten findings to fix first: new blocking findings first, then ERROR before WARNING, then the component with the highest heat score, then the oldest. "See all" opens the Findings page with the **Blocking only** filter, which sorts the same way by default; any view can choose this **Fix priority** sort. Runs recorded before this feature, or without a `check.json` that lists the blocking class, show it as unknown.

Every number that has a list behind it is a link. Each tile, each point on the severity chart and its legend, each bar of the weekly and age charts, and each heatmap cell opens the findings or the list it counts. Numbers with no list behind them, such as the baseline size or the mean time to fix, are not links. The filters live in the address, so a filtered view can be bookmarked or shared, and the back button works. Links are ordinary links that a keyboard can reach.

The heatmap ranks components by a heat score, ERROR × 10 + WARNING × 3 + INFO, with components that have new blocking findings first. Each cell shows its count, and its shade grows with the count; a bar beside each row shows the score. The top 15 components are shown, and a button shows the rest.

One database can hold several repositories, and the dashboard has a repository selector. The trend charts use the scheduled scans of the default branch. A repository with no scheduled runs uses all of its runs instead.

### Recording a run

After `shoalscan check`, store the run with `shoalscan record`. It needs the findings file, the output of `check` (it reads the `SHOALSCAN_SUMMARY` line), and a few facts about the run:

```sh
status=0
shoalscan check --out "$OUT" > "$OUT/check.txt" || status=$?
shoalscan record --findings "$OUT/findings.json" --check-output "$OUT/check.txt" --check-exit "$status" \
  --repo-name owner/project --ref main --commit "$(git rev-parse HEAD)" --kind scheduled
```

`--kind` is `scheduled` for a scan of the default branch and `pr` for a pull-request run. `--scanned-at` sets the time of the scan in ISO 8601 with a time zone; it defaults to now, and a time more than 24 hours in the future is refused. `--check-output -` reads the check output from standard input.

`--check-exit` is the exit status of `check`. With 0 or 1 it must agree with the summary, and the dashboard shows the run as **Passed** or **Blocked**, with the reasons: new blocking findings, stale baseline entries, changed files that were not fully scanned, or added baseline entries. With 2 the check could not run, so `record` stores a **Scan error** with no results; it needs no findings or check output then. A scan error never feeds the trend charts and never replaces a run that holds results.

`check` also writes `check.json` next to `findings.json`. It holds the lists behind the summary's counts: which findings are new and which of them block, the stale baseline entries, and what happened to each changed file. `record` reads it from there (or from `--check-details`), refuses it when it was made from another findings file or another check, and stores the lists so the dashboard can show them. A run recorded without `check.json` keeps its counts, but the dashboard cannot list its new or stale entries. The findings file also lists the inline suppressions and the files that were not fully scanned, and `record` stores those too.

The database lives at `$XDG_DATA_HOME/shoalscan/history.sqlite3`, or `~/.local/share/shoalscan/history.sqlite3` when `XDG_DATA_HOME` is not set; `--db` picks another file. It is created with mode 0600 and uses SQLite's WAL mode. Its schema has a version, and a newer Shoalscan migrates an older database the first time it records into it. An older Shoalscan refuses a database that is newer than it understands.

`scan` writes the commit it scanned into `findings.json`, and `record` refuses a `--commit` that differs, so a run can never be filed under the wrong commit. Findings from a `--no-git` scan name no commit; `record` takes them only with `--allow-no-git`.

Recording is idempotent per repository, commit and kind. Recording the same run again changes nothing, and recording the same commit and kind with different results replaces the earlier record, so a retried job is harmless. `record` refuses a check summary whose finding count does not match the findings file, because the two would come from different runs.

Findings are stored by their identity (tool, rule, path and fingerprint), so the dashboard can tell when each finding was first seen and when it was fixed. A finding that disappears and later comes back counts as fixed and then new again. Findings that were already present in the first recorded run count from that run, so their ages and times to fix are lower bounds. To keep the dashboard's memory bounded, these figures come from the newest 400 trend runs (about a year of nightly scans), read two runs at a time.

The history is bounded. A run may hold at most 100,000 findings, messages are cut at 4,000 characters, and each message is stored once however many runs share it. After each record, Shoalscan keeps the newest 2,000 runs of the repository (`--max-runs`) and drops pull-request runs more than 90 days older than the newest run (`--keep-pr-days`).

### Correcting the history

`shoalscan history list-runs --repo-name owner/project` lists a repository's runs, newest first, with their ids, kinds, commits and outcomes. To remove a run that should not be there, for example a first scan recorded with a temporary configuration, delete it by id:

```sh
shoalscan history delete-run --repo-name owner/project --run 12 --yes
```

Without `--yes` it only says what it would delete. It deletes the run with its findings and the lists recorded for it, prints what it deleted, and removes finding identities and messages that no other run uses. First seen, fixed, ages and times to fix are worked out from the remaining runs each time the dashboard shows them, so they stay consistent. Deleting a repository's last run removes the repository from the dashboard. Every deletion is recorded with the run's id, kind, commit and finding count, when it happened and the local account that ran it, and the Runs page says how many runs were deleted. Both commands take `--db` like `record`.

### Serving the dashboard

The dashboard serves HTTPS only and needs three things: a login token, a TLS certificate and its key, and the history database. Make the token first:

```sh
shoalscan serve token
```

It prints a new 256-bit token once. Only its SHA-256 is stored, in `$XDG_CONFIG_HOME/shoalscan/dashboard/token.sha256` (or `~/.config/shoalscan/dashboard/`). Running it again replaces the token and ends every session made with the old one.

Then make a certificate. `init-tls` needs the `openssl` command:

```sh
shoalscan serve init-tls --ip 127.0.0.1
```

Name every address (`--ip`) and host name (`--dns`) that people will use to reach the dashboard; repeat the options for several. `init-tls` makes a new certificate authority, has it sign one server certificate, and deletes the CA's private key, so nobody can sign another certificate with that CA afterwards. As a second safeguard, the CA's name constraints cover both kinds of name a server certificate can carry. DNS names are limited to the names you gave, or to the reserved `shoalscan.invalid` when you gave none. IP addresses are limited to the addresses you gave, and IPv4 or IPv6 is excluded entirely when you gave no address of that kind. The CA may also vouch only for TLS servers. A client that enforces name constraints, as current browsers and TLS libraries do, rejects a certificate from this CA for any other name. `init-tls` works with OpenSSL 3 and with the LibreSSL `openssl` that macOS ships. It writes `ca.pem` and `server.pem` (mode 0644, as certificates are public) and `server.key` (mode 0600) into `tls/` in the dashboard's state directory, which has mode 0700. The server certificate is valid for 397 days; run `init-tls --force` to make a new one, and trust the new CA.

Start the dashboard:

```sh
shoalscan serve
```

It listens on `127.0.0.1:8443` by default. Open `https://127.0.0.1:8443`, paste the token, and you are in. To serve other machines, bind to an address they can reach and name the host names and addresses they use:

```sh
shoalscan serve init-tls --dns scans.example.internal --ip 192.0.2.10
shoalscan serve --bind 0.0.0.0 --host scans.example.internal --host 192.0.2.10
```

The dashboard answers only to requests whose `Host` header is one of those names with the port. With a wildcard `--bind`, `--host` is required. Put `--state-dir` after `token` or `init-tls` when you use those subcommands.

#### Trusting the certificate

Before you trust the CA, compare its SHA-256 fingerprint with the one `init-tls` printed:

```sh
openssl x509 -in ~/.config/shoalscan/dashboard/tls/ca.pem -noout -fingerprint -sha256
```

Then trust `ca.pem` on each machine that opens the dashboard:

- **macOS:** `security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db ca.pem`, or open `ca.pem` in Keychain Access and set it to "Always Trust".
- **Debian and Ubuntu:** `sudo cp ca.pem /usr/local/share/ca-certificates/shoalscan-dashboard.crt && sudo update-ca-certificates`.
- **Fedora and RHEL:** `sudo cp ca.pem /etc/pki/ca-trust/source/anchors/shoalscan-dashboard.pem && sudo update-ca-trust`.
- **Firefox:** Settings, Privacy & Security, Certificates, View Certificates, Authorities, Import, and tick "Trust this CA to identify websites".

The CA's key is gone, and the `-p ssl` policy on macOS limits the trust to TLS servers. Its name constraints also cover only the dashboard's names. So trusting it does not let anyone impersonate other sites to you in a client that enforces name constraints.

#### Your own certificate

You can use a certificate from your own CA instead. Pass the PEM certificate chain and the private key:

```sh
shoalscan serve --cert /path/to/fullchain.pem --key /path/to/key.pem --host scans.example.internal
```

Keep the key readable only by the user that runs the dashboard.

#### How the dashboard protects itself

- It speaks TLS 1.2 or later only, with forward-secret AEAD ciphers. There is no plain-HTTP port.
- Login is a form POST of the token, never a URL. The token is compared through its SHA-256 in constant time. An address may fail five times in 15 minutes and then has to wait. Past 50 failures in total, only addresses that have failed recently are held off, so an address with no failures can always log in. A successful login clears its address's failures. The counts live in memory only: restarting `shoalscan serve` clears a lockout.
- A session is a `__Host-` cookie that is `Secure`, `HttpOnly` and `SameSite=Strict`. Sessions live only in memory, end after eight idle hours or seven days, and end at once when the token is rotated.
- Every POST must come from the dashboard's own origin, and logout also needs the session's CSRF token.
- Every response carries a strict Content Security Policy (only the dashboard's own scripts, styles and images, no inline code, no framing), `nosniff`, a same-origin referrer policy and HSTS.
- Requests with an unknown `Host` header are refused, which defeats DNS rebinding.
- Static files come from a fixed list, so a request path can never reach another file.
- Requests and connections are bounded. A request URL may be 4,096 bytes and a body 2,048 bytes; a chunked body is refused and the connection closed. The server holds at most 64 connections, 16 from one address, and only 4 from one address that have not finished the TLS handshake. A handshake must finish within 5 seconds, and a connection lives at most 60 seconds. Errors the HTTP parser raises carry the same security headers as every other response.
- The database is opened read-only, and every query is parameterised. Finding messages and paths are shown as text, never as HTML.

### Reviewing findings

After you look into a finding, record what you decided on the dashboard. Open the finding from the Findings table (the Review link), or select several findings and use **Mark as**. A finding can be:

- **Open**, the default. A finding with no review and no baseline reason shows as **Untriaged**.
- **False positive**, **Accepted risk** or **Won't fix**. These stay with the finding run after run.
- **Fixed**, a fix you claim. The next scheduled scan checks it: when the finding is gone, it becomes **Verified fixed**; when it is still there or comes back, it becomes a **Regression**.

Every change needs a description of 10 to 2000 characters, and is kept in the finding's history with who made it, when (in UTC) and on which run. When a finding enters a resolved status (false positive, accepted risk, won't fix, fixed or verified fixed), the time is stored; going back to open or regression clears it. The dashboard shows times in your local time, with the exact UTC time on hover. Automatic changes are made by "shoalscan" with a description such as "No longer found in the scheduled run of 2026-10-10T02:00:00Z at 3f2a1b4c5d6e.". Only the newest scheduled run moves reviews; pull-request runs never do.

Reviews follow a finding by its repository's name and its identity (tool, rule, path and fingerprint), not by run. They stay when runs are deleted, even all of a repository's runs, and apply again if the repository is recorded under the same name. A moved file starts without its reviews. When a finding moves between resolved statuses, its resolution time stays the time it was first resolved. A finding that the baseline accepts shows its baseline entry's reason and issue, read-only and marked "from baseline", until someone reviews it on the dashboard: a reason that starts with "False positive:" shows as a false positive, one that starts with "Accepted:" as an accepted risk, and any other as baselined. That needs the `check.json` that `check` writes.

**Dashboard reviews do not change what blocks CI.** The baseline does. To carry reviews into the baseline, export them and commit the result through a reviewed change:

```sh
shoalscan triage export --repo owner/project --issue "#123" > reviewed-entries.toml
```

It prints baseline entries for the findings reviewed as false positive, accepted risk or won't fix. Each reason is the review's description with "(reviewed in dashboard by WHO on WHEN)", and `--issue` is required. `--suppressions` also prints matching inline suppression lines, as comments. The command never writes the repository's baseline itself.

### Scanning from the dashboard

The dashboard can start scans itself, but only of repositories registered on the server, and the feature is off until you register one. It adds three things: **Run a fresh scan** on the Runs page, **Rescan** buttons on the latest run and on a run's detail, and a **Configuration** page that lists and edits the registered repositories.

Scanning from the dashboard needs **git 2.40 or later**. The worker reads git attributes from an empty tree (`GIT_ATTR_SOURCE`), so a scanned repository's `.gitattributes` cannot make a checkout run a filter driver, such as git-lfs downloading from a URL the repository chose. Older git, such as the git 2.34 that Ubuntu 22.04 ships, silently ignores that setting. Shoalscan does not trust the version number: before every scan it checks, with a throwaway repository, that git really ignores the repository's attributes, and it refuses to scan when it does not. The dashboard then shows "git 2.40 or later is required: it must honour GIT_ATTR_SOURCE" and disables the scan buttons.

#### Registering repositories

Repositories are registered in `scan_targets.toml` in the dashboard's state directory (`~/.config/shoalscan/dashboard` by default). Without that file there is no scan control, no Configuration page, and the scan endpoints answer 404. To let the dashboard create the file from its Configuration page, start it with `shoalscan serve --allow-config`.

```toml
history_db = "/home/you/.local/share/shoalscan/history.sqlite3"  # the database this dashboard serves
tools_dir = "/home/you/.cache/shoalscan/tools"                    # optional
cooldown_minutes = 10        # per repository, between scans started from the dashboard
timeout_minutes = 30         # a scan that runs longer is stopped and records nothing
max_scans_per_hour = 6       # for all repositories together
min_free_mb = 2048           # refuse to start a scan with less free disk space than this
max_clone_mb = 2048          # a clone or fetch that grows past this is stopped and cleaned up

[[target]]
name = "owner/project"                               # the name on the dashboard
source = "https://github.com/owner/project.git"      # a public repository, cloned by the server
branch = "main"
enabled = true
nightly = true

[[target]]
name = "owner/private"
mirror = "private-project"                           # a local mirror registered in local_sources.toml
branch = "main"

[[target]]
name = "owner/hand-set"
clone = "/srv/clones/hand-set"                       # set by hand only
branch = "main"
config = "/srv/policies/hand-set.toml"               # optional, by hand only, outside the clone
baseline = "/srv/policies/hand-set-baseline.toml"    # optional, by hand only, outside the clone
python = "/opt/shoalscan/bin/python"                 # optional, by hand only
max_clone_mb = 2000                                  # optional, by hand only: this target's own clone size limit
```

The file must be owned by the user that runs Shoalscan and must not be writable by anyone else; the dashboard refuses to start otherwise. Every key is checked, and an unknown key is an error. Each target has exactly one source:

- **`source`**, an https URL of a public repository on an allowed host. The allowed hosts are `github.com`, `gitlab.com` and `bitbucket.org`, unless `allowed_hosts.toml` in the state directory says otherwise (`hosts = ["github.com"]`). The server clones only the registered branch, with its full history so earlier commits can be rescanned, into `clones/` in the state directory, and fetches only that branch, with git limited to https, with no prompts and no credential helpers. Private repositories cannot be scanned this way.
- **`mirror`**, the name of a local clone registered in `local_sources.toml` in the state directory (`[[mirror]]` tables with a `name` and an absolute `path`). Use a mirror for a private repository: you keep it up to date yourself, for example with `git fetch` in a cron job, and Shoalscan never fetches it or needs its credentials.
- **`clone`**, an absolute path to a clone, set only by editing the file. Shoalscan fetches it with your own git setup, as `examples/scheduled-scan.sh` does.

A repository added on the Configuration page gets its policy and baseline in `targets/<name>/` in the state directory: `shoalscan.toml` is the policy text from the page, and `baseline.toml` is its baseline.

#### Starting a scan

A request to scan names a registered repository and nothing else. No path, branch, ref, flag or command text ever comes from the browser. Starting a scan is a POST that needs a session, the CSRF token and the dashboard's exact `Origin` header. Only one scan runs at a time: a second request gets 409 with the running scan's status. A repository can be scanned again only after its cooldown, and the hourly cap applies to all repositories; both answer 429 with the time to wait.

The web server never scans. It starts one detached worker, `python -m shoalscan.scanjob`, with a fixed argument list, no shell, a new session, an allowlisted environment and its output in a log in the state directory. The worker reads `scan_targets.toml` again and takes only the repository's name from the server. It takes a lock file that names its process; a lock whose process has gone, or whose process number now belongs to another process, is stale and is taken over. It fetches the clone, scans the head of the branch in a temporary worktree, and runs `scan`, `check` and `record --kind scheduled --check-exit` with a deadline. At the deadline the whole process group is killed and nothing is recorded. Temporary files are removed on every exit path. The Runs page polls the status while a scan runs; the log lines it shows have every absolute path removed.

**Rescan** scans the branch's current tip again. **Rescan this commit**, on a run's detail, scans exactly the commit that run scanned: the browser sends only the repository's name and the run's number, the worker looks the commit up in the history database, and checks that it is a full commit SHA still in the clone after a fetch. The new record replaces that run, which is then labelled "Rescanned". A commit that is no longer in the clone fails with a clear message and records nothing.

Every scan started from the dashboard, the command line or the nightly job is audited in the history database with who started it, when, what kind of request it was, its outcome and the run it produced. The Runs page shows them. The dashboard has a single login token, so the person is recorded as "dashboard user".

#### The Configuration page

The page lists the registered repositories with their source, branch, whether they are enabled and scanned nightly, and their latest run, with buttons to edit, disable or enable, remove (after typing the name again) and scan now. A browser can set only these fields, and each one is checked on the server and refused, never cleaned up, when it does not fit:

- the name, like `owner/project`;
- the source: an https URL on an allowed host, with no user name, password, port, query or fragment, in plain ASCII; or one of the registered mirrors, chosen by name;
- the branch, by git's own rules, never starting with `-`;
- enabled and nightly;
- the policy, the text of a `.shoalscan.toml`, checked with Shoalscan's strict configuration parser. It may not set `baseline`, because the dashboard manages the baseline's location.

The browser can never set a clone path, a configuration or baseline path, an interpreter, a timeout or any command text; keys set by hand in the file are kept when the page saves it. Every change is written atomically (a temporary file, fsync, rename) at mode 0600 and audited with who made it, when, which fields changed and the SHA-256 of the policy text before and after. The page shows the audit. Removing a repository keeps its runs, findings and baseline.

Baselines change only from the command line. The page shows a repository's baseline, read-only, with the command to change it, for example:

```sh
shoalscan baseline init --repo <a checkout> --config <state dir>/targets/<name>/shoalscan.toml \
  --baseline <state dir>/targets/<name>/baseline.toml --issue "#123" --reason "accepted at adoption"
```

Review a baseline change like any other change to your security policy.

#### One nightly job for every repository

`shoalscan scanjob --nightly --state-dir <state dir>` scans every enabled repository with `nightly = true`, one after another, with the same worker, lock and audit. It skips disabled repositories and the ones without `nightly`, and waits for a scan started from the dashboard to finish. `examples/scheduled/local.shoalscan.nightly-targets.plist` (launchd) and `examples/scheduled/shoalscan-nightly-targets.service` with its `.timer` (systemd) run it every night. `shoalscan scanjob --target owner/project --state-dir <state dir>` scans one repository from the command line.

### Scheduled scans

The trend charts need a regular scan of the default branch. `examples/scheduled-scan.sh` does one: it fetches a clone you keep for scanning, scans the head of the default branch in a temporary worktree (so the clone's own checkout is never touched), runs `check`, and records the run as `scheduled`. It exits with 0 when the run was recorded, whether the check passed or failed, and with 2 when the scan or the setup failed; then nothing is recorded, because a failed scan is never "no findings".

```sh
SHOALSCAN_SPEC="shoalscan @ git+https://github.com/spark-app-studio/shoalscan@<commit-sha>" \
SHOALSCAN_REPO_NAME=owner/project \
examples/scheduled-scan.sh ~/scans/project
```

The script makes its virtual environment with `python3`. Set `SHOALSCAN_PYTHON` to use another interpreter, for example `SHOALSCAN_PYTHON=/usr/local/bin/python3.12` on a machine whose `python3` is older. The script stops with a clear message, and records nothing, when that Python is older than 3.11. The other settings are listed at the top of the script.

To run it every night:

- **macOS:** `examples/scheduled/local.shoalscan.scheduled-scan.plist` is a launchd agent that runs at 02:30. Edit the paths, copy it to `~/Library/LaunchAgents/`, and load it with `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/local.shoalscan.scheduled-scan.plist`.
- **Linux:** `examples/scheduled/shoalscan-scan.service` and `shoalscan-scan.timer` are systemd user units. Edit the paths, copy both to `~/.config/systemd/user/`, then run `systemctl --user daemon-reload` and `systemctl --user enable --now shoalscan-scan.timer`. Run `loginctl enable-linger "$USER"` so it also runs when you are not logged in.

Pull-request runs can be recorded too, with `--kind pr`, on a machine that holds the history database. They show on the Runs page. Once a repository has scheduled runs, pull-request runs no longer feed its trend charts.

## CI

`examples/github-actions/shoalscan.yml` is a GitHub Actions workflow with every action pinned by commit SHA. It needs no secrets, reads the policy from the base branch on pull requests, and uploads the SARIF file to code scanning. `examples/self-hosted.sh` does the same on any machine with Python, such as a self-hosted runner, and keeps its exit codes: 0 pass, 1 fail, 2 broken. It reinstalls Shoalscan when the pinned install spec changes. `examples/CODEOWNERS` puts the policy files under review.

## Development

Run the tests with:

```sh
python3 -m unittest discover -s tests
```

The end-to-end tests run the real Opengrep, so install the tools first with `shoalscan install` (or `PYTHONPATH=src python3 -m shoalscan install`). Without them those tests are skipped, and the skip message says why. Set `SHOALSCAN_TOOLS_DIR` to use tools installed somewhere else.

## Limits

No scanner finds every vulnerability. Pattern and taint analysis misses authorization and logic flaws, data flows across files, and concurrency bugs. Shoalscan is one layer of defence alongside dependency audits, tests and code review.

Shoalscan's own safeguards have limits too:

- The policy-from-base model protects pull requests only when CI passes `--policy-ref`, and only as well as the base branch is protected. Changes on the base branch itself are trusted, which is why the policy files belong under CODEOWNERS.
- The policy diff shows tracked files. A rule directory's untracked files are not part of a commit, so they never reach CI.
- The changed-file check sees files that Opengrep reports as skipped or errored. A file that no rule's language covers is not scanned at all and is not reported, and a parse error Opengrep does not report is not seen.
- Fingerprints follow code within a file and, with `rename-path`, across moves; they do not survive edits to the matched code or to the enclosing function's name.

## Status

Early development. Phase 1 (Opengrep install, scan, baseline and check) and phase 2 (the run history and the dashboard) are done. See [docs/design.md](docs/design.md) for the plan and [CHANGELOG.md](CHANGELOG.md) for changes.

## Licence

Shoalscan is licensed under the [Apache License 2.0](LICENSE). The Opengrep community rules that `shoalscan install` can download are not part of Shoalscan. They keep their own licence (LGPL-2.1 with the Commons Clause).
