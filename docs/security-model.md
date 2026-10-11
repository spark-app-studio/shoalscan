# Security model

This guide collects how Shoalscan protects itself: the scan, the dashboard and the worker that scans from the dashboard. [Limits](limits.md) lists what these safeguards do not cover.

## Scans and the policy

- Scanner binaries and the community rules are pinned by SHA-256 in `tools.lock`, and the Opengrep and Trivy cosign signatures are checked at install time ([Getting started](getting-started.md#install-the-pinned-scanners)).
- A scan makes no network calls. Each scanner gets only an allowlisted environment: `PATH`, `HOME`, the temporary directory variables, the locale, the user name and the time zone.
- Nothing in the scanned repository can configure a scanner or silence it: Opengrep ignores `.semgrepignore` files, Gitleaks ignores `.gitleaks.toml`, `.gitleaksignore` and `gitleaks:allow` comments, Hadolint ignores `.hadolint.yaml` and `# hadolint ignore=` pragmas, zizmor runs offline and ignores `zizmor.yml` and `# zizmor: ignore` comments, and Trivy runs offline with its embedded checks and ignores `trivy.yaml`, `.trivyignore` and modules in the home directory; its inline ignore comments must name a check and an issue ([Scanners](scanners.md)). Inline suppressions for Opengrep must name a rule and an issue.
- Secrets that Gitleaks finds never reach the findings, the SARIF file or the history ([details](scanners.md#the-secrets-stay-out-of-the-output)).
- The tools directory and the output directory must be outside the repository, so a pull request cannot plant files in them.
- A scan that fails in any way fails the command; it is never read as "no findings".
- On a pull request with `--policy-ref`, the configuration, the baseline and the rule directories come from the base branch, so a change cannot relax its own checks ([details](baseline-and-check.md#pull-requests-the-policy-comes-from-the-base-branch)).
- Nothing needs a token or a secret: scanning, recording and serving the dashboard all work without credentials.

## The dashboard

- It speaks TLS 1.2 or later only, with forward-secret AEAD ciphers. There is no plain-HTTP port.
- Login is a form POST of the token, never a URL. The token is compared through its SHA-256 in constant time. An address may fail five times in 15 minutes and then has to wait. Past 50 failures in total, only addresses that have failed recently are held off, so an address with no failures can always log in. A successful login clears its address's failures. The counts live in memory only: restarting `shoalscan serve` clears a lockout.
- A session is a `__Host-` cookie that is `Secure`, `HttpOnly` and `SameSite=Strict`. Sessions live only in memory, end after eight idle hours or seven days, and end at once when the token is rotated.
- Every POST must come from the dashboard's own origin, and logout also needs the session's CSRF token.
- Every response carries a strict Content Security Policy (only the dashboard's own scripts, styles and images, no inline code, no framing), `nosniff`, a same-origin referrer policy and HSTS.
- Requests with an unknown `Host` header are refused, which defeats DNS rebinding.
- Static files come from a fixed list, so a request path can never reach another file.
- Requests and connections are bounded. A request URL may be 4,096 bytes and a body 2,048 bytes; a chunked body is refused and the connection closed. The server holds at most 64 connections, 16 from one address, and only 4 from one address that have not finished the TLS handshake. A handshake must finish within 5 seconds, and a connection lives at most 60 seconds. Errors the HTTP parser raises carry the same security headers as every other response.
- The database is opened read-only, and every query is parameterised. Finding messages and paths are shown as text, never as HTML.

### The certificate

`shoalscan serve init-tls` makes a single-use certificate authority that signs one server certificate and then has its private key deleted. Its name constraints limit it to the dashboard's own DNS names and IP addresses, and it may vouch only for TLS servers, so trusting it does not let anyone impersonate other sites in a client that enforces name constraints. [The dashboard](dashboard.md#serving-the-dashboard) has the details and how to trust it.

## The scan worker

Scanning from the dashboard is off until repositories are registered in `scan_targets.toml`, which must be owned by the user that runs Shoalscan and not writable by anyone else ([Scanning from the dashboard](dashboard-scanning.md)).

A request to scan names a registered repository and nothing else. No path, branch, ref, flag or command text ever comes from the browser. Starting a scan is a POST that needs a session, the CSRF token and the dashboard's exact `Origin` header. One scan runs at a time, with a per-repository cooldown and an hourly cap for all repositories.

The web server never scans. It starts one detached worker, `python -m shoalscan.scanjob`, with a fixed argument list, no shell, a new session, an allowlisted environment and its output in a log in the state directory. The worker reads `scan_targets.toml` again and takes only the repository's name from the server. It takes a lock file that names its process; a lock whose process has gone, or whose process number now belongs to another process, is stale and is taken over. It fetches the clone, scans the head of the branch in a temporary worktree, and runs `scan`, `check` and `record --kind scheduled --check-exit` with a deadline. At the deadline the whole process group is killed and nothing is recorded. Temporary files are removed on every exit path. The log lines the Runs page shows have every absolute path removed.

- **Git attributes.** The worker reads git attributes from an empty tree (`GIT_ATTR_SOURCE`), so a scanned repository's `.gitattributes` cannot make a checkout run a filter driver. This needs git 2.40 or later, and Shoalscan checks before every scan that git really honours it ([details](dashboard-scanning.md#requirement-git-240-or-later)).
- **Clones.** A public `source` is cloned over https only, from an allowed host, with no prompts and no credential helpers. Clones and fetches are size-limited, and a scan needs a minimum of free disk space. Private repositories are scanned from mirrors you keep up to date yourself, so Shoalscan never needs their credentials.
- **Rescan this commit** sends only the repository's name and a run number; the worker looks the commit up in the history database and checks that it is a full commit SHA still in the clone.
- **The Configuration page** can set only a few checked fields (name, source, branch, enabled, nightly and the policy text), and refuses, never cleans up, a value that does not fit. It can never set a path, an interpreter, a timeout or command text. Every change is written atomically at mode 0600 and audited. Baselines change only from the command line ([details](dashboard-scanning.md#the-configuration-page)).
- **Audit.** Every scan and every configuration change is recorded in the history database with who, when and the outcome.

**See also:** [Limits](limits.md).
