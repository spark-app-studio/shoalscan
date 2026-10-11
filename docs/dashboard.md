# The dashboard

Shoalscan keeps a history of runs in a SQLite database and serves a small dashboard over it. This guide covers recording runs, correcting the history, serving the dashboard and what its pages show.

## Recording a run

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

The trend charts need a regular scan of the default branch; [Scheduled scans](scheduled-scans.md) sets one up.

## Correcting the history

`shoalscan history list-runs --repo-name owner/project` lists a repository's runs, newest first, with their ids, kinds, commits and outcomes. To remove a run that should not be there, for example a first scan recorded with a temporary configuration, delete it by id:

```sh
shoalscan history delete-run --repo-name owner/project --run 12 --yes
```

Without `--yes` it only says what it would delete. It deletes the run with its findings and the lists recorded for it, prints what it deleted, and removes finding identities and messages that no other run uses. First seen, fixed, ages and times to fix are worked out from the remaining runs each time the dashboard shows them, so they stay consistent. Deleting a repository's last run removes the repository from the dashboard. Every deletion is recorded with the run's id, kind, commit and finding count, when it happened and the local account that ran it, and the Runs page says how many runs were deleted. Both commands take `--db` like `record`.

## Serving the dashboard

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

[Security model](security-model.md#the-dashboard) describes how the dashboard protects itself: TLS settings, login, sessions, headers and limits.

### Trusting the certificate

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

### Your own certificate

You can use a certificate from your own CA instead. Pass the PEM certificate chain and the private key:

```sh
shoalscan serve --cert /path/to/fullchain.pem --key /path/to/key.pem --host scans.example.internal
```

Keep the key readable only by the user that runs the dashboard.

## The pages

The dashboard has four pages:

- **Overview:** the latest run's result, tiles with the key numbers, open findings by severity over time, the baseline burning down, new and fixed findings per week, the mean time to fix, how old the open findings are, a heatmap of findings by component, inline suppressions over time, and files that were not fully scanned.
- **Findings:** a table you can filter by run, severity, rule, component, path, age, and whether a finding is new or new and blocking. Each rule links to its message and every place it was found.
- **Runs:** every recorded run with its status and counts. Select a run to see its detail and links to everything behind its numbers: its findings, the new and new blocking ones, stale baseline entries, inline suppressions and files that were not fully scanned.
- **About:** what Shoalscan is, who it is for, the scanners and rule sources with their pinned versions and licences, and the limits of static analysis.

A run's status says what happened in words. **Passed** means the check passed. **Blocked** names the first reason, such as "Blocked: 3 new blocking findings", and lists the others: stale baseline entries, changed files that were not fully scanned, or added baseline entries. A short explanation links to the new blocking findings. **Scan error** means the check could not run, so the run has no results.

Near the top of the Overview, the **Blocking findings** panel answers "what should we fix first?". It counts the findings the policy treats as blocking (a blocking severity outside `non_blocking_paths`, as the check decided), split into **new** ones, which fail pull requests, and **baselined** ones, the backlog accepted at adoption. Both numbers are links. A small line shows the count over the scheduled runs, so the burn-down of what matters is visible. Below it are the ten findings to fix first: new blocking findings first, then ERROR before WARNING, then the component with the highest heat score, then the oldest. "See all" opens the Findings page with the **Blocking only** filter, which sorts the same way by default; any view can choose this **Fix priority** sort. Runs recorded before this feature, or without a `check.json` that lists the blocking class, show it as unknown.

Every number that has a list behind it is a link. Each tile, each point on the severity chart and its legend, each bar of the weekly and age charts, and each heatmap cell opens the findings or the list it counts. Numbers with no list behind them, such as the baseline size or the mean time to fix, are not links. The filters live in the address, so a filtered view can be bookmarked or shared, and the back button works. Links are ordinary links that a keyboard can reach.

The heatmap ranks components by a heat score, ERROR × 10 + WARNING × 3 + INFO, with components that have new blocking findings first. Each cell shows its count, and its shade grows with the count; a bar beside each row shows the score. The top 15 components are shown, and a button shows the rest.

One database can hold several repositories, and the dashboard has a repository selector. The trend charts use the scheduled scans of the default branch. A repository with no scheduled runs uses all of its runs instead.

**Next:** [Reviewing findings](reviewing-findings.md), [Scheduled scans](scheduled-scans.md) and [Scanning from the dashboard](dashboard-scanning.md).
