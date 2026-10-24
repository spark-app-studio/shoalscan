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

The database lives at `$XDG_DATA_HOME/shoalscan/history.sqlite3`, or `~/.local/share/shoalscan/history.sqlite3` when `XDG_DATA_HOME` is not set; `--db` picks another file. It is created with mode 0600 and uses SQLite's WAL mode. Its schema has a version, and a newer Shoalscan migrates an older database the first time it records into it or starts `serve` with it. Before every migration it writes a copy of the database as it was, `history.sqlite3.bak-schema<N>` next to it (mode 0600, where N is the old schema version), and says so on the console. An older Shoalscan refuses a database that is newer than it understands. To roll back to an older Shoalscan after a migration, stop the dashboard and any scheduled scans, move the migrated database aside, and copy `history.sqlite3.bak-schema<N>` to `history.sqlite3`; runs recorded after the migration are not in the copy.

`scan` writes the commit it scanned into `findings.json`, and `record` refuses a `--commit` that differs, so a run can never be filed under the wrong commit. Findings from a `--no-git` scan name no commit; `record` takes them only with `--allow-no-git`.

Recording is idempotent per repository, commit and kind. Recording the same run again changes nothing, and recording the same commit and kind with different results replaces the earlier record, so a retried job is harmless. `record` refuses a check summary whose finding count does not match the findings file, because the two would come from different runs.

Findings are stored by their identity (tool, rule, path and fingerprint), so the dashboard can tell when each finding was first seen and when it was fixed. A finding that disappears and later comes back counts as fixed and then new again. Findings that were already present in the first recorded run count from that run, so their ages and times to fix are lower bounds. To keep the dashboard's memory bounded, these figures come from the newest 400 trend runs (about a year of nightly scans), read two runs at a time.

The history is bounded. A run may hold at most 100,000 findings, messages are cut at 4,000 characters, and each message is stored once however many runs share it. After each record, Shoalscan keeps the newest 2,000 scheduled runs of the repository (`--max-runs`) and, counted apart, the newest 2,000 pull-request runs (`--max-pr-runs`), and drops pull-request runs more than 90 days older than the newest run (`--keep-pr-days`). Pull-request runs never push a scheduled run out, so a flood of pull requests cannot erase the history, and reviews are kept by finding identity, so pruning never drops one.

The trend charts need a regular scan of the default branch; [Scheduled scans](scheduled-scans.md) sets one up.

## Correcting the history

`shoalscan history list-runs --repo-name owner/project` lists a repository's runs, newest first, with their ids, kinds, commits and outcomes. To remove a run that should not be there, for example a first scan recorded with a temporary configuration, delete it by id:

```sh
shoalscan history delete-run --repo-name owner/project --run 12 --yes
```

Without `--yes` it only says what it would delete. It deletes the run with its findings and the lists recorded for it, prints what it deleted, and removes finding identities and messages that no other run uses. First seen, fixed, ages and times to fix are worked out from the remaining runs each time the dashboard shows them, so they stay consistent. Deleting a repository's last run removes the repository from the dashboard. Every deletion is recorded with the run's id, kind, commit and finding count, when it happened and the local account that ran it, and the Runs page says how many runs were deleted. Both commands take `--db` like `record`.

## Serving the dashboard

The dashboard serves HTTPS only and needs three things: an OpenID Connect provider for sign-in (such as Dex, Keycloak, Okta or Microsoft Entra ID), a TLS certificate and its key, and the history database. Sign-in is set up in the browser, the first time the dashboard starts (see [Signing in](#signing-in)).

Then make a certificate. `init-tls` needs the `openssl` command:

```sh
shoalscan serve init-tls --ip 127.0.0.1
```

Name every address (`--ip`) and host name (`--dns`) that people will use to reach the dashboard; repeat the options for several. `init-tls` makes a new certificate authority, has it sign one server certificate, and deletes the CA's private key, so nobody can sign another certificate with that CA afterwards. As a second safeguard, the CA's name constraints cover both kinds of name a server certificate can carry. DNS names are limited to the names you gave, or to the reserved `shoalscan.invalid` when you gave none. IP addresses are limited to the addresses you gave, and IPv4 or IPv6 is excluded entirely when you gave no address of that kind. The CA may also vouch only for TLS servers. A client that enforces name constraints, as current browsers and TLS libraries do, rejects a certificate from this CA for any other name. `init-tls` works with OpenSSL 3 and with the LibreSSL `openssl` that macOS ships. It writes `ca.pem` and `server.pem` (mode 0644, as certificates are public) and `server.key` (mode 0600) into `tls/` in the dashboard's state directory, which has mode 0700. The server certificate is valid for 397 days; run `init-tls --force` to make a new one, and trust the new CA.

Start the dashboard:

```sh
shoalscan serve
```

It listens on `127.0.0.1:8443` by default. Open `https://127.0.0.1:8443`: the first time, it takes you to the setup wizard. To serve other machines, bind to an address they can reach and name the host names and addresses they use:

```sh
shoalscan serve init-tls --dns scans.example.internal --ip 192.0.2.10
shoalscan serve --bind 0.0.0.0 --host scans.example.internal --host 192.0.2.10
```

The dashboard answers only to requests whose `Host` header is one of those names with the port. With a wildcard `--bind`, `--host` is required. Put `--state-dir` after `user`, `oidc` or `init-tls` when you use those subcommands.

### Signing in

People sign in through your organisation's OpenID Connect provider. Shoalscan never sees a password.

**Setting it up.** The first time `shoalscan serve` starts, it has no sign-in settings, so it serves only a setup wizard. It makes a one-time setup code and writes it to `setup-code` in its state directory, readable only by the account that runs the dashboard. The console names the file but never shows the code, since console output often ends up in system journals and container logs:

```text
shoalscan serve: sign-in is not set up yet. Open /setup on the dashboard and enter the one-time setup code from this file (readable only by this account):

    /home/shoal/.config/shoalscan/dashboard/setup-code

For example: cat /home/shoal/.config/shoalscan/dashboard/setup-code
The code works for 30 minutes and only while the dashboard runs; a restart makes a new one.
```

The wizard needs that code, so only someone who can read the file on the server can set up sign-in; a stranger who reaches the port first cannot. The code works for 30 minutes, and the file is deleted when it expires; after that, restart `shoalscan serve` for a new one. Saving the settings deletes the file. In the wizard:

1. Register Shoalscan at your provider as a confidential client, with the redirect URI the wizard shows (`https://<the dashboard's address>/oidc/callback`) and a client secret. For Dex, the wizard shows the `staticClients` entry to add.
2. Enter the setup code, the issuer URL, the client id and secret, and, if the provider's certificate comes from a private CA, paste that CA's certificate (PEM). The dashboard keeps it as `oidc-ca.pem` in its state directory; it never takes a file path from the browser.
3. Choose who is an admin: by default, anyone whose ID token's `groups` claim holds `shoal-admin`. Any claim works: a group, a role, or a claim that is `true`.
4. **Test the connection.** The wizard reads the provider's discovery document and signing keys, checks that ID tokens are signed with RS256, that PKCE and the scopes are supported, and that the provider accepts the client id and secret. Then **Save and go to sign-in**.

The settings are kept in `oidc.toml` in the state directory, mode 0600, since it holds the client secret. `shoalscan serve oidc show [--test]` prints them (never the secret) and checks the provider again; `shoalscan serve oidc reset` removes them, so the next start runs the wizard again.

**Who gets in.**

- **Admins** are the people whose ID token carries the admin claim. That is decided at the provider, at every sign-in: take someone out of the group there, and their next sign-in is no longer an admin's. An admin session lasts at most one hour, so that change takes effect within the hour; to take someone's admin rights away at once, also disable them here. Admins manage who may sign in, the Configuration page and scans.
- **Members** are people an admin has allowed, by email address, on the **Users** page or with `shoalscan serve user allow EMAIL`. They read every page and review findings.
- **Everyone else is refused**, even with a valid account at the provider, and is told to ask an admin.

Only email addresses the provider marks as verified count, and only plain ASCII addresses are accepted. A person's first sign-in ties their address to their account at the provider, so another account that later uses the same address is refused. An admin can take back a member's access, or disable anyone but themselves, admins included; either ends the person's sessions at once.

**Sessions.** A member's session ends after eight hours without use or after seven days; an admin's after eight hours without use or after one hour. One person can be signed in on at most 10 browsers at once; signing in on an eleventh ends their oldest session. `shoalscan serve user list|allow|disallow|disable|enable` does the same from the command line. Every change, and every first sign-in, is recorded with who and when, and the **Users** page shows it.

The people list is kept in `users.sqlite3` in the state directory (mode 0600), not in the history database: `shoalscan record` writes the history, often from CI, and nothing that can write it should be able to let someone in.

**How sign-in works.** **Sign in** sends you to the provider with the authorization code flow, PKCE (S256), a `state` tied to a short-lived signed cookie and a `nonce`; the dashboard itself keeps nothing for a sign-in in progress. When you come back, Shoalscan swaps the code for an ID token at the provider's token endpoint, using the client secret over TLS, and checks the token's RS256 signature against the provider's published keys, its issuer, audience, authorised party, expiry and nonce. The issuer must match exactly what the provider publishes, trailing slash included.

Starting a sign-in is limited per client address to a burst of 30, then one every 10 seconds, and failed sign-ins are limited per address too. Behind a reverse proxy, a load balancer, NAT or a container port mapping, the dashboard sees one address for everyone, so all clients share these limits. The burst lets a team sign in together; if people see "Too many sign-ins were started from your network address", they wait a minute and try again. The provider must be reached over https (plain http only on the loopback interface), with its certificate checked; proxy settings are ignored.

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

- **Overview:** the latest run's result, the blocking findings, how far the [similar-finding embeddings](triage.md#the-similar-findings-panel) cover the latest run, tiles with the key numbers, open findings by severity over time, the baseline burning down, new and fixed findings per week, the mean time to fix, how old the open findings are, a heatmap of findings by component, inline suppressions over time, and files that were not fully scanned.
- **Findings:** a table you can filter by run, severity, rule, component, path, age, and whether a finding is new or new and blocking. Each rule links to its message and every place it was found. The **Suggestion** column shows, for an untriaged finding, the decision of its most similar decided finding and where that decision comes from (a review, or the baseline of a scheduled run); **Use the suggestion** sets the bulk review's status, and you write the description ([Suggestions on the Findings page](triage.md#suggestions-on-the-findings-page)). The [Groups](triage.md#groups-of-similar-findings) page gathers similar untriaged findings so one review can cover them.
- **Runs:** every recorded run with its status and counts. Select a run to see its detail and links to everything behind its numbers: its findings, the new and new blocking ones, stale baseline entries, inline suppressions and files that were not fully scanned. When the repository has runs of pull request heads (`refs/pull/N/head`, as [`scanjob --pull-requests`](scheduled-scans.md#scanning-the-open-pull-requests-of-a-public-repository) records them), a **Pull requests** table above the runs shows each pull request's latest run: its number, head commit, status, new blocking and new findings, changed files that were not fully scanned, and how many runs it has.
- **About:** what Shoalscan is, who it is for, the scanners and rule sources with their pinned versions and licences, and the limits of static analysis.

A run's status says what happened in words. **Passed** means the check passed. **Blocked** names the first reason, such as "Blocked: 3 new blocking findings", and lists the others: stale baseline entries, changed files that were not fully scanned, or added baseline entries. A short explanation links to the new blocking findings. **Scan error** means the check could not run, so the run has no results.

Near the top of the Overview, the **Blocking findings** panel answers "what should we fix first?". It counts the findings the policy treats as blocking (a blocking severity outside `non_blocking_paths`, as the check decided), split into **new** ones, which fail pull requests, and **baselined** ones, the backlog accepted at adoption. Both numbers are links. A small line shows the count over the scheduled runs, so the burn-down of what matters is visible. Below it are the ten findings to fix first: new blocking findings first, then ERROR before WARNING, then the component with the highest heat score, then the oldest. "See all" opens the Findings page with the **Blocking only** filter, which sorts the same way by default; any view can choose this **Fix priority** sort. Runs recorded before this feature, or without a `check.json` that lists the blocking class, show it as unknown.

Every number that has a list behind it is a link. Each tile, each point on the severity chart and its legend, each bar of the weekly and age charts, and each heatmap cell opens the findings or the list it counts. Numbers with no list behind them, such as the baseline size or the mean time to fix, are not links. The filters live in the address, so a filtered view can be bookmarked or shared, and the back button works. Links are ordinary links that a keyboard can reach.

The heatmap ranks components by a heat score, ERROR × 10 + WARNING × 3 + INFO, with components that have new blocking findings first. Each cell shows its count, and its shade grows with the count; a bar beside each row shows the score. The top 15 components are shown, and a button shows the rest.

One database can hold several repositories, and the dashboard has a repository selector. The trend charts, the headline "Latest run", the repository list and the Configuration page's last run use only the scheduled scans of the default branch. Pull-request runs never feed them, because they scanned a change nobody has accepted yet (on a public repository, anyone can open one); they show on the Runs page and in its Pull requests table.

**Next:** [Reviewing findings](reviewing-findings.md), [Scheduled scans](scheduled-scans.md) and [Scanning from the dashboard](dashboard-scanning.md).
