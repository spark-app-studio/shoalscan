# Scanning from the dashboard

The [dashboard](dashboard.md) can start scans itself, but only of repositories registered on the server, and the feature is off until you register one. It adds three things: **Run a fresh scan** on the Runs page, **Rescan** buttons on the latest run and on a run's detail, and a **Configuration** page that lists and edits the registered repositories.

## Requirement: git 2.40 or later

Scanning from the dashboard needs **git 2.40 or later**. The worker reads git attributes from an empty tree (`GIT_ATTR_SOURCE`), so a scanned repository's `.gitattributes` cannot make a checkout run a filter driver, such as git-lfs downloading from a URL the repository chose. Older git, such as the git 2.34 that Ubuntu 22.04 ships, silently ignores that setting. Shoalscan does not trust the version number: before every scan it checks, with a throwaway repository, that git really ignores the repository's attributes, and it refuses to scan when it does not. The dashboard then shows "git 2.40 or later is required: it must honour GIT_ATTR_SOURCE" and disables the scan buttons.

## Registering repositories: `scan_targets.toml`

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

The file must be owned by the user that runs Shoalscan and must not be writable by anyone else; the dashboard refuses to start otherwise. Every key is checked, and an unknown key is an error.

### Sources: public repositories, mirrors and hand-set clones

Each target has exactly one source:

- **`source`**, an https URL of a public repository on an allowed host. The allowed hosts are `github.com`, `gitlab.com` and `bitbucket.org`, unless `allowed_hosts.toml` in the state directory says otherwise (`hosts = ["github.com"]`). The server clones only the registered branch, with its full history so earlier commits can be rescanned, into `clones/` in the state directory, and fetches only that branch, with git limited to https, with no prompts and no credential helpers. Private repositories cannot be scanned this way.
- **`mirror`**, the name of a local clone registered in `local_sources.toml` in the state directory (`[[mirror]]` tables with a `name` and an absolute `path`). Use a mirror for a private repository: you keep it up to date yourself, for example with `git fetch` in a cron job, and Shoalscan never fetches it or needs its credentials.
- **`clone`**, an absolute path to a clone, set only by editing the file. Shoalscan fetches it with your own git setup, as `examples/scheduled-scan.sh` does.

A repository added on the Configuration page gets its policy and baseline in `targets/<name>/` in the state directory: `shoalscan.toml` is the policy text from the page, and `baseline.toml` is its baseline.

## Starting a scan

A request to scan names a registered repository and nothing else. Only one scan runs at a time: a second request gets 409 with the running scan's status. A repository can be scanned again only after its cooldown, and the hourly cap applies to all repositories; both answer 429 with the time to wait.

The scan runs in a separate worker, not in the web server. It fetches the clone, scans the head of the branch in a temporary worktree, and runs `scan`, `check` and `record --kind scheduled --check-exit` with a deadline; a scan that passes the deadline is stopped and records nothing. The Runs page polls the status while a scan runs; the log lines it shows have every absolute path removed. [Security model](security-model.md#the-scan-worker) describes how the request and the worker are constrained.

### Rescan

**Rescan** scans the branch's current tip again. **Rescan this commit**, on a run's detail, scans exactly the commit that run scanned: the browser sends only the repository's name and the run's number, the worker looks the commit up in the history database, and checks that it is a full commit SHA still in the clone after a fetch. The new record replaces that run, which is then labelled "Rescanned". A commit that is no longer in the clone fails with a clear message and records nothing.

### The scan audit

Every scan started from the dashboard, the command line or the nightly job is audited in the history database with who started it, when, what kind of request it was, its outcome and the run it produced. The Runs page shows them. The dashboard has a single login token, so the person is recorded as "dashboard user".

## The Configuration page

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

## Nightly scans of registered repositories

`shoalscan scanjob --nightly --state-dir <state dir>` scans every enabled repository with `nightly = true`. [Scheduled scans](scheduled-scans.md#one-nightly-job-for-every-registered-repository) describes it and its example units.

**See also:** [Security model](security-model.md).
