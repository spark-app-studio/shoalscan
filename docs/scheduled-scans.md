# Scheduled scans

The [dashboard's](dashboard.md) trend charts need a regular scan of the default branch, and [reviews](reviewing-findings.md) of fixed findings are verified by the newest scheduled run. There are two ways to run one each night: the example script, for one repository you keep a clone of, or `scanjob --nightly`, for every repository registered with the dashboard.

## The example script

`examples/scheduled-scan.sh` does one scheduled scan: it fetches a clone you keep for scanning, scans the head of the default branch in a temporary worktree (so the clone's own checkout is never touched), runs `check`, and records the run as `scheduled`. It exits with 0 when the run was recorded, whether the check passed or failed, and with 2 when the scan or the setup failed; then nothing is recorded, because a failed scan is never "no findings".

```sh
SHOALSCAN_SPEC="shoalscan @ git+https://github.com/spark-app-studio/shoalscan@<commit-sha>" \
SHOALSCAN_REPO_NAME=owner/project \
examples/scheduled-scan.sh ~/scans/project
```

The script makes its virtual environment with `python3`. Set `SHOALSCAN_PYTHON` to use another interpreter, for example `SHOALSCAN_PYTHON=/usr/local/bin/python3.12` on a machine whose `python3` is older. The script stops with a clear message, and records nothing, when that Python is older than 3.11. By default the script passes `--require-network-sandbox`, so the scan fails unless the scanners can run without network access ([Scanner isolation](security-model.md#scanner-isolation)); set `SHOALSCAN_REQUIRE_NETWORK_SANDBOX=0` to scan on a machine without a sandbox. The other settings are listed at the top of the script.

### Running it every night

- **macOS:** `examples/scheduled/local.shoalscan.scheduled-scan.plist` is a launchd agent that runs at 02:30. Edit the paths, copy it to `~/Library/LaunchAgents/`, and load it with `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/local.shoalscan.scheduled-scan.plist`.
- **Linux:** `examples/scheduled/shoalscan-scan.service` and `shoalscan-scan.timer` are systemd user units. Edit the paths, copy both to `~/.config/systemd/user/`, then run `systemctl --user daemon-reload` and `systemctl --user enable --now shoalscan-scan.timer`. Run `loginctl enable-linger "$USER"` so it also runs when you are not logged in.

## One nightly job for every registered repository

`shoalscan scanjob --nightly --state-dir <state dir>` scans every enabled repository with `nightly = true` in the dashboard's [`scan_targets.toml`](dashboard-scanning.md#registering-repositories-scan_targetstoml), one after another, with the same worker, lock and audit as the dashboard's **Run a fresh scan**. It skips disabled repositories and the ones without `nightly`, and waits for a scan started from the dashboard to finish. `examples/scheduled/local.shoalscan.nightly-targets.plist` (launchd) and `examples/scheduled/shoalscan-nightly-targets.service` with its `.timer` (systemd) run it every night. `shoalscan scanjob --target owner/project --state-dir <state dir>` scans one repository from the command line.

## Pull-request runs

Pull-request runs can be recorded too, with `--kind pr`, on a machine that holds the history database. They show on the Runs page. Once a repository has scheduled runs, pull-request runs no longer feed its trend charts.

## Scanning the open pull requests of a public repository

A public repository's pull requests should not run on your own CI runners: anyone can open one. `shoalscan scanjob --pull-requests --state-dir <state dir>` lets the Shoalscan machine scan them itself instead, with no GitHub credentials and no GitHub Actions at all. Turn it on per repository with `pull_requests = true` in [`scan_targets.toml`](dashboard-scanning.md#registering-repositories-scan_targetstoml), on a target with an https `source`:

```toml
max_pull_requests = 10       # optional: at most this many pull requests scanned per poll (1 to 100)

[[target]]
name = "owner/project"
source = "https://github.com/owner/project.git"
branch = "main"
nightly = true
pull_requests = true         # set by hand only
```

Each poll does this for every enabled target with `pull_requests = true`, one after another:

1. **List the pull requests.** One anonymous `git ls-remote` of the source lists `refs/heads/<branch>`, `refs/pull/*/head` and `refs/pull/*/merge`. It runs with the same git hardening as every other fetch: https only, no prompts, no credential helpers, no redirects. It does not use the GitHub API, so it needs no token and meets no API rate limit.
2. **Decide which ones are open.** GitHub keeps `refs/pull/N/head` for every pull request ever opened, so a head ref alone says nothing. `refs/pull/N/merge`, GitHub's test merge with the base branch, exists for open pull requests that can be merged, so a pull request with a merge ref is a candidate. An open pull request with conflicts may have no merge ref; it is still a candidate when an earlier pull-request run of its `refs/pull/N/head` is recorded, so its new heads keep being scanned.
3. **Skip what is already scanned.** A head commit that already has a pull-request run in the history is skipped, whatever recorded it. The rest are scanned newest first, at most `max_pull_requests` per poll; the others wait for the next poll.
4. **Scan each head as a pull-request run.** The worker fetches `refs/pull/N/head` into a ref of its own in the existing clone (`refs/shoalscan/pull/N`, removed afterwards), checks that it is still the commit the listing showed, and scans it in a temporary worktree, exactly like a scheduled scan: the same lock, deadline (`timeout_minutes`), free-space check (`min_free_mb`), clone size limit (`max_clone_mb`), network sandbox and git hardening, so no hook, filter driver, LFS download or submodule runs on the fetched code. The run is recorded with `--kind pr` and the ref `refs/pull/N/head`.

The pull request never decides how it is checked. Its policy is the one a scheduled scan of the target uses: the target's configuration file or managed policy, else the `.shoalscan.toml` at the head of the registered branch, read from git. Its baseline is the target's baseline file outside the clone. The repository rule directories the policy names are read from the head of the registered branch (`scan --rules-commit`), and the changed files are listed against the merge base of the pull request and that head (`check --changed-since`), so a changed file that could not be fully scanned fails the run, as it does under `--policy-ref` in CI. A new finding is one the target's baseline does not accept.

The results stay on the dashboard: the Runs page lists each pull request with its latest run, its number and its head commit ([The pages](dashboard.md#the-pages)). Nothing is posted to the pull request or anywhere else.

Polls respect the dashboard's limits. A target is polled again only after `cooldown_minutes`, and every pull-request scan counts against `max_scans_per_hour`, which the dashboard's own scans share; a poll stops scanning when the hourly cap is reached and leaves the rest for the next poll. Every scan is audited on the Runs page under "pull-request poll", with the pull request's number and head commit.

The poll fails closed. When the listing fails, times out, prints more than 32 MB, has a line that is not a ref, lists a ref twice, or does not show the registered branch (the proof that it really is a listing of that repository), the poll records a scan error in the scan audit and exits with 1; it never reports "nothing to scan". A pull request that moved between the listing and the fetch records nothing and is scanned on the next poll, and so is one whose scan timed out or failed before it was recorded. A head whose run was recorded as a scan error is not tried again until it changes.

Limits of the listing, as GitHub behaves today:

- An open pull request with conflicts and no earlier run may have no merge ref, so it is not found until its conflicts are resolved.
- Some closed pull requests, and pull requests GitHub has deleted, keep their merge refs. Each one is scanned at most once, because its head never changes again. The first poll of a busy repository can find several of them; `max_pull_requests` bounds each poll, newest first.
- A pull request is checked against the target's registered branch, whatever branch it targets.
- Forges other than GitHub name their pull request refs differently (GitLab uses `refs/merge-requests/N/head`); only GitHub's `refs/pull/` refs are listed.

### Running the poll regularly

Run the poll more often than the nightly job, for example every 15 minutes. It returns quickly when nothing is new. A poll that finds the cooldown still running for a target skips it, so set `cooldown_minutes` no longer than the interval.

- **macOS:** `examples/scheduled/local.shoalscan.pull-requests.plist` is a launchd job that runs `scanjob --pull-requests` every 15 minutes (`StartInterval` 900). Edit the paths, copy it to `~/Library/LaunchAgents/` (or `/Library/LaunchDaemons/` for a job that runs as a service account), and load it with `launchctl bootstrap`.
- **Linux:** `examples/scheduled/shoalscan-pull-requests.service` and `shoalscan-pull-requests.timer` are systemd user units that do the same.

The exit status is 0 when every pull request scanned was recorded (passed or blocked) and nothing failed, and 1 when a listing or a scan failed.

**Next:** [Scanning from the dashboard](dashboard-scanning.md).
