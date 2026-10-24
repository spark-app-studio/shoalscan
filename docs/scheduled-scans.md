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

Pull-request runs can be recorded too, with `--kind pr`, on a machine that holds the history database. They show on the Runs page. Pull-request runs never feed the trend charts or the headline run.

## Scanning the open pull requests of a public repository

A public repository's pull requests should not run on your own CI runners: anyone can open one. `shoalscan scanjob --pull-requests --state-dir <state dir>` lets the Shoalscan machine scan them itself instead, with no GitHub credentials and no GitHub Actions at all. Turn it on per repository with `pull_requests = true` in [`scan_targets.toml`](dashboard-scanning.md#registering-repositories-scan_targetstoml), on a target with an https `source`:

```toml
max_pull_requests = 10       # optional: at most this many pull requests scanned per poll (1 to 100)
max_pr_scans_per_hour = 6    # optional: pull-request scans per hour, a budget apart from the dashboard's (1 to 60)

[[target]]
name = "owner/project"
source = "https://github.com/owner/project.git"
branch = "main"
nightly = true
pull_requests = true         # set by hand only
```

Everything in a pull request is treated as written by an attacker: its code, its file names, its size, its configuration and how often it is pushed to. Each poll does this for every enabled target with `pull_requests = true`, one after another:

1. **List the pull requests.** One anonymous `git ls-remote` of the source lists `refs/heads/<branch>`, `refs/pull/*/head` and `refs/pull/*/merge`. It runs with the same git hardening as every other fetch (https only, no prompts, no credential helpers, no redirects) and with `HOME=/nonexistent`, so no `~/.netrc` is ever read. It does not use the GitHub API, so it needs no token and meets no API rate limit.
2. **Decide which ones are open.** GitHub keeps `refs/pull/N/head` for every pull request ever opened, so a head ref alone says nothing. A pull request is a candidate when:
   - it has `refs/pull/N/merge`, GitHub's test merge with the base branch, which exists for open pull requests that can be merged;
   - an earlier pull-request run of its `refs/pull/N/head` is recorded, so an open pull request that later gets conflicts keeps being scanned; or
   - the target's poll state says so. The first poll of a target writes `pull_requests/<target>.json` in the state directory, with the highest pull request number it saw (the high-water mark) and every head it listed. From then on, a pull request above the mark (opened since polling began, such as one that conflicts from its first push and so never gets a merge ref), or one whose head moved since the previous poll, is a candidate, and stays one. The hundreds of closed pull requests whose head refs GitHub keeps are never scanned by the first poll, and later only when one moves.
3. **Skip what is already scanned, fairly.** A head that already has a pull-request run with results is skipped, whatever recorded it, as long as nothing it depends on changed (see below). A pull request is scanned at most once an hour, however often it is pushed to; the hour counts from its last attempt, whether or not that attempt recorded anything. The candidates go in order of when their pull request was last scanned or attempted: never first, then the longest ago, lower numbers first among equals; heads whose results are out of date come after the never-scanned ones, and retries of scan errors last. That order has a cost: while new pull requests or new heads keep arriving, they can use up the hourly budget and push the rescans of older heads (after the registered branch moved, say) to later polls. Only a pull request that looks open (it has a merge ref, or the poll state makes it eligible) is rescanned or has a scan error retried; a closed one never is. At most `max_pull_requests` go per poll and `max_pr_scans_per_hour` per hour; the others wait for the next poll. So one busy pull request, or a flood of new ones, cannot keep the others waiting for long, and pull requests never use up the dashboard's `max_scans_per_hour` or delay the nightly job.
4. **Fetch the head into a throwaway repository.** The worker fetches `refs/pull/N/head` into a bare repository in its temporary work directory that borrows the branch clone's objects read-only (`objects/info/alternates`), and removes that repository afterwards. When the pull request was pushed to after the listing, the head it fetched is its real head at that moment, and that is what is scanned and recorded. The fetch is always anonymous, from the target's https source; a mirror or a hand-set clone is refused by name. The pull request's objects never enter the branch clone or count against its size; they have their own `max_clone_mb` limit, and a fetch that grows past it is stopped.
5. **Check the size before checking out.** Git objects are compressed, so a few kilobytes of objects can expand to gigabytes. Before the checkout, the worker lists the commit's tree and refuses it when it would be larger than `max_checkout_mb`, has more files than `max_checkout_files`, has a path deeper than 64 directories, or the disk cannot hold it twice (Gitleaks may copy it) besides `min_free_mb`, counting each file's size in whole 4 KiB blocks plus 4 KiB for its inode and directory entry. The size is also watched while git writes the checkout.
6. **Scan the head as a pull-request run**, in a temporary worktree, exactly like a scheduled scan: the same lock, deadline (`timeout_minutes`), network sandbox and git hardening, so no hook, filter driver, LFS download or submodule runs on the fetched code, and scanner output is stripped of control and escape sequences before it reaches the log. The run is recorded with `--kind pr` and the ref `refs/pull/N/head`.

The **head** of the pull request is scanned, not GitHub's merge result: the code the author wrote, compared with its merge base on the registered branch.

The pull request never decides how it is checked:

- Its policy is the one a scheduled scan of the target uses: the target's configuration file or managed policy, else the `.shoalscan.toml` at the head of the registered branch, read from git. Its baseline is the target's baseline file outside the clone.
- The repository rule directories the policy names are read from the head of the registered branch (`scan --rules-commit`).
- The changed files are listed against the merge base of the pull request and that head (`check --changed-since`), so a changed file that could not be fully scanned fails the run, as it does under `--policy-ref` in CI.
- A new finding is one the target's baseline does not accept. An inline suppression the pull request adds on one of its changed lines fails the run too, and so does any finding a scanner silenced because of an inline comment when its lines overlap the lines the pull request added, even under a marker that was already on the branch (an Opengrep marker silences the next line too, and a Trivy marker the block below it): a change from outside cannot silence a finding itself. The added lines come from a textual diff, so a NUL byte cannot make a file look unchanged; a changed file whose diff shows no lines counts as added in full, and every Trivy marker inside a changed chart archive counts as new.
- A stale baseline entry (the pull request fixed a baselined finding) is reported but does not fail the run: the pull request cannot change the baseline, and a fix is no new risk.
- The results depend on the head of the registered branch and the target's policy and baseline files as well as on the pull request's head. The poll state keeps a scan key (a SHA-256 of those) for each head's results, and a head whose results were recorded under another key is scanned again, within the limits above. The key uses the registered branch's head, not only the content of the policy, rule directories and baseline, so every push to the branch makes every open pull request's results out of date; those rescans come after every new head, so they use only budget that new pull requests leave.

The results stay on the dashboard: the Runs page lists each pull request with its latest run, its number, its head commit, its new and new blocking findings, its suppressions and new suppressions, and, for a failed scan, why it failed ([The pages](dashboard.md#the-pages)). Pull-request runs never feed the trend charts or the headline run. Nothing is posted to the pull request or anywhere else.

A target is polled again only after `cooldown_minutes`. The dashboard and the poll change `scan_requests.json` under the same lock, and a reservation in the hourly budget is given back when its scan never started. Every scan is audited on the Runs page under "pull-request poll", with the pull request's number and head commit.

The poll fails closed:

- When the listing fails, times out, prints more than 32 MB, has a line that is not a ref, lists a ref twice, or does not show the registered branch (the proof that it really is a listing of that repository), or when the poll state cannot be read, the poll records a scan error in the scan audit and exits with 1; it never reports "nothing to scan".
- A failure the pull request caused (its fetch, the size of its objects or checkout, its checkout, its scan, or the deadline once its own fetch had started) is recorded as a pull-request run of its head with the outcome scan error, so it shows on the dashboard and is not tried again until the head changes, or after a day, after every other candidate, while the pull request looks open.
- A failure of this machine (the branch clone's fetch, free disk space, an old git, the policy, the record) is a failed attempt of the poll: nothing is recorded against the head, and the next poll tries again after the pull request's hour.
- Every attempt that did not start a scan gives its place in `max_pr_scans_per_hour` back.

Limits, as GitHub behaves today:

- An open pull request that existed before the first poll, conflicts with its base and never had a run has no merge ref, so it is not found until its head moves or its conflicts are resolved.
- Some closed pull requests, and pull requests GitHub has deleted, keep their merge refs. Each one is scanned at most once, because its head never changes again.
- A pull request is checked against the target's registered branch, whatever branch it targets.
- Inline markers of other scanners (Trivy's) on changed lines are not counted as new suppressions.
- A repository with more than 10,000 inline suppressions or more than 10,000 silenced findings cannot have its pull requests checked: `check --changed-since` stops (a scan error) rather than guess which ones a pull request added.
- Forges other than GitHub name their pull request refs differently (GitLab uses `refs/merge-requests/N/head`); only GitHub's `refs/pull/` refs are listed.

### Running the poll regularly

Run the poll more often than the nightly job, for example every 15 minutes. It returns quickly when nothing is new. A poll that finds the cooldown still running for a target skips it, so set `cooldown_minutes` no longer than the interval.

- **macOS:** `examples/scheduled/local.shoalscan.pull-requests.plist` is a launchd job that runs `scanjob --pull-requests` every 15 minutes (`StartInterval` 900). Edit the paths, copy it to `~/Library/LaunchAgents/` (or `/Library/LaunchDaemons/` for a job that runs as a service account), and load it with `launchctl bootstrap`.
- **Linux:** `examples/scheduled/shoalscan-pull-requests.service` and `shoalscan-pull-requests.timer` are systemd user units that do the same.

The exit status is 0 when every pull request scanned was recorded (passed or blocked) and nothing failed, and 1 when a listing or a scan failed.

**Next:** [Scanning from the dashboard](dashboard-scanning.md).
