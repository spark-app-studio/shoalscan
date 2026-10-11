# Scheduled scans

The [dashboard's](dashboard.md) trend charts need a regular scan of the default branch, and [reviews](reviewing-findings.md) of fixed findings are verified by the newest scheduled run. There are two ways to run one each night: the example script, for one repository you keep a clone of, or `scanjob --nightly`, for every repository registered with the dashboard.

## The example script

`examples/scheduled-scan.sh` does one scheduled scan: it fetches a clone you keep for scanning, scans the head of the default branch in a temporary worktree (so the clone's own checkout is never touched), runs `check`, and records the run as `scheduled`. It exits with 0 when the run was recorded, whether the check passed or failed, and with 2 when the scan or the setup failed; then nothing is recorded, because a failed scan is never "no findings".

```sh
SHOALSCAN_SPEC="shoalscan @ git+https://github.com/spark-app-studio/shoalscan@<commit-sha>" \
SHOALSCAN_REPO_NAME=owner/project \
examples/scheduled-scan.sh ~/scans/project
```

The script makes its virtual environment with `python3`. Set `SHOALSCAN_PYTHON` to use another interpreter, for example `SHOALSCAN_PYTHON=/usr/local/bin/python3.12` on a machine whose `python3` is older. The script stops with a clear message, and records nothing, when that Python is older than 3.11. The other settings are listed at the top of the script.

### Running it every night

- **macOS:** `examples/scheduled/local.shoalscan.scheduled-scan.plist` is a launchd agent that runs at 02:30. Edit the paths, copy it to `~/Library/LaunchAgents/`, and load it with `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/local.shoalscan.scheduled-scan.plist`.
- **Linux:** `examples/scheduled/shoalscan-scan.service` and `shoalscan-scan.timer` are systemd user units. Edit the paths, copy both to `~/.config/systemd/user/`, then run `systemctl --user daemon-reload` and `systemctl --user enable --now shoalscan-scan.timer`. Run `loginctl enable-linger "$USER"` so it also runs when you are not logged in.

## One nightly job for every registered repository

`shoalscan scanjob --nightly --state-dir <state dir>` scans every enabled repository with `nightly = true` in the dashboard's [`scan_targets.toml`](dashboard-scanning.md#registering-repositories-scan_targetstoml), one after another, with the same worker, lock and audit as the dashboard's **Run a fresh scan**. It skips disabled repositories and the ones without `nightly`, and waits for a scan started from the dashboard to finish. `examples/scheduled/local.shoalscan.nightly-targets.plist` (launchd) and `examples/scheduled/shoalscan-nightly-targets.service` with its `.timer` (systemd) run it every night. `shoalscan scanjob --target owner/project --state-dir <state dir>` scans one repository from the command line.

## Pull-request runs

Pull-request runs can be recorded too, with `--kind pr`, on a machine that holds the history database. They show on the Runs page. Once a repository has scheduled runs, pull-request runs no longer feed its trend charts.

**Next:** [Scanning from the dashboard](dashboard-scanning.md).
