# CI

Shoalscan runs as one step in any CI system. On a pull request, pass `--policy-ref` with the base commit's full SHA to both `scan` and `check`, so the configuration, the baseline and the rule directories come from the base branch ([why](baseline-and-check.md#pull-requests-the-policy-comes-from-the-base-branch)). Nothing needs a token or a secret.

## GitHub Actions

[`examples/github-actions/shoalscan.yml`](../examples/github-actions/shoalscan.yml) is a GitHub Actions workflow with every action pinned by commit SHA. Copy it to `.github/workflows/shoalscan.yml`. It needs no secrets, reads the policy from the base branch on pull requests (`github.event.pull_request.base.sha`), and uploads the SARIF file to code scanning. It also runs a nightly full scan of the default branch.

## Self-hosted runners and other CI systems

[`examples/self-hosted.sh`](../examples/self-hosted.sh) does the same on any machine with Python 3.11 or later, such as a self-hosted runner, GitLab CI, Jenkins, Buildkite or Drone. It keeps the exit codes: 0 pass, 1 fail, 2 broken. It installs Shoalscan into a virtual environment and reinstalls it when the pinned install spec changes. Set these variables:

- `SHOALSCAN_SPEC`: what pip installs; pin it to a reviewed commit or release, for example `shoalscan @ git+https://github.com/spark-app-studio/shoalscan@<sha>`.
- `SHOALSCAN_HOME`: where the virtual environment and tools live (default `$HOME/.cache/shoalscan`).
- `SHOALSCAN_OUT`: where `findings.json` and `findings.sarif` go (default a new temporary directory).
- `SHOALSCAN_POLICY_REF`: on a pull request, the base commit's full SHA, or a fully qualified ref such as `refs/remotes/origin/main`. Short names are refused.

```sh
SHOALSCAN_SPEC="shoalscan @ git+https://github.com/spark-app-studio/shoalscan@<commit-sha>" \
SHOALSCAN_POLICY_REF="$BASE_SHA" \
examples/self-hosted.sh .
```

To keep a history of runs for the dashboard, record each run after `check`; see [The dashboard](dashboard.md#recording-a-run) and [Scheduled scans](scheduled-scans.md).

## CODEOWNERS

Shoalscan's policy files decide what fails a pull request. Require a review from the people who own security for every change to them. [`examples/CODEOWNERS`](../examples/CODEOWNERS) has the lines to copy into `.github/CODEOWNERS` (or your forge's equivalent); replace the team name and adjust the paths to your rule directories and workflow:

```
/.shoalscan.toml                     @your-org/security
/.shoalscan/                         @your-org/security
/security/rules/                     @your-org/security
/.github/workflows/shoalscan.yml     @your-org/security
```

The policy-from-base model is only as strong as the protection of the base branch; see [Limits](limits.md#limits-of-shoalscans-safeguards).

**Next:** [Rules](rules.md).
