# Contributing to Shoalscan

Thank you for your interest in Shoalscan. This guide explains how to set up a working copy, what we expect from a change, and how a pull request is reviewed. By taking part in the project you agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

If you think you have found a security vulnerability, please do not open a public issue or pull request. Follow [SECURITY.md](SECURITY.md) instead, so that the problem can be fixed before it is made public.

## Setting up

Shoalscan uses the Python standard library only, so there is nothing to install apart from Python itself. You need Python 3.11 or later, git, and Linux or macOS.

```sh
git clone https://github.com/spark-app-studio/shoalscan.git
cd shoalscan
```

You can run the command line straight from the source tree by putting `src` on the Python path:

```sh
PYTHONPATH=src python3 -m shoalscan --version
```
## Running the tests

Run the whole test suite from the root of the repository:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
```

A single test module or test case can be run the same way, for example `PYTHONPATH=src python3 -m unittest tests.test_baseline`.

The end-to-end tests run the real Opengrep binary, so they need the pinned scanners. Install them once with `PYTHONPATH=src python3 -m shoalscan install`. If you keep the tools somewhere other than the default cache directory, point `SHOALSCAN_TOOLS_DIR` at that directory. Without the tools, these tests are skipped and the skip message says why. Continuous integration runs the suite on Python 3.11, 3.12 and 3.13, so please make sure a change works on 3.11.

Shoalscan's own Opengrep rules in `rules/` have tests next to them. After installing the tools, run them with:

```sh
~/.cache/shoalscan/tools/opengrep scan --test rules/
```

[docs/development.md](docs/development.md) and [docs/rules.md](docs/rules.md) have more detail.

## Code style

- **Standard library only.** Shoalscan has no runtime dependencies, and that is a deliberate part of its security model: everything it runs is either in this repository or pinned in `tools.lock`. A change that adds a runtime dependency needs to be discussed in an issue first, before any code is written.
- **Type hints** on new and changed functions.
- **Small, focused changes.** One pull request should do one thing. A refactor and a behaviour change are easier to review as two pull requests.
- **PEP 8, checked by Ruff,** with 120-character lines. Ruff formats the code and checks PEP 8 naming, layout and import order; CI runs both. Install the pinned version and run it before you push:

  ```sh
  python3 -m pip install --require-hashes -r requirements-dev.txt
  ruff format src tests scripts && ruff check src tests scripts
  ```

  Ruff is a development tool only; it is not a dependency of Shoalscan. The configuration is in `pyproject.toml`. The schema migrations in `history.py` are exempt from the line length, because shipped migrations are never edited.
- Follow the style of the surrounding code. Prefer clear names and plain control flow over clever tricks.
- Fail closed. When Shoalscan cannot be sure a scan or a check is correct, it must report an error rather than a pass.

## What every change needs

- **A test.** Every behaviour change, including every bug fix, comes with a test that fails without the change and passes with it. Please check this yourself by running the new test against the code before your change.
- **Documentation.** If the change affects how Shoalscan is used or configured, update the relevant guide in `docs/` in the same pull request. The README stays short, so details belong in `docs/`.
- **A CHANGELOG entry.** Add a line under an "Unreleased" heading at the top of [CHANGELOG.md](CHANGELOG.md), creating the heading if it is not there yet. Describe the change from the user's point of view.

## Commit messages

Write a short summary line of about 70 characters or fewer, in the imperative mood, for example "Refuse a baseline entry without a reason". Leave a blank line, then explain what the change does and why, wrapped at about 72 characters. If the commit fixes an issue, mention it, for example "Fixes #12". Keep each commit focused; it is fine for a pull request to have several commits that each make sense on their own.

## Developer Certificate of Origin

Shoalscan uses the [Developer Certificate of Origin](https://developercertificate.org/) (DCO), version 1.1. Every commit must be signed off. A sign-off is a line at the end of the commit message:

```text
Signed-off-by: Your Name <your.email@example.com>
```

Git adds it for you when you commit with `-s`:

```sh
git commit -s -m "Refuse a baseline entry without a reason"
```

By signing off, you certify that you wrote the change, or otherwise have the right to submit it under the project's open-source licence (Apache License 2.0), and that you understand the contribution and your sign-off are recorded publicly. The full text is at [developercertificate.org](https://developercertificate.org/). The name and email address must be real, and they should match the commit author. We do not ask for a separate contributor licence agreement.

If you forgot to sign off, you can fix the last commit with `git commit --amend -s --no-edit`, or several commits with `git rebase --signoff origin/main`, and then force-push your branch.

## Proposing a new scanner or rule

Please open an issue before you start work on a new scanner or a new Opengrep rule. A scanner affects what `shoalscan install` downloads and verifies, so we want to agree on how it is pinned, how its signature or checksum is checked, how its output maps to Shoalscan's finding format, and what its licence allows. A rule needs a clear case for what it catches and a plan for keeping false positives low, because we value fewer false positives over wider coverage. The issue is the place to settle these questions so that your time is not wasted.

Rules are deliberately conservative. A new rule needs metadata (CWE, severity, confidence and a short fix hint) and Opengrep tests that show both what it reports and what it leaves alone.

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Make your change, with tests, documentation and a CHANGELOG entry.
3. Run the test suite, and the rule tests if you changed a rule.
4. Open a pull request and fill in the template. Link the issue it addresses.

All continuous-integration checks must pass before a pull request can be merged. A maintainer will review it, usually within a week. Reviews may ask for changes; please push new commits to the same branch rather than opening a new pull request. A maintainer merges the pull request once it has been approved and the checks pass. Changes to the security model, to supply-chain verification or to the dashboard's authentication get an especially careful review, so expect more questions on those.

If a pull request goes quiet for a long time, we may close it. You are always welcome to reopen it or pick it up again later.

## Questions

For questions about using Shoalscan, start with the guides in [docs/](docs). If they do not answer your question, or they seem wrong or unclear, open an issue with the bug report form; unclear documentation is a bug too. Please search existing issues first.
