# Development

Shoalscan uses the Python standard library only, for the command line and the dashboard. The source is in `src/shoalscan/`, the tests in `tests/`, and Shoalscan's own Opengrep rules in `rules/`.

## Running the tests

Run the tests with:

```sh
python3 -m unittest discover -s tests
```

Without an installed package, put the source on the path: `PYTHONPATH=src python3 -m unittest discover -s tests`.

The end-to-end tests run the real Opengrep, so install the tools first with `shoalscan install` (or `PYTHONPATH=src python3 -m shoalscan install`). Without them those tests are skipped, and the skip message says why. Set `SHOALSCAN_TOOLS_DIR` to use tools installed somewhere else.

Shoalscan's own rules have Opengrep tests next to them; [Rules](rules.md#shoalscans-own-rules) shows how to run them.

## Code style

The code follows PEP 8 with 120-character lines, formatted and checked by Ruff, pinned by hash in `requirements-dev.txt`:

```sh
python3 -m pip install --require-hashes -r requirements-dev.txt
ruff format src tests scripts fuzz
ruff check src tests scripts fuzz
```

CI runs both checks. The test modules import `helpers` before `shoalscan` (it puts `src/` on the import path), and the import order in `pyproject.toml` keeps it that way.

## Fuzzing

`fuzz/targets.py` holds fuzz targets for the parsers that read input Shoalscan does not control:

| Target | What it reads |
|---|---|
| `config_file` | `.shoalscan.toml`, from the scanned repository |
| `baseline_file` | the baseline, from the scanned repository |
| `suppression_line` | Opengrep and Trivy suppression markers in a source line |
| `markdown_text` | text for the Markdown escaper used by the work list and the report |
| `id_token` | any string as an ID token on the dashboard's sign-in |
| `id_token_claims` | correctly signed ID tokens with any claims |
| `gitleaks_report` | Gitleaks' JSON report |
| `trivy_report` | Trivy's JSON report |
| `hadolint_report` | Hadolint's JSON output |
| `zizmor_report` | zizmor's JSON output |
| `findings_file` | `findings.json`, which `check` and `record` read back |

Each target checks a contract, such as "valid, or a `SetupError`, nothing else", "the escaped text holds no markup" or "every finding is in a file of the repository", not only that nothing crashes. The scanner-report targets run against a small repository in a temporary directory; an input can write `$ROOT` for its path, since the scanners report absolute paths.

The targets need only the standard library, and `tests/test_fuzz_targets.py` runs each over its seeds and random edits of them with the other tests. The `fuzz` workflow runs them coverage-guided with [Atheris](https://github.com/google/atheris), a minute each on pull requests that change the code and ten minutes each week; a failing input is kept as a workflow artifact. To fuzz on Linux x86-64 yourself:

```sh
python3 -m pip install --require-hashes --only-binary :all: -r requirements-fuzz.txt
python3 fuzz/run.py config_file -max_total_time=60
```

To add a target, write a function that takes `bytes` in `fuzz/targets.py`, add it to `TARGETS` and a few inputs to `SEEDS`, and add its name to the matrix in `.github/workflows/fuzz.yml`.

## Deliberately insecure fixtures

`rules/` holds each rule's Opengrep tests, and `tests/data/` the sample repository the end-to-end tests scan. Both contain insecure code on purpose, so that Shoalscan has something to find. They are never run or shipped, and both Shoalscan's own scan (`.shoalscan.toml`) and CodeQL (`.github/codeql/codeql-config.yml`) leave them out. CodeQL alerts raised on them before that were dismissed as false positives, with the reason recorded.

## Design and changes

[design.md](design.md) describes the goals, principles and plan. [CHANGELOG.md](../CHANGELOG.md) lists the changes in each release.
