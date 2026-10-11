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
ruff format src tests scripts
ruff check src tests scripts
```

CI runs both checks. The test modules import `helpers` before `shoalscan` (it puts `src/` on the import path), and the import order in `pyproject.toml` keeps it that way.

## Design and changes

[design.md](design.md) describes the goals, principles and plan. [CHANGELOG.md](../CHANGELOG.md) lists the changes in each release.
