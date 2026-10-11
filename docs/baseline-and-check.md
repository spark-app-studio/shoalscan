# The baseline and the check

The baseline records the findings a repository has accepted for now. `shoalscan check` compares a scan's findings with it, so a pull request fails only on what it introduces, and the baseline can only shrink.

## Findings and fingerprints

Every finding has a `tool`, `rule`, `severity` (ERROR, WARNING or INFO), `path`, `line`, `fingerprint`, `component` and `message`. The fingerprint is a hash of the tool, the rule, the enclosing function or class, and the matched code with its whitespace collapsed. Identical matches in the same function of one file get an occurrence number. The fingerprint holds neither the line number nor the path, so moving code up or down keeps it, and `baseline rename-path` follows a moved file. Opengrep's own match ID is not used, because it changes with the directory the rules are loaded from.

The enclosing context is found by reading lines, not syntax: walking up from the match, every `def`, `fn`, `function`, `class` (and similar) line indented less than what came before encloses it, giving a qualified name such as `class:Svc/def:run`. Line numbers follow newlines only, as Opengrep counts them. That has limits you should know:

- Changing the matched code, renaming the enclosing function, or moving the code into another function changes the fingerprint. The finding then shows up as new, and its old baseline entry as stale.
- Moving or renaming a file without `baseline rename-path` does the same.
- Code at the left margin, or in a language whose definitions this heuristic does not recognise, has no context; identical matches there are told apart only by their order in the file.

## The baseline file

`shoalscan baseline init` writes the baseline from a full scan (see [Getting started](getting-started.md#the-first-baseline)). The baseline is a TOML file with one `[[finding]]` table per accepted finding:

```toml
version = 1

[[finding]]
tool = "opengrep"
rule = "community.python.lang.security.audit.eval-detected"
path = "src/tools/calc.py"
fingerprint = "59301fe727479b07bc9d8054f41ca694:0"
issue = "#123"
reason = "Input is a constant expression; fix tracked in #123"
```

Every key is required, and `issue` must be `#123` or a URL.

## The check

Compare the findings with the baseline:

```sh
shoalscan check
```

`check` prints a readable report and then one line that starts with `SHOALSCAN_SUMMARY `, followed by JSON with the counts by severity, by component and by rule, the number of new findings, stale baseline entries, the baseline size, the suppressions and the files that were not fully scanned. It exits with 0 when the check passes, 1 when the check fails, and 2 when the setup is broken, the scan failed or Shoalscan itself hit an unexpected error.

- A new finding fails the check when its severity is blocking. By default ERROR and WARNING block.
- A new INFO finding is reported but never blocks.
- A baseline entry that no longer matches any finding is stale and fails the check, so the baseline can only shrink.
- Files that Opengrep skipped (for example because they are larger than `max_target_bytes`) or reported an error for (a parse error or a timeout) are listed. With `--policy-ref`, for a file the change touched and the configuration does not exclude:
  - a skipped file, a timeout, running out of memory, or any error other than a partial parse fails the check;
  - a partial parse fails when an unparsed span overlaps a line the change added, or covers more than half the file, and is otherwise reported as a warning;
  - a file that matches [`parse_warn_only`](configuration.md#partial-parses) only warns about a partial parse, whatever its size or place. It is listed loudly as `PARTIALLY PARSED (warn-only by policy)` with the share of the file left unparsed and whether that overlaps the added lines, and counted in the summary. A skipped file, a timeout or any other error still fails;
  - a syntax error that Opengrep does not report (some Python parse errors) is not seen.
- `check` refuses findings that do not match the current tree: `scan` records the HEAD tree hash and whether the working tree had changes, and any edit or commit after the scan means scanning again. The one exception is the baseline file `check` reads; see [The tree binding](#the-tree-binding). `check` refuses a directory that is not a git work tree unless you pass `--no-git`; the findings are then not tied to a commit.
- With `--policy-ref`, changed files that the configured excludes skip are listed loudly as CHANGED BUT NOT SCANNED. They do not fail the check, but reviewers should confirm the exclusion is intended.

`check` also writes `check.json` next to `findings.json`, with the lists behind the summary's counts. `shoalscan record` stores it in the history; see [The dashboard](dashboard.md#recording-a-run).

## The tree binding

`scan` records what it scanned: the HEAD commit and tree, whether the working tree had changes, and a digest of those changes (the full diff against HEAD, the status and the content of every untracked file). `check` computes the same values again and refuses the findings when anything differs, so findings always describe the tree being checked.

The baseline file `check` reads is left out of that comparison: the `baseline` key of the configuration, or the `--baseline` path when it is inside the repository. The baseline is the input `check` compares the findings against, not something the findings describe, so writing or editing it cannot change what was scanned. This is what lets `shoalscan scan`, `shoalscan baseline init` and `shoalscan check` run in that order without a commit in between. Everything else stays strict:

- Any other edit, commit or new untracked file after the scan still makes `check` refuse the findings.
- The configuration is not left out: a change to it can change what is scanned, so it always means scanning again.
- The exception applies only when `scan` and `check` name the same baseline file. Without a policy ref, `scan` records the configured baseline (or the `--baseline` of `baseline init`); if `check` reads another file, the comparison is fully strict.
- If the scan reported anything in the baseline file itself (a finding, a suppression, or a skipped or unparsed file), the baseline is a scanned file like any other, and the comparison is fully strict.
- A baseline path outside the repository, inside `.git`, reached through a symbolic link, or naming a directory is never left out. `..` in `--baseline` is resolved before the path is compared. Git renames are not paired here, so moving a file onto the baseline's path still shows as a deletion.
- With `--policy-ref`, the comparison is fully strict, as it always was: on a pull request the baseline is part of the change under review, and scan and check run back to back.

Edits to the baseline after the scan are not scanned until the next scan, but `check` still reads the edited file under its strict rules: it must be a valid baseline, and every entry must match a finding.

## Inline suppressions

Opengrep skips a finding on a line that carries a suppression comment, or on the line after one. Shoalscan requires every such comment to name the rule and an issue, with the colon right after the marker and one space before the rule id:

```python
requests.get(url, verify=CA_BUNDLE)  # nosemgrep: community.python.requests.security.disabled-cert-validation #123 private CA
```

Shoalscan reads these comments with the same expression Opengrep uses, with ASCII-only word boundaries as in Opengrep, so a marker next to a letter such as `é` still counts. Like Opengrep, it matches the marker's letters with Unicode case folding, so a marker spelled with a long s (`ſ`) counts too. If the colon is missing, is preceded by a space, or is followed by more than one space, Opengrep ignores the rule id and silences every rule on the line; Shoalscan reports that as a bare suppression, which blocks. A comment with no valid rule id or no issue also blocks. Opengrep matches the marker anywhere on a line, even inside a string, so Shoalscan checks every file that Opengrep scanned, prose files such as Markdown included. Suppressions are counted in the summary, together with the number of findings they silence, so silencing never looks like fixing. Trivy's own inline comments are held to the same rule ([Scanners](scanners.md#nothing-in-the-repository-or-the-machine-can-silence-it)).

## Moving and renaming files

When a file moves, point its baseline entries at the new path; fingerprints do not contain the path, so they stay valid:

```sh
shoalscan baseline rename-path src/old_name.py src/new_name.py
```

## Pull requests: the policy comes from the base branch

On a pull request, run both commands with `--policy-ref` set to the base commit's full SHA. In GitHub Actions that is `github.event.pull_request.base.sha`:

```sh
shoalscan scan  --policy-ref "$BASE_SHA" --out "$OUT"
shoalscan check --policy-ref "$BASE_SHA" --out "$OUT"
```

Shoalscan accepts only a full commit SHA or a fully qualified `refs/remotes/...` or `refs/heads/...` ref that exists. It refuses short names such as `origin/main`: git prefers a tag of the same name over the branch, so anyone who can push a tag could otherwise choose the policy.

With a policy ref, `.shoalscan.toml`, the baseline and the repository's own rule directories are read from that ref with `git show` and `git archive`, not from the pull request's checkout. A pull request therefore cannot exclude its own files, turn off rules or accept its own findings. On top of that:

- The pull request's baseline may only remove entries compared with the base branch. An added or changed entry fails, with a message that a baseline addition needs a separate, reviewed change on the base branch. The one exception is a pure move made with `baseline rename-path`: git must report the rename (at least 90% similar), every entry of the old path must move one-to-one with the same tool, rule, fingerprint, issue and reason, and the component and non-blocking status must not change. Moves are listed loudly in the report.
- Any change the pull request makes to the configuration, the baseline or the rule directories is printed as a loud diff, so reviewers see it, even though it is not applied.
- `check` refuses findings that `scan` produced under a different policy.
- `blocking` must include ERROR.
- First-time adoption: when the base ref has neither a configuration nor a baseline, the pull request's own configuration and baseline are used and reported as ADOPTION, so reviewers know they are setting the policy. ERROR findings still block. A base ref with a configuration but no baseline file, or the other way round, is refused; commit both (`shoalscan baseline init` writes an empty baseline when there are no findings).

### Protect the policy with CODEOWNERS

Put `.shoalscan.toml`, the baseline, your rule directories and the CI workflow under CODEOWNERS, so that changes to the policy on the base branch need a review from the people who own security. `examples/CODEOWNERS` shows the lines to add; [CI](ci.md#codeowners) lists them.

**See also:** [Limits](limits.md) of fingerprints and of the changed-file check. **Next:** [CI](ci.md).
