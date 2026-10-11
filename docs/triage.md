# The triage work list

`shoalscan triage` turns the last scan into a prioritised work list: what to fix first, grouped so that one pull request can fix one kind of problem. It runs on a developer machine, offline, from the files `shoalscan scan` wrote and the repository's baseline. It never changes the baseline, the configuration or what blocks CI.

```sh
shoalscan scan
shoalscan triage --output ~/triage.md
```

Keep the list outside the repository. A file written into the working tree changes it, so the list would warn that the scan is out of date, `check` would refuse the scan, and the next scan would read the list's own text.

## What the list holds

1. **Stale baseline entries** come first. They match no finding any more, so `shoalscan check` fails until they are removed, and removing them is the quickest work there is.
2. **Groups of findings**, one per rule family. A rule family is the first CWE the rule names in its metadata, so Shoalscan's TLS rule and a community rule about disabled certificate checks fall into the same group, CWE-295. A rule that names no CWE is a family of its own.

Each group lists its rules, with each rule's message, fix hint, confidence, CWE and OWASP labels, references, and a link to the rule's file. The link points at the pinned commit for community rules and at the release tag for Shoalscan's own rules. Your own rules show their path in the repository. Then the group lists its findings by component. Each finding is marked **new, blocks** (it fails the check), new (it does not block, for example because it is INFO or under a non-blocking path) or baselined, with its baseline entry's issue and reason.

## The order

Groups and the findings inside them follow the dashboard's **Fix priority**:

1. new blocking findings first;
2. then ERROR before WARNING before INFO;
3. then the higher heat score (ERROR ×10, WARNING ×3, INFO ×1): for a group, the sum over its findings; for a finding, its component's score;
4. then, for groups, the larger group first.

## Working through it

Take the groups from the top, one per pull request:

- **Fix** the findings, remove their baseline entries in the same change, and add a test or a rule that keeps the fix in place.
- **A false positive** gets an inline suppression that names the rule and an issue ([Inline suppressions](baseline-and-check.md#inline-suppressions)).
- **An accepted risk** stays in the baseline, with a reason that says why.

If you also review findings on the dashboard, [`triage export`](reviewing-findings.md#carrying-reviews-into-the-baseline-triage-export) turns those reviews into baseline entries.

## Options

| Option | Meaning |
|---|---|
| `--repo DIR` | the repository (default: the current directory) |
| `--out DIR` | where `scan` wrote `findings.json` (default: the same default as `scan`) |
| `--config FILE`, `--baseline FILE` | as for `check` |
| `--format markdown` or `json` | Markdown for people (the default), JSON for scripts and coding agents |
| `--output FILE` | write the list to a file instead of standard output |
| `--blocking-only` | list only the findings the policy treats as blocking |
| `--max-per-group N` | findings listed per group in Markdown (default 25); JSON always lists every finding |

The JSON form has `format` 1 and lists every finding with its `key` (tool, rule, path and fingerprint), so an agent can work through one group and check its work with `shoalscan scan && shoalscan check`.

## When the list may be out of date

Triage is advice, so it warns instead of failing. It warns, in the list and on standard error, when:

- HEAD or the working tree changed after the scan (an edit to the baseline file alone does not count, as for `check`);
- `.shoalscan.toml` changed after the scan, or the scan read its policy from a `--policy-ref`;
- there is no baseline file, so every finding counts as new.

Scan again for an up-to-date list.

## Similar findings, with a local embedding model

With thousands of findings, most of them repeat a few patterns, and a decision about one usually holds for its neighbours. Shoalscan can find those neighbours with an embedding model that runs on your own machine through [Ollama](https://ollama.com), by default Google's EmbeddingGemma. Nothing leaves the machine, and no token or account is needed.

```sh
ollama pull embeddinggemma
shoalscan triage embed --repo-name owner/project        # once, then after new runs
shoalscan triage suggest-similar 3f2a1b4c --repo-name owner/project
```

`triage embed` reads the repository's findings from the history database and stores one vector per finding. Only findings that are new, or whose message changed, are sent again. `shoalscan record --embed` does the same right after recording a run; if Ollama is not running or the model is not pulled, `record` prints a warning and still records the run.

`triage suggest-similar` takes a finding's fingerprint (the whole of it, or its first 8 characters or more) and lists the three findings most like it, at a cosine similarity of 0.85 or more. Each comes with what was decided about it: its dashboard review (with who and when) or its baseline entry's issue and reason. Use it to apply one decision to a whole group, still finding by finding:

```text
Findings like community.python.lang.security.audit.dangerous-subprocess-use-audit in src/shoalscan/gitref.py (61da0a83d820), similarity at least 0.85:
  0.995  ERROR   src/shoalscan/install.py:131  community.python.lang.security.audit.dangerous-subprocess-use-audit
         reviewed false_positive by alice on 2026-10-02: Fixed argument list, no shell.
```

| Option | Meaning |
|---|---|
| `--threshold N` | the lowest similarity to list, above 0 and at most 1 (default 0.85) |
| `--limit N` | how many to list (default 3) |
| `--all-repos` | compare with the findings of every repository in the history, not just this one |
| `--format json` | for scripts and agents |
| `--model NAME` | the Ollama embedding model (default `embeddinggemma`); vectors are kept per model |
| `--ollama-host URL` | for `embed` and `record --embed`: Ollama's address, which must be on the loopback interface (default `http://127.0.0.1:11434`) |

The dashboard shows the same list under **Similar findings** on each finding's review page, from the stored vectors; the dashboard itself never calls Ollama.

What is embedded and where it goes:

- **The finding's text, never its code:** the tool, the rule id, the component, the path and the message.
- **Only to Ollama on this machine.** The host must be `127.0.0.1`, `::1` or `localhost`, proxy settings are ignored, and the host is a command-line setting. It is never read from `.shoalscan.toml`, because that file belongs to the scanned repository, which must not be able to send its findings anywhere.
- **Never during `scan` or `check`.** Similarity is advice for triage; it cannot change what blocks CI.

Vectors are stored as packed float32 in the `finding_embeddings` table of the history database (schema version 12), and go when their finding's identity is pruned from the history. Similarity is computed in plain Python, so there are no new dependencies.

## Rule metadata in `findings.json`

From this version, `scan` records what each rule behind a finding says about itself under `rules` in `findings.json`: its CWE and OWASP labels, confidence, likelihood and impact, fix hint, reference links, and the rule file it came from. Rules can come from the scanned repository, so the values are bounded, only http(s) links are kept, and the list escapes all of them, so they show as plain text. A findings file from an older version still works; its groups are then one per rule, without links.

**Next:** [The security report](report.md).
