# Reviewing findings

After you look into a finding, record what you decided on the [dashboard](dashboard.md). Reviews help people triage, but they never change what blocks CI; the baseline does.

## Review statuses

Open the finding from the Findings table (the Review link), or select several findings and use **Mark as**. A finding can be:

- **Open**, the default. A finding with no review and no baseline reason shows as **Untriaged**.
- **False positive**, **Accepted risk** or **Won't fix**. These stay with the finding run after run.
- **Fixed**, a fix you claim. The next scheduled scan checks it: when the finding is gone, it becomes **Verified fixed**; when it is still there or comes back, it becomes a **Regression**.

## Descriptions and timestamps

Every change needs a description of 10 to 2000 characters, and is kept in the finding's history with who made it, when (in UTC) and on which run. When a finding enters a resolved status (false positive, accepted risk, won't fix, fixed or verified fixed), the time is stored; going back to open or regression clears it. When a finding moves between resolved statuses, its resolution time stays the time it was first resolved. The dashboard shows times in your local time, with the exact UTC time on hover.

## Automatic verification and regressions

Automatic changes are made by "shoalscan" with a description such as "No longer found in the scheduled run of 2026-10-10T02:00:00Z at 3f2a1b4c5d6e.". Only the newest scheduled run moves reviews; pull-request runs never do. [Scheduled scans](scheduled-scans.md) sets up the regular scan this needs.

A finding that is missing from a run counts as fixed only when that run could have seen it: its scanner ran (a scanner can be turned off in `scanners`), for Opengrep and Gitleaks its rule was among the rules that ran, its file was not excluded, skipped or unreadable, and no parse gap covered its line.

## How reviews follow a finding

Reviews follow a finding by its repository's name and its identity (tool, rule, path and fingerprint), not by run. They stay when runs are deleted, even all of a repository's runs, and apply again if the repository is recorded under the same name. A moved file starts without its reviews.

A finding that the baseline accepts shows its baseline entry's reason and issue, read-only and marked "from baseline", until someone reviews it on the dashboard: a reason that starts with "False positive:" shows as a false positive, one that starts with "Accepted:" as an accepted risk, and any other as baselined. That needs the `check.json` that `check` writes.

## Similar findings

The review page of a finding lists the findings most like it, with the decision made about each, when the repository's findings have been embedded with a local model ([Similar findings](triage.md#similar-findings-with-a-local-embedding-model)). It is a hint for triage, never a decision. The Findings page also shows a suggestion for each untriaged finding and can fill in a bulk review from it ([Suggestions on the Findings page](triage.md#suggestions-on-the-findings-page)).

## Carrying reviews into the baseline: `triage export`

**Dashboard reviews do not change what blocks CI.** The baseline does. To carry reviews into the baseline, export them and commit the result through a reviewed change:

```sh
shoalscan triage export --repo owner/project --issue "#123" > reviewed-entries.toml
```

It prints baseline entries for the findings reviewed as false positive, accepted risk or won't fix. Each reason is the review's description with "(reviewed in dashboard by WHO on WHEN)", and `--issue` is required. `--suppressions` also prints matching inline suppression lines, as comments. The command never writes the repository's baseline itself. [The baseline file](baseline-and-check.md#the-baseline-file) describes the format.

**Next:** [The triage work list](triage.md).
