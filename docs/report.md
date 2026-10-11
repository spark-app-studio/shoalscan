# The security report

`shoalscan report` writes a dated security report on one repository from the run history: where its security stands, how that changed over a period, what was found and fixed, what the baseline accepts and why, and what the scan could not see. It suits a monthly review, an audit file (SOC 2, ISO 27001), or a note to a client.

```sh
shoalscan report --repo-name owner/project --since 2026-09-01 --until 2026-09-30 > security-2026-09.md
```

It reads the history database that `shoalscan record` writes, read-only, and needs no network and no credentials. Run it where the database is, usually next to the dashboard.

## The period

A report covers whole days in UTC, from `--since` to `--until`, both included. `--until` defaults to today and `--since` to 30 days before `--until`, so a bare `shoalscan report --repo-name owner/project` covers the last 30 days. A period may be up to 366 days long, enough for an audit year. A report walks at most the newest 400 trend runs up to `--until`; if the period holds more than that (more than one scheduled scan a day), `report` refuses it rather than print incomplete counts, so choose a shorter period.

The figures come from the trend runs, as on the dashboard: the scheduled scans of the default branch, or every run when the repository has none. The **end** of the period is the newest trend run in it; the **start** is the newest trend run before it, so each change is measured from the state the period began with. Runs whose check could not run (scan errors) hold no results and are only counted.

## What it holds

- **Summary:** the latest scan's result, the open findings by severity and their change since the start, the blocking findings (new and baselined), the baseline size and stale entries, untriaged blocking findings and regressions, and how many findings were new and fixed, with the median and mean time to fix.
- **Trend:** open findings by severity and the baseline size at the start and the end, and the new and fixed findings for each week of the period.
- **Fixed in the period** and **New in the period:** each finding with its date, severity, place, rule and component (up to 100 of each; the counts are always complete).
- **Accepted risks and false positives:** the findings the baseline accepts in the latest scan, grouped by their entries' issue and reason, and classed as on the dashboard: a reason that starts with "False positive:" or "Accepted:" counts as such. Then the dashboard review statuses now, and every review change made in the period, with who made it.
- **Components:** the latest scan's findings by component, hottest first.
- **Coverage:** the scheduled and pull-request runs in the period by outcome, runs that were later deleted from the history, files not fully scanned, inline suppressions, and the scanners with their versions and whether the scanner's signature was verified.
- **Limits:** what static analysis cannot find.

Times to fix count from when a finding first appeared, even before the period, within the newest 400 trend runs; a finding that was already there in the first recorded run counts from that run, so its time to fix is a lower bound.

## Options

| Option | Meaning |
|---|---|
| `--repo-name NAME` | the repository's name in the history (required) |
| `--since DAY`, `--until DAY` | the first and last day, `YYYY-MM-DD`, UTC |
| `--format markdown` or `json` | Markdown for people (the default), JSON for scripts |
| `--output FILE` | write the report to a file instead of standard output |
| `--db FILE` | the history database (default: the same as `record`) |

The JSON form has `format` 1 and holds the same figures.

Text that comes from scanned repositories, such as paths, rule ids, baseline reasons, component names and review descriptions, is escaped, so it shows as written and cannot add links, images, HTML or headings to the report.

## A monthly report

A scheduled job can write one report a month, for the month before:

```sh
since=$(date -u -d "$(date -u +%Y-%m-01) -1 month" +%Y-%m-%d)
until=$(date -u -d "$(date -u +%Y-%m-01) -1 day" +%Y-%m-%d)
shoalscan report --repo-name owner/project --since "$since" --until "$until" --output "reports/security-${since%-01}.md"
```

(On macOS, use `date -v` instead of `date -d`.)

**Next:** [Scheduled scans](scheduled-scans.md).
