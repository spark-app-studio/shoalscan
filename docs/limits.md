# Limits

## Limits of static analysis

No scanner finds every vulnerability. Pattern and taint analysis misses authorization and logic flaws, data flows across files, and concurrency bugs. Shoalscan is one layer of defence alongside dependency audits, tests and code review.

## Limits of Shoalscan's safeguards

Shoalscan's own safeguards have limits too:

- The policy-from-base model protects pull requests only when CI passes `--policy-ref`, and only as well as the base branch is protected. Changes on the base branch itself are trusted, which is why the policy files belong under [CODEOWNERS](ci.md#codeowners).
- The policy diff shows tracked files. A rule directory's untracked files are not part of a commit, so they never reach CI.
- The dashboard's rate limits are per client address. Behind a reverse proxy, load balancer, NAT or container port mapping, all clients share one address and so share the limits; one person starting many sign-ins can make others wait a minute.
- The dashboard reads the identity provider's discovery document and keys again every hour. If that read fails, sign-ins are refused for 30 seconds before it is tried again, even though the previous keys may still be good. People who are already signed in are not affected.

### Unscanned files

The changed-file check sees files that Opengrep reports as skipped or errored. A file that no rule's language covers is not scanned at all and is not reported, and a parse error Opengrep does not report is not seen. Files listed in [`parse_warn_only`](configuration.md#partial-parses) only warn about partial parses, so their unparsed lines are not checked by any rule.

Trivy reports the Terraform files it cannot parse, but not YAML or JSON files it cannot parse; those are neither scanned nor counted. Gitleaks does not report the files it skipped, so a file over the size limit is not counted as unscanned for secrets. It scans the working tree, not the history.

### Fingerprints

Fingerprints follow code within a file and, with `rename-path`, across moves; they do not survive edits to the matched code or to the enclosing function's name. [Findings and fingerprints](baseline-and-check.md#findings-and-fingerprints) explains how they are made and what changes them.
