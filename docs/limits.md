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

Trivy reports the Terraform files it cannot parse, but not YAML or JSON files it cannot parse; those are neither scanned nor counted. Gitleaks scans the working tree, not the history.

### Trivy's inline comments

Shoalscan lints every Trivy inline ignore comment, and fails a scan when Trivy logs a silenced finding without a valid comment at or above it in its file. Trivy logs silenced findings only for Terraform and CloudFormation; in Dockerfiles it drops them without a trace, so only the lint guards those. A valid comment above a finding in the same file is taken to explain it, as Trivy does not say which comment silenced which finding. Helm charts are checked as Shoalscan renders them, with their comments removed, so inline ignore comments have no effect there. A finding in a chart is reported at its template's first line, not the exact line, and a chart is checked with its default values and the extra values files you name, not every combination of values it supports.

### The network

Without an operating-system network sandbox (see [Scanner isolation](security-model.md#scanner-isolation)), a scanner is kept off the network by its environment alone: no credentials, no git transport and proxies that go nowhere. That does not cover this machine's own loopback interface, which Go programs reach without a proxy, nor a program that ignores proxy variables. Pass `--require-network-sandbox` (the dashboard's worker does by default), or run untrusted scans where the platform cuts the network off.

### Fingerprints

Fingerprints follow code within a file and, with `rename-path`, across moves; they do not survive edits to the matched code or to the enclosing function's name. [Findings and fingerprints](baseline-and-check.md#findings-and-fingerprints) explains how they are made and what changes them.
