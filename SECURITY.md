# Security policy

Shoalscan is a security tool, so we take vulnerabilities in it seriously. Thank you for helping to keep its users safe.

## Supported versions

Shoalscan is in early development. Security fixes are made for the latest 0.x minor release only. Today that is 0.1. When a new minor release comes out, earlier minor releases stop receiving fixes, so please upgrade to the latest release before you report a problem.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability reporting. Go to the repository's **Security** tab, open **Advisories**, and press **Report a vulnerability**, or use this link directly:

https://github.com/spark-app-studio/shoalscan/security/advisories/new

Only the maintainers can see a report made this way. Never report a vulnerability in a public issue, a pull request, a discussion or any other public place.

## What to include

A good report helps us confirm and fix the problem quickly. Please include as much of the following as you can:

- the Shoalscan version (`shoalscan --version`) and the commit if you run from source;
- your operating system and Python version;
- the component affected, for example the scan, the check, `shoalscan install`, the dashboard or the scan worker;
- a description of the vulnerability and its impact: what an attacker can do, and what they need to do it;
- the steps to reproduce it, ideally with a minimal repository, configuration or request;
- any proof-of-concept code, logs or screenshots, with secrets and private data removed;
- any ideas you have for a fix.

## What happens next

- We acknowledge your report within 3 business days.
- We send you an initial assessment within 10 business days: whether we can reproduce it, how severe we think it is, and what we plan to do.
- We keep you informed as we work on a fix, and we may ask you for more information.
- We follow coordinated disclosure. We aim to release a fix and publish a GitHub security advisory within 90 days of the report, and usually sooner. If a fix needs longer, we will agree a new date with you. Please do not disclose the vulnerability publicly before the advisory is published.
- With your permission, we credit you in the advisory.

## Scope

In scope is Shoalscan itself: the command line, the scan, the baseline and the check, the run history, the dashboard (`shoalscan serve`), the scan worker (`shoalscan scanjob`), and supply-chain verification (`tools.lock`, `shoalscan install` and signature checking). Shoalscan's own rules in `rules/` are in scope too, for example a rule that can be made to crash or hang a scan.

Out of scope are vulnerabilities in the third-party scanners Shoalscan runs, and gaps or false negatives in the third-party rules themselves. Please report those upstream, to [Opengrep](https://github.com/opengrep/opengrep) for the scanner. A missed detection by a rule is not usually a vulnerability in Shoalscan; you are welcome to open a normal issue or propose a rule as described in [CONTRIBUTING.md](CONTRIBUTING.md). If Shoalscan installs or runs a scanner or rules in an unsafe way, for example by accepting a download whose checksum does not match, that is in scope.

## Shoalscan's security model

Shoalscan pins every scanner and the community rules by SHA-256 and checks signatures where the tool publishes them. A scan makes no network calls and needs no credentials. On a pull request the policy is read from the base branch, so a change cannot relax its own checks. The dashboard serves TLS only, with token login, strict session cookies, same-origin checks and a strict Content Security Policy. [docs/security-model.md](docs/security-model.md) describes these safeguards in detail, and [docs/limits.md](docs/limits.md) lists what they do not cover. A report that shows one of these safeguards can be bypassed is exactly what we want to hear about.
