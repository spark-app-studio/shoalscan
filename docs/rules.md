# Rules

A scan runs up to three sets of Opengrep rules: Shoalscan's own rules, the pinned community rules snapshot, and your own rule directories. Their ids start with `shoalscan.`, `community.` and `repo.` respectively. [Configuration](configuration.md#rule-selection) explains how to choose them.

## Shoalscan's own rules

The [`rules/`](../rules) directory holds Shoalscan's rules. Each rule has metadata with its CWE, severity, confidence and a short fix hint, and each has Opengrep tests next to it.

- **TLS verification turned off:** Python (`verify=False`, `CERT_NONE`, unverified contexts), Node (`rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`) and Rust (`danger_accept_invalid_certs(true)` and friends). A custom rustls certificate verifier is reported separately as a warning to review.
- **Plain `http://` URLs in code:** loopback addresses (only when the host is followed by a port, a path or the end, so `http://localhost@host` is reported), the cloud metadata address, reserved example and test domains, XML namespace identifiers and test files are not reported. A constant is reported once, where its literal is.
- **Secrets passed to log calls:** Python (`logging`, `extra={...}`, `print`), Node (including object shorthand such as `{ token }`) and Rust (`log` and `tracing` macros, inline format arguments such as `"{token}"`, and `?field` shorthand) with an argument named like a password, token, secret key, API key, private key or credential.
- **Broad exception handlers on security paths:** a Python `try` that calls a verification, authentication or authorization function, with a bare `except`, `except Exception` or `except BaseException` that only passes, continues or logs.

The rules are deliberately conservative: fewer false positives matter more than coverage. Run their tests with:

```sh
~/.cache/shoalscan/tools/opengrep scan --test rules/
```

Set `shoalscan_rules = false` under `[opengrep]` to turn them off.

## The community rules snapshot

`shoalscan install` downloads a snapshot of the archived [opengrep-rules](https://github.com/opengrep/opengrep-rules) repository, pinned by commit and SHA-256 in `tools.lock` like the scanner binaries, and keeps the rules' licence file next to them. The snapshot has the categories security, correctness, best-practice, compatibility, maintainability, performance, portability and caching; `categories` and `exclude_rules` choose which of them run. Pass `--no-community-rules` to `install`, or set `community_rules = false`, to go without them.

### Licence

The Opengrep community rules are not part of Shoalscan and are not bundled in this repository. They keep their own licence, LGPL-2.1 with the Commons Clause. Shoalscan itself is licensed under the [Apache License 2.0](../LICENSE).

## Your own rules

List your rule directories, relative to the repository, in `rule_dirs`. On a pull request run with `--policy-ref`, they are read from the base branch, so a change cannot alter the rules that judge it.

**Next:** [The dashboard](dashboard.md).
