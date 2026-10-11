# Scanners

`scanners` in `.shoalscan.toml` chooses which scanners a scan runs; only Opengrep runs by default. Every scanner is pinned in `tools.lock` and installed by `shoalscan install`; its findings share one format, one baseline and one check.

| Scanner | Finds | Default | Pinned and verified |
|---|---|---|---|
| Opengrep | insecure code patterns, with Shoalscan's, the community's and your own rules | on | SHA-256, and a cosign signature checked against the Opengrep release workflow |
| Gitleaks | secrets: API keys, tokens, private keys, passwords | off | SHA-256 of the release archive, of the binary in it and of its default rules |
| Hadolint | Dockerfile mistakes, with ShellCheck for `RUN` lines: running as root, unpinned images and packages, unsafe shell pipes | off | SHA-256 of the binary |

```toml
scanners = ["opengrep", "gitleaks", "hadolint"]
```

## Gitleaks

Gitleaks looks for secrets in every file of the working tree, with its 200-odd default rules. Each finding is an ERROR named `gitleaks.<rule>` (for example `gitleaks.github-pat`), so it blocks a pull request unless the baseline accepts it, and the triage work list groups them all under CWE-798.

### Nothing in the repository can silence it

Gitleaks normally obeys three things a repository controls: a `.gitleaks.toml` that can replace or narrow the rules, a `.gitleaksignore` that drops findings, and `gitleaks:allow` comments. Shoalscan turns all three off. It passes the pinned default rules with `--config`, points `--gitleaks-ignore-path` at an empty directory and passes `--ignore-gitleaks-allow`. The environment variables that could set a configuration (`GITLEAKS_CONFIG` and `GITLEAKS_CONFIG_TOML`) never reach it either, as the scanner gets an allowlisted environment.

A false positive, or a secret that is meant to be there (a test key, say), goes into the baseline with an issue and a reason, like any other finding. `excludes` apply to Gitleaks as well, and `.git` is never reported.

### The secrets stay out of the output

Gitleaks writes each secret into its report. Shoalscan keeps that report in the scan's private temporary directory and deletes it when the scan ends. It uses the secret only to mask it out of the matched line before hashing the line into the fingerprint, so neither the secret nor a hash of it reaches `findings.json`, `findings.sarif`, `check.json` or the history. The message is the rule's description from the pinned configuration.

Because the fingerprint hashes the line with the secret masked, rotating a secret in place keeps the same finding: the leak is still at the same place. When Gitleaks found a secret only after decoding it (base64, say), the masked line is not available, and the fingerprint uses the rule and the enclosing function or class only.

### Fix a leaked secret first, then the code

A secret in a commit is in the repository's history, so removing it from the code does not make it safe. Revoke and rotate it first, then remove it and read it from a secret store or the environment.

### What Gitleaks does not report

Gitleaks does not list the files it skipped (for example, files over `max_target_bytes`), so they are not counted as unscanned. It scans the working tree, not the git history; to search the history once, run Gitleaks yourself with `gitleaks git`.

### Its pin

Gitleaks publishes a checksums file but no signature or provenance, so its pin rests on SHA-256 only: the release archive, the `gitleaks` binary inside it (checked again before every scan) and the default rules file, fetched from the commit the release tag points to. Each hash in `tools.lock` was checked against the project's published checksums.

## Hadolint

Hadolint lints Dockerfiles, and checks the shell in `RUN` instructions with ShellCheck. Findings are named `hadolint.<code>`, such as `hadolint.DL3002` (the last user is root) or `hadolint.SC2086` (a ShellCheck rule). Hadolint's `error` level becomes ERROR, `warning` WARNING, and `info` and `style` INFO, so with the default `blocking`, its warnings block pull requests too. The triage work list links each rule to its page on the Hadolint or ShellCheck wiki.

### Which files

Shoalscan finds the Dockerfiles itself and gives them to Hadolint: regular files named `Dockerfile`, `Dockerfile.<anything>`, `<anything>.dockerfile`, `Containerfile` or `Containerfile.<anything>`, in any letter case, outside `.git` and the excludes. Symbolic links are not followed. Names such as `Dockerfile.md`, `Dockerfile.dockerignore` and templates (`Dockerfile.j2`, `Dockerfile.tmpl` and similar) are left out. A Dockerfile over `max_target_bytes` is skipped and listed as not fully scanned.

A Dockerfile that Hadolint cannot parse (its DL1000) is listed as not fully scanned rather than reported as a finding. On a pull request, a changed Dockerfile that did not parse fails the check, as any changed file that was not scanned does.

### Leaving rules out

Many Hadolint rules are about reproducible builds rather than security. Leave out the ones you do not want in `.shoalscan.toml`:

```toml
[hadolint]
ignore = ["DL3008", "DL3015"]   # Hadolint (DL) and ShellCheck (SC) rule codes
```

This is policy: on a pull request run with `--policy-ref`, it comes from the base branch. Findings of an ignored rule are never taken as fixed on the dashboard.

### Nothing in the repository can silence it

Hadolint normally reads a `.hadolint.yaml` from the working directory or the home directory, `HADOLINT_*` environment variables, and `# hadolint ignore=DLxxxx` pragmas in the Dockerfile. Shoalscan passes its own empty configuration with `--config`, passes `--disable-ignore-pragma`, and runs Hadolint with the scanners' allowlisted environment, so only `[hadolint] ignore` leaves rules out.

### Its pin

Hadolint publishes bare binaries and a checksums file, but no signature or provenance, so its pin rests on SHA-256 only. Each hash in `tools.lock` was checked against the project's published checksums, and `scan` checks the binary again before every run. Hadolint is licensed GPL-3.0; Shoalscan downloads and runs it, and does not bundle it.

**Next:** [Rules](rules.md).
