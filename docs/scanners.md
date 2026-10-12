# Scanners

`scanners` in `.shoalscan.toml` chooses which scanners a scan runs; only Opengrep runs by default. Every scanner is pinned in `tools.lock` and installed by `shoalscan install`; its findings share one format, one baseline and one check.

| Scanner | Finds | Default | Pinned and verified |
|---|---|---|---|
| Opengrep | insecure code patterns, with Shoalscan's, the community's and your own rules | on | SHA-256, and a cosign signature checked against the Opengrep release workflow |
| Gitleaks | secrets: API keys, tokens, private keys, passwords | off | SHA-256 of the release archive, of the binary in it and of its default rules |
| Hadolint | Dockerfile mistakes, with ShellCheck for `RUN` lines: running as root, unpinned images and packages, unsafe shell pipes | off | SHA-256 of the binary |
| zizmor | GitHub Actions flaws: template injection, dangerous triggers, unpinned actions, broad permissions, persisted credentials | off | SHA-256 of the release archive and of the binary in it; build provenance checked when pinned |
| Trivy | infrastructure-as-code misconfigurations in Terraform, CloudFormation, Kubernetes, Helm charts (rendered with a pinned Helm), Dockerfiles, Azure ARM and Ansible | off | SHA-256 of the release archive and of the binary in it, and a cosign signature checked at install against the Trivy release workflow |

```toml
scanners = ["opengrep", "gitleaks", "hadolint", "zizmor", "trivy"]
```

## Gitleaks

Gitleaks looks for secrets in every file of the working tree, with its 200-odd default rules. Each finding is an ERROR named `gitleaks.<rule>` (for example `gitleaks.github-pat`), so it blocks a pull request unless the baseline accepts it, and the triage work list groups them all under CWE-798.

### Nothing in the repository can silence it

Gitleaks normally obeys three things a repository controls: a `.gitleaks.toml` that can replace or narrow the rules, a `.gitleaksignore` that drops findings, and `gitleaks:allow` comments. Shoalscan turns all three off. It passes the pinned default rules with `--config`, points `--gitleaks-ignore-path` at an empty directory and passes `--ignore-gitleaks-allow`. The environment variables that could set a configuration (`GITLEAKS_CONFIG` and `GITLEAKS_CONFIG_TOML`) never reach it either, as the scanner gets an allowlisted environment.

A flag is not enough for the ignore file: Gitleaks 8.30.1 reads the `.gitleaksignore` at the top of the directory it scans whatever `--gitleaks-ignore-path` says, and it reads no other (none deeper in the tree). So Shoalscan makes sure that file never reaches it. When a repository has one, Gitleaks scans a private staging copy of the tree (hard links where the file system allows, copies otherwise) that holds every file it would scan except the top-level `.gitleaksignore` (Gitleaks treats deeper ones as ordinary files, and scans them), and the top-level `.gitleaksignore` is then scanned on its own, as a single file, so a secret written in it is still found. Without one, the tree is scanned in place. Findings are reported at their paths in the repository either way. On a case-insensitive file system (macOS, by default) Gitleaks would open a `.GitleaksIgnore` as its ignore file, so every letter-case variant at the top of the tree is handled the same way, and Shoalscan checks that the staging copy holds none before Gitleaks runs. Where hard links are not possible, the copy may be at most 4 GiB; past that the scan fails.

### Its rules, without path allowlists

Gitleaks's default rules come with allowlists that drop findings by path: anything under `node_modules/` or some `vendor/` trees, lock files, `go.mod`, `*.pdf` and other document and binary types, Python `*.dist-info/` directories, and any path containing `gitleaks.toml`. A repository chooses its own path names, so these would let it put a secret where Gitleaks never reports it. Shoalscan therefore runs Gitleaks with a configuration derived, at every scan, from the pinned and verified rules file: every allowlist that matches on paths, or on the line around a secret (`regexTarget = "line"`, which matches text written next to the secret), is removed, and so is an `AND` allowlist that needs a path. Allowlists that match only the secret itself, such as stopwords and value patterns (`true`, `${VAR}`, `aaaa...`), are kept, as no path name can change them. A rule's own `path`, which limits it to some files (such as `.tf` files), is kept too, since it only chooses where the rule applies. To leave paths out of the scan, such as vendored code, use `excludes` in `.shoalscan.toml`, which is policy and comes from the base branch under `--policy-ref`.

A false positive, or a secret that is meant to be there (a test key, say), goes into the baseline with an issue and a reason, like any other finding. `excludes` apply to Gitleaks as well, and `.git` is never reported.

### The secrets stay out of the output

Gitleaks writes each secret into its report. Shoalscan keeps that report in the scan's private temporary directory and deletes it when the scan ends. It uses the secret only to mask it out of the matched line before hashing the line into the fingerprint, so neither the secret nor a hash of it reaches `findings.json`, `findings.sarif`, `check.json` or the history. The message is the rule's description from the pinned configuration.

Because the fingerprint hashes the line with the secret masked, rotating a secret in place keeps the same finding: the leak is still at the same place. When Gitleaks found a secret only after decoding it (base64, say), the masked line is not available, and the fingerprint uses the rule and the enclosing function or class only.

### Fix a leaked secret first, then the code

A secret in a commit is in the repository's history, so removing it from the code does not make it safe. Revoke and rotate it first, then remove it and read it from a secret store or the environment.

### Files too large to scan

Gitleaks skips files over its size limit (`max_target_bytes`, rounded up to whole megabytes) without saying so. Shoalscan lists each of them as skipped (`exceeded_size_limit`), so they are counted as not fully scanned, and on a pull request a changed file that Gitleaks skipped fails the check, as any changed file that was not scanned does. `.git`, excluded paths and links are not listed, as Gitleaks reports nothing there anyway.

### What Gitleaks does not scan

It scans the working tree, not the git history; to search the history once, run Gitleaks yourself with `gitleaks git`.

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

## zizmor

zizmor audits GitHub Actions: workflows, action definitions and Dependabot configuration. Findings are named `zizmor.<audit>`, such as `zizmor.template-injection` or `zizmor.unpinned-uses`. zizmor's `High` severity becomes ERROR, `Medium` WARNING, and `Low` and `Informational` INFO. It runs its "regular" persona, the one with the fewest false positives. The triage work list links each audit to its documentation.

### Which files

Shoalscan gives zizmor the workflows directly in `.github/workflows` (`*.yml` and `*.yaml`), every `action.yml` or `action.yaml` in the repository, and `.github/dependabot.yml`, outside `.git` and the excludes, without following links, and not over `max_target_bytes` (such a file is listed as skipped). A `.gitignore` does not hide a file from it.

All the files are audited in one run. If zizmor cannot read one of them (a YAML syntax error, say), each file is audited alone: the ones it cannot read are listed as not fully scanned, and the findings of the others still count. On a pull request, a changed workflow that could not be audited fails the check.

### Leaving audits out

```toml
[zizmor]
ignore = ["artipacked"]   # zizmor audit names
```

This is policy: on a pull request run with `--policy-ref`, it comes from the base branch. Findings of an ignored audit are never taken as fixed on the dashboard.

### Offline, and nothing in the repository can silence it

zizmor normally reads a `zizmor.yml` (or `.github/zizmor.yml`) that can turn audits off, honours `# zizmor: ignore[...]` comments, and can call the GitHub API. Shoalscan passes `--offline`, `--no-config` and `--no-ignores`, and runs it with the scanners' allowlisted environment, so no token and no `ZIZMOR_*` variable reaches it. Audits that need the network do not run.

### Its pin

zizmor publishes no checksums file, but its release archives carry GitHub build provenance. Before they were pinned, the four archives in `tools.lock` were verified with `gh attestation verify` against zizmor's release workflow at the v1.30.1 tag. `install` checks the SHA-256 of each archive and of the `zizmor` binary in it, and `scan` checks the binary again before every run; neither fetches the attestation again.

## Trivy

Trivy's `config` command checks infrastructure as code: Terraform, CloudFormation, Kubernetes manifests, Dockerfiles, Azure ARM templates and Ansible. Helm charts are rendered by Shoalscan with a pinned Helm and then checked as Kubernetes manifests ([below](#helm-charts)); Trivy's own Helm scanner is turned off. Findings are named `trivy.<check>`, such as `trivy.AWS-0087` or `trivy.KSV-0017`. `CRITICAL` and `HIGH` become ERROR, `MEDIUM` WARNING, and `LOW` and `UNKNOWN` INFO. The triage work list shows each check's resolution and links to its page.

Trivy finds the configuration files itself. Findings in excluded files and under `.git` are dropped. A finding in anything that is not a file of the repository (for example, a remote Terraform module) fails the scan, so it can never be filed under the wrong path.

### Offline, with the checks in the binary

Trivy normally downloads its checks bundle from a registry and keeps it in a cache. Shoalscan gives it an empty cache directory and `--skip-check-update`, so it uses the checks embedded in the pinned binary, and passes `--skip-version-check` and `--disable-telemetry`. Updating the checks means updating the pin.

Trivy also downloads the remote modules a Terraform file names (`git::`, `s3::`, `gcs::`, https and the registry), and 0.74.0 has no option to stop it. Shoalscan runs it, like every scanner, with an empty home directory, git that allows no transport and reads no configuration, proxies on a closed port, and an operating-system network sandbox where there is one ([Security model](security-model.md#scanner-isolation)), so the download fails, Trivy logs that it could not load the module, and only the repository's own files are scanned.

### Nothing in the repository or the machine can silence it

Trivy normally reads a `trivy.yaml` and `.trivyignore` files, `TRIVY_*` environment variables, and WebAssembly modules from `~/.trivy/modules`. Shoalscan passes empty files for `--config` and `--ignorefile`, an empty `--module-dir`, and runs Trivy with the scanners' allowlisted environment.

Trivy also honours inline comments such as `#trivy:ignore:AWS-0089`, and cannot be told not to. Version 0.74.0 accepts more spellings than that one. Any word on a line that starts, after leading `#`, `/` or `*`, with `trivy:` or with the legacy `tfsec:` prefix is read as a list of `key:value` pairs, and the value of an `ignore` key names the check; other keys such as `exp:2030-01-01` (an expiry date) may come before or after it, and the id may carry parameters in brackets. A `*` anywhere in the id is a wildcard, and ids match in any letter case. Shoalscan holds all of these to the same rule as Opengrep's suppression comments: each must name one check, without a wildcard, and an issue on the same line, as in

```hcl
#trivy:ignore:AWS-0089 #123 access logs go to the central bucket
resource "aws_s3_bucket" "assets" {
```

A comment without an issue, with a wildcard, or with more than one check, is a blocking finding (`shoalscan.suppression-without-rule-and-issue`). To miss none, Shoalscan looks for both prefixes anywhere in a line and in any letter case; a word without an `ignore` key, such as the image tag `aquasec/trivy:0.74.0`, is not a comment. Every comment is counted and listed with the other inline suppressions, and so is every finding Trivy reports it silenced, so silencing never looks like fixing. The comments are read in the files Trivy reads, whatever their size (Trivy reads files over `max_target_bytes` too): `.tf`, `.tf.json`, `.tofu`, `.tofu.json`, `.tfvars`, `.hcl`, `.yaml`, `.yml`, `.json`, `.template`, `.tpl`, `.bicep`, Dockerfiles, and the files inside packaged charts (`.tgz`, `.tar.gz`, `.tar`). A file over 64 MB that mentions a Trivy prefix cannot be checked and is reported as an invalid comment.

As a second line of defence, every finding Trivy logs as silenced (it does for Terraform and CloudFormation) must have a valid comment in its file, at or above the finding's first line. If one is not, something the lint did not recognise silenced a check, and the scan fails rather than pass.

### Helm charts

Trivy's own Helm scanner reads ignore comments from the chart as it renders it, and a template can write such a comment at render time, from text that looks like nothing in the source. So Shoalscan turns that scanner off and renders the charts itself:

- **Which charts.** Every directory with a `Chart.yaml`, outside `.git` and the excludes. Subcharts in a chart's `charts/` directory are rendered with their parent; library charts are not rendered on their own.
- **How.** `helm template` with the pinned Helm 4.2.4, offline, in the scanners' isolated environment and network sandbox, with Helm's cache, configuration, data and plugin directories in the scan's private staging directory and no Kubernetes configuration. No plugin or post-renderer runs, `lookup` finds nothing, and dependencies are never fetched.
- **Values.** The chart's own `values.yaml`, and any extra values files you name for the chart, which charts with required values need:

  ```toml
  [trivy.helm_values]
  "deploy/helm/app" = ["deploy/helm/app/values-ci.yaml"]   # chart directory ("." for the root) = values files
  ```

  This is policy: under `--policy-ref` it comes from the base branch. Paths are repository-relative.
- **Nothing a template writes can silence a check.** Before Trivy reads the rendered manifests, every comment line is removed and every inline ignore marker is defused, and a finding Trivy reports as silenced in them fails the scan. Inline ignore comments therefore have no effect in Helm charts (they are still linted like other Trivy comments). Accept a finding in the baseline, or leave a check out with `[trivy] ignore`.
- **Where findings are reported.** Helm marks each rendered document with the template it came from (`# Source: ...`). A finding is reported at that template, on its first line, since rendered lines do not map back to template lines; the message names the resource. Its fingerprint uses the rule, the template and the resource's kind and name, so it stays the same when unrelated lines change.
- **Charts that cannot be rendered** are listed as not fully scanned, every file of them, so a pull request that changes one fails the check: a chart that does not render (`helm render failed`), one whose dependencies are not in its `charts/` directory (`helm chart dependencies missing`; run `helm dependency build` and commit them, or exclude the chart), one that holds a symbolic link (Helm would follow it out of the repository), and one whose extra values file is missing.

Helm's release archives are pinned by SHA-256, archive and binary. Their PGP signatures were checked with gpg against the project's KEYS file when they were pinned; `install` does not check them again, as that would need gpg.

### Leaving checks out

```toml
[trivy]
ignore = ["KSV-0011", "AWS-0089"]   # Trivy check ids
```

This is policy: on a pull request run with `--policy-ref`, it comes from the base branch. Findings of an ignored check are never taken as fixed on the dashboard.

### What Trivy does not report

Trivy logs the Terraform files it cannot parse, and Shoalscan lists them as not fully scanned. A YAML or JSON file it cannot parse is not recognised as configuration at all, so it is neither scanned nor reported.

### Its pin

v0.74.0 is pinned, not the newest release: it had been public for two months when it was pinned, which leaves time for a bad release to be noticed. Each archive's SHA-256 was checked against the release's checksums file and its Sigstore bundle against Trivy's release workflow (`reusable-release.yaml` at the v0.74.0 tag, commit `e1fd17a`). `shoalscan install` downloads the bundle and checks the signature again with cosign before it extracts anything, unless `--skip-signature-check` is given, and then says loudly that it did not. After a successful check it writes `trivy.verified.json` in the tools directory. `scan` checks the binary's SHA-256 before every run, and records `"verification": "sha256 and cosign"` only when that record matches the installed binary; otherwise it records `"sha256 (signature not verified)"` and warns, as it does for Opengrep. Running `shoalscan install` again with cosign available verifies a binary that was installed without the check.

**Next:** [Rules](rules.md).
