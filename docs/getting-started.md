# Getting started

This guide installs Shoalscan and its pinned scanners, runs the first scan and writes the first baseline.

## Install Shoalscan

Shoalscan needs Python 3.11 or later and has no Python dependencies. It runs on Linux and macOS, on x86_64 and arm64.

Each release on [GitHub](https://github.com/spark-app-studio/shoalscan/releases) carries a wheel, a source archive and a `SHA256SUMS` file. Download the wheel and the checksums, check the wheel, and install it:

```sh
base=https://github.com/spark-app-studio/shoalscan/releases/download/v0.3.0
curl -fsSLO "$base/shoalscan-0.3.0-py3-none-any.whl" -O "$base/SHA256SUMS"
shasum -a 256 --check --ignore-missing SHA256SUMS
python3 -m pip install ./shoalscan-0.3.0-py3-none-any.whl
```

You can also install the command from a commit you have reviewed:

```sh
python3 -m pip install "shoalscan @ git+https://github.com/spark-app-studio/shoalscan@<commit-sha>"
```

## Install the pinned scanners

Then install the pinned scanners. By default they go into `$XDG_CACHE_HOME/shoalscan/tools`, or `~/.cache/shoalscan/tools` when `XDG_CACHE_HOME` is not set:

```sh
shoalscan install
```

This downloads Opengrep 1.30.2, cosign, a snapshot of the community rules, Gitleaks 8.30.1 with its default rules, Hadolint 2.15.1, zizmor 1.30.1 and Trivy 0.74.0, over HTTPS only. Trivy's signature is checked with cosign, like Opengrep's. Gitleaks, Hadolint, zizmor and Trivy run only when you enable them ([Scanners](scanners.md)). Every file is checked against its SHA-256 in `tools.lock` before it is used, and each download has a time limit that every read respects. The extracted rules are checked against one digest of all their files, pinned in `tools.lock`; nothing stored in the tools directory is trusted for that check. Files are moved into place atomically, so an interrupted install never leaves a half-written tool behind. Running `install` again verifies what is already there and downloads only what is missing or does not match. Pass `--no-community-rules` to skip the rules snapshot.

### Signature verification with cosign

The Opengrep binary is also checked with `cosign verify-blob` against the identity of the Opengrep release workflow.

If cosign cannot be installed, `shoalscan install` stops. You can pass `--skip-signature-check` to install with the SHA-256 checks only; Shoalscan prints a warning. A cosign download that does not match its pin is reported as possible tampering, and the install stops.

After a successful cosign check, install writes `opengrep.verified.json` in the tools directory: a local install record of what this machine checked (the binary, signature and certificate hashes, the identity, the issuer and the workflow commit). It is not an attestation and proves nothing to anyone else; anyone who can write the tools directory can edit it. Shoalscan calls the binary verified only when that record matches `tools.lock` and the installed binary. Without it (a skipped check, or a binary copied in by hand), every scan warns loudly, and the next `shoalscan install` with cosign verifies the signature.

### Certificate errors on macOS

On a python.org build of Python for macOS, HTTPS downloads can fail with `CERTIFICATE_VERIFY_FAILED`. Run the `Install Certificates.command` that came with Python, or point `SSL_CERT_FILE` at your system's CA bundle.

## Configure the repository

Each repository keeps a `.shoalscan.toml` at its root. Every key is optional, so a short file is enough to start:

```toml
excludes = ["node_modules", "vendor"]
blocking = ["ERROR", "WARNING"]
```

[Configuration](configuration.md) lists every key.

## The first scan

Scan the repository in the current directory:

```sh
shoalscan scan
```

The scan runs Opengrep with local rules only and writes two files to the output directory. `findings.json` holds the normalised findings. `findings.sarif` holds Opengrep's SARIF output, with repository-relative paths and Shoalscan's fingerprints added and the code snippets removed, so you can upload it to a code scanning service. Without snippets, the file never carries a copy of a secret that a rule matched; code scanning services show the line from the repository instead. A scan that fails in any way (the scanner crashes, times out, exits with an error, reports an error, runs a rule that was not selected, or writes output that cannot be read) fails the command. It is never read as "no findings", and no findings file is left behind. Opengrep, like every scanner, gets only an allowlisted environment (`PATH`, the locale, the user name and the time zone) and an empty home directory of its own, without network access where the system allows ([Scanner isolation](security-model.md#scanner-isolation)).

The tools directory and the output directory must be outside the repository: a pull request could plant files inside it. Shoalscan refuses either one inside `--repo`. Unless you pass `--out`, the output goes to a private per-repository directory under the system temporary directory, and `check` finds it there.

## The first baseline

Write the first baseline from a full scan:

```sh
shoalscan baseline init --issue "#123" --reason "Existing findings at adoption, triaged in #123"
```

The issue can be `#123` or a URL. `baseline init` refuses to overwrite an existing baseline unless you pass `--force`. The file is sorted and deterministic, so the same scan always writes the same baseline. When there are no findings, it writes an empty baseline; commit it anyway.

Then compare the findings with the baseline:

```sh
shoalscan check
```

`check` refuses findings that do not match the current tree, so scan again after any edit or commit. The baseline file `check` reads is the one exception: writing or editing it does not change what was scanned, so `scan`, `baseline init` and `check` work in that order without a commit in between. [The baseline and the check](baseline-and-check.md#the-tree-binding) explains why.

Commit `.shoalscan.toml` and the baseline (`.shoalscan/baseline.toml` by default). From then on, run `shoalscan scan` and `shoalscan check` together on every change.

Every command takes `--repo`, `--config`, `--tools-dir` and `--out` where they apply. Run `shoalscan <command> --help` for the details.

**Next:** [Configuration](configuration.md), then [The baseline and the check](baseline-and-check.md) and [CI](ci.md).
