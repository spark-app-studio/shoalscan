# Test code labels

When a Rust finding sits inside test code, a reviewer usually wants to know that first. Shoalscan can label such findings: a finding whose code lies inside a `#[cfg(test)]` module or item gets the label **test code**, and the labelled findings are grouped apart in the scan output, `findings.json`, the check report and the dashboard.

A label is triage help. It is not a security proof, and it never decides anything:

- **A labelled finding blocks exactly like any other.** A new labelled finding with a blocking severity fails `check`, and the check's result is the same as without labels. Nothing passes because of a label.
- **Only a person accepts one,** through the baseline or a dashboard review, as for any finding (see [Accepting a finding in test code](#accepting-a-finding-in-test-code)).

## Why a label is not a proof

`#[cfg(test)]` code is meant to be compiled only for tests, but the build decides what is compiled, and much can change it: a procedural macro in the repository can emit any code whatever its input's attributes say, a build tool that the build scripts run can compile test code into a release, a build script can set `cfg(test)`, and so can compiler flags, wrappers or linker settings in the build configuration, the CI environment or a dependency. A scanner reads the source; it cannot rule all of that out for an arbitrary repository. So Shoalscan tells you where a finding sits, and leaves the decision to you.

## Turning labels on

List the rules whose Rust findings should be labelled in `.shoalscan.toml`:

```toml
[test_code]
rules = [
  "community.rust.lang.security.temp-dir",
  "community.rust.lang.security.unsafe-usage",
  "community.rust.lang.security.args",
  "shoalscan.rust-plain-http-url",
]
```

Entries are matched the way `opengrep.exclude_rules` matches them: an exact rule id, or a prefix ending in `.*`. Only Opengrep findings in `.rs` files get labels. Like the rest of the policy, `[test_code]` is read from the base branch with `--policy-ref`.

The configuration refuses:

- **Rules that find secrets.** Any rule whose id contains `secret`, or names a token, key or JWT family (`detected-...-token`, `...-api-key`, `private-key`, `jwt`), and every Gitleaks rule: a real secret in test code is still a leaked secret, and a label must not make one look harmless.
- **Broad wildcards.** A `prefix.*` entry needs at least three dotted parts before the `*` (`community.rust.lang.security.*` is accepted; `community.*` and `repo.rules.*` are not).
- **Rules of any scanner other than Opengrep**, anything that is not an Opengrep rule id, and Shoalscan's suppression lint.

## What gets a label

| Kind | What it is |
| --- | --- |
| `cfg_test_module` | A top-level `#[cfg(test)] mod NAME { ... }` block, with everything in it, nested modules included |
| `cfg_test_item` | A top-level function, `impl` block (inherent or trait), constant or static with `#[cfg(test)]` |

`#[cfg(all(test, ...))]` counts like `#[cfg(test)]`. The label records the file and line of the attribute.

Opengrep's own Rust parser finds the items: Shoalscan ships a small rule pack, `scope/rust-test-scope.yaml`, which runs in the same scan as the security rules. Its matches are never findings. A finding is labelled only when:

- all of it, from its first byte to its last, lies inside the item Opengrep matched (shipped code on the same line as a test item, or after a test module's closing brace, gets no label);
- the item's own attribute, with comments and white space removed, is exactly `#[cfg(test)]` or `#[cfg(all(..., test, ...))]` (so `#[cfg(r#test)]`, `#[cfg_attr(..., cfg(test))]`, `#[cfg(any(test, ...))]` and `#[cfg(not(test))]` get none, and an attribute never carries over to the next item);
- Opengrep reported no error for the file.

No label goes to test functions (`#[test]`, `#[tokio::test]`, `#[rstest]`) outside a `#[cfg(test)]` module, since their names can be rebound; to whole files such as a crate's `tests/`; to items nested in an ordinary module (Opengrep keeps the attributes of top-level items only); or to code under `examples/`, in `build.rs` or under `src/bin/`.

Opengrep cannot bind a module's name to a metavariable, so Shoalscan writes one pattern per module name that follows such an attribute in the tree's Rust files, up to 2,000 names; when there are more, the scan warns, and findings in the modules left out get no label.

## When the labels may be unreliable

Shoalscan also reads the whole tree (only `.git` is skipped, `target/` and `node_modules/` included) and adds a note, "the test code labels may be unreliable: <reason>", to the scan output and to `findings.json` (`test_code.unreliable`), when it finds something that is known to change how test code is compiled:

- a build script (`build.rs`, or `build = ...` in a Cargo.toml);
- a procedural macro crate (`proc-macro = true`);
- a `Cargo.toml`, `.cargo/config(.toml)` or `rust-toolchain(.toml)` it does not fully understand: one that does not parse, `[replace]`, `[source]`, `paths`, `cargo-features`, a `[patch]` from outside the repository, a compiler, a wrapper, a linker (`linker`, `-C linker=`, `-C link-arg=`, `-C link-args=`), `rustflags` other than `-C`, `-L`, `-l` and lint levels, a toolchain `path`, or any key it does not know;
- a name that could stand for one of those files on a case-insensitive file system (compared after Unicode normalisation and case folding, so `BUILD.RS` and `build.rſ` count), a symbolic link it cannot follow, or a directory it cannot list.

The note never changes whether a finding blocks. Its absence is not a guarantee either: scripts, CI workflows and the build environment are not read.

## Accepting a finding in test code

A labelled finding blocks until a person accepts it, with the mechanisms Shoalscan already has.

**In the baseline (what CI reads).** After a scan with the policy, a reviewer runs:

```sh
shoalscan baseline accept --test-code --fingerprint <fingerprint> --by "Dana Reviewer" --issue "#123" --out "$OUT"
```

`--fingerprint` names a labelled finding the baseline lacks (repeat it for several, or pass `--all` for every such finding). The command adds a baseline entry for each, with the issue and the reason `Accepted: test code (<kind> at <path>:<line>); accepted by <who> on <date>`, after checking that the findings come from this configuration and this tree. It refuses a finding that has no label. Commit the baseline through a reviewed change on the base branch: like any baseline addition, an entry a pull request adds to its own baseline fails the check under `--policy-ref` ([Pull requests](baseline-and-check.md#pull-requests-the-policy-comes-from-the-base-branch)).

**On the dashboard (a recorded decision).** A labelled finding's review page shows its label and an **Accept as test code** button, available to any signed-in person, as reviews are. It records an ordinary review by that signed-in person, at that time, with the status **Accepted risk** and the reason "Accepted: test code (...)". The server checks that the run labels the finding as test code and writes the reason itself; the browser sends no text. Like every review, it does not change what blocks CI; `shoalscan triage export` turns such reviews into baseline entries, with "(reviewed in dashboard by WHO on WHEN)", for a reviewed change ([Reviewing findings](reviewing-findings.md)). Only reviews a signed-in person made are exported.

## Where labels show

- **Scan:** the number of labelled findings, and the note when the labels may be unreliable.
- **findings.json** and the **SARIF** file: `"test_code": {"kind": "cfg_test_module", "path": "src/lib.rs", "line": 7}` on each labelled finding (in SARIF under `properties["shoalscan/test_code"]`, not as a suppression).
- **check:** the summary counts `test_code`, `new_test_code` and `new_blocking_test_code`; the report lists new blocking labelled findings in a group of their own, with their labels and how to accept them; `check.json` lists every label. A label is ignored unless the check's own policy lists the rule.
- **Dashboard:** a **Labelled as test code** tile and filter, the label next to each finding and on its review page, and the **Accept as test code** button.

**See also:** [Configuration](configuration.md), [The baseline and the check](baseline-and-check.md), [Reviewing findings](reviewing-findings.md).
