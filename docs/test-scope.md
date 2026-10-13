# Test scope: findings in Rust test code

Some findings are real patterns in code that is never built into what you ship: a temporary directory in a unit test, `unsafe` that sets an environment variable in a test module. Shoalscan can accept such a finding automatically, but only when it can prove the code is compiled for tests alone, and only for the rules your policy names. The finding is still recorded everywhere; it just does not block.

The feature is off until the policy turns it on, and it covers Opengrep findings in Rust files only.

## Turning it on

List the rules in `.shoalscan.toml`:

```toml
[test_scope]
non_blocking = [
  "community.rust.lang.security.temp-dir",
  "community.rust.lang.security.unsafe-usage",
  "community.rust.lang.security.args",
  "shoalscan.rust-plain-http-url",
]
```

Entries are matched the way `opengrep.exclude_rules` matches them: an exact rule id, or a prefix ending in `.*`. Rule ids carry the prefix of their source (`community.`, `shoalscan.` or `repo.`); see [Rule selection](configuration.md#rule-selection).

The configuration refuses:

- **Rules that find secrets.** Any rule whose id contains `secret`, or names a token, key or JWT family (`detected-...-token`, `...-api-key`, `private-key`, `jwt`), and every Gitleaks rule. A real secret in test code is still a leaked secret: it sits in the repository's history, and anyone who can read the code can use it. Rotate it, or record a false positive in the baseline.
- **Broad wildcards.** A `prefix.*` entry needs at least three dotted parts before the `*` (`community.rust.lang.security.*` is accepted; `community.*`, `shoalscan.*` and `repo.rules.*` are not). Name the rules you mean.
- **Rules of any scanner other than Opengrep** (Hadolint, zizmor, Trivy), anything that is not an Opengrep rule id, and Shoalscan's suppression lint.

Like the rest of the policy, `[test_scope]` is read from the base branch when you run with `--policy-ref`, so a pull request cannot accept its own findings by adding a rule here ([Pull requests](baseline-and-check.md#pull-requests-the-policy-comes-from-the-base-branch)).

## What counts as test-only code

Only items count: the code inside an attribute's item, at the top level of a file.

| Kind | What it is |
| --- | --- |
| `cfg_test_module` | A `#[cfg(test)] mod NAME { ... }` block, with everything in it, nested modules included |
| `cfg_test_item` | A function, `impl` block (inherent or trait), constant or static with `#[cfg(test)]` |

`#[cfg(all(test, ...))]`, which needs `test` and something more, counts like `#[cfg(test)]`. The scope's location is the file and line of the attribute. Other attributes may sit next to the one that matters (`#[allow(...)]`), an attribute may be split over several lines, and doc comments may come between the attribute and the item.

This is sound wherever the file is used. Code inside a `#[cfg(test)]` item is removed from every build without `cfg(test)`, however the file that holds it is included. A `#[cfg(test)]` module that is `pub` and is referred to elsewhere is still test-only: in a build without `cfg(test)` the module does not exist, so code that refers to it would not compile unless it is itself compiled only for tests.

## What does not count

Anything Shoalscan cannot prove stays a normal finding. In particular:

- **Test functions: `#[test]`, `#[tokio::test]`, `#[rstest]` and the like.** Each is a name, and Shoalscan cannot prove which macro a name means in a file. A dependency or an import can redefine `tokio::test` or `rstest`, and even `#[test]` can be rebound: an `include!` carries the including file's `use some_crate::test;` into the included code, and on nightly Rust a `macro_rules!` attribute named `test` applies to child modules. A finding in a test function counts only when the function is also inside a `#[cfg(test)]` module, as unit tests usually are. Integration tests under `tests/` are outside this feature for now.
- **Whole files.** A crate's `tests/` and `benches/` directories, and the file a `#[cfg(test)] mod NAME;` declaration loads, are not test scope. Whether a file is reachable only from tests cannot be proved from the source: shipped code can include it with a path built at compile time (`include!(concat!(env!("CARGO_MANIFEST_DIR"), ...))`), through a macro, or from another crate. Inside such files, `#[cfg(test)]` items still count. For other findings there, decide in review: exclude test fixtures with `excludes`, or accept findings in the baseline with a reason.
- **Code beside an item.** A finding counts only when all of it, from its first byte to its last, lies inside the item Opengrep matched. Shipped code on the same line as a `#[cfg(test)]` item, after a test module's closing brace, or after `#[cfg(test)] const X: u8 = 1;` is not test scope.
- **Conditions that also hold outside tests:** `#[cfg(any(test, ...))]`, `#[cfg(not(test))]` (also inside `all(...)`), `#[cfg(feature = "...")]` (even `feature = "test"`), `#[cfg_attr(test, ...)]` and `#[cfg_attr(..., cfg(test))]`.
- **Any spelling Shoalscan does not recognise**, such as `#[cfg(r#test)]`. Every match is checked again: the item's own attributes, with comments and white space removed, must include exactly `#[cfg(test)]` or `#[cfg(all(..., test, ...))]`. An attribute never carries over to the next item: `#[cfg(test)] struct S;` covers only `S`.
- **Attributed items inside another module.** Opengrep's Rust parser keeps the attributes of a file's top-level items only. So `mod outer { #[cfg(test)] mod inner { ... } }` is not test scope.
- **Other items:** `#[cfg(test)] use ...`, structs, traits, macros and inner attributes (`#![cfg(test)]`).
- **`examples/`, `build.rs` and `src/bin/`**, whatever their attributes.
- **A file Opengrep reported an error for** (a partial parse, a timeout): a parser that recovered from an error could place an item's end wrongly.

## The trust model

`cfg(test)` means "compiled for tests" only if nothing else sets it, and a build script, a compiler or linker wrapper, compiler flags, a toolchain override, a CI step or a patched dependency can. Shoalscan does not try to read every script, workflow and configuration a build might use; that cannot be done completely. Instead it trusts two things and checks the rest:

- **The base branch is trusted.** It is code that was already reviewed: its scripts, CI workflows, Dockerfiles and documentation are what you decided to build with.
- **The CI environment is trusted:** the runner, its environment variables (`RUSTFLAGS`, `RUSTC_WRAPPER` and the like set outside the repository), the Cargo home and anything set from outside the checkout. Building release artifacts without `--cfg test` is the operator's responsibility.
- **A pull request keeps test scope only when it changes nothing but Rust source.** With `--policy-ref`, Shoalscan lists every path the scanned tree changes compared with the merge base of the policy ref and HEAD: committed, staged and unstaged changes and untracked files (not files `.gitignore` ignores), with renames listed as a deletion and an addition (`--no-renames`). Test scope is off for the scan when any changed path:
  - is not a `.rs` file;
  - is, or lies under, a name Cargo or rustup reads (`build.rs`, `Cargo.toml`, `.cargo`, `rust-toolchain`, `rust-toolchain.toml`), in any spelling (see below);
  - is deleted, is a symbolic link or a submodule, or has its mode changed;
  - lies under a `target/` or `node_modules/` directory.

  The warning names the first such path. So a change that touches a workflow, a script, a Dockerfile, a document or the Shoalscan policy itself loses test scope for that run, whatever it contains, and is reviewed like any other.
- **The base must be found.** If git cannot find the merge base (a shallow clone without it, an unrelated history) or fails, test scope is off for the scan, with a loud reason. In CI, fetch the history back to the merge base: with GitHub Actions' checkout, `fetch-depth: 0`, as `examples/github-actions/shoalscan.yml` does.
- **Without a policy ref** (a scheduled scan of the default branch, or a local scan of a tree you trust), there is no change to check, and the whole tree is trusted, subject to the checks below.

### Checks on the whole tree

These still run on every scan, so that the base itself cannot hold what would set `cfg(test)` where Shoalscan can see it. Shoalscan walks the whole tree, `target/` and `node_modules/` included (only `.git` is skipped), and turns test scope off for the whole scan when it finds:

- **A build script.** Any `build.rs`, and any Cargo.toml with `build = ...` (other than `false`). There is no way to trust one: a build script can read, include or run anything.
- **A `Cargo.toml` it does not fully understand**, read as TOML: one that does not parse, has `[replace]` or `cargo-features`, a `[patch]` entry that is not a path inside the repository (a patched crate in the repository is held to these same rules), `rustflags` in a profile, or any key Shoalscan does not know (the package, target, dependency, feature, workspace, profile, badge and lint settings Cargo documents are known).
- **A `.cargo/config` or `.cargo/config.toml` outside its allowlist**, read as TOML. Only `[build]` `target`, `target-dir`, `jobs`, `incremental` and `rustflags`, `[unstable]` `build-std` and `build-std-features`, and `[target.<triple>]` `rustflags` and `runner` are accepted, plus `[build] rustc-wrapper` set to a wrapper the policy allows. A compiler (`build.rustc`), a linker (`[target] linker`), another wrapper, `[patch]`, `[source]`, `paths`, `[env]` or anything else turns test scope off. Each `rustflags` entry must be `-C` (not a linker setting such as `-C linker=` or `-Clinker-flavor=`), `-L` or `-l` with its value, or a lint level (`-A`, `-W`, `-D`, `-F`); `--cfg`, `-Z`, `--crate-attr`, `@file` and anything else turn it off.
- **A `rust-toolchain` or `rust-toolchain.toml`** that names anything but a channel, `components`, `targets` and a `profile` (a `path`, for one).
- **A name that could stand for one of these on a case-insensitive file system** (the default on macOS and Windows). Shoalscan compares names after Unicode normalisation (NFKC) and full case folding, so `BUILD.RS`, `.Cargo/Config.Toml`, `build.rſ` (a long s, which folds to `s`) and full-width letters all count as the special name, and any spelling other than the exact one turns test scope off.
- **Symbolic links** to a directory, a Rust file, one of the names above or anything outside the tree, and any directory that cannot be listed.

To use a compiler cache such as sccache from `.cargo/config.toml`, allow it by name in the policy (read from the base branch under `--policy-ref`):

```toml
[test_scope]
allowed_rustc_wrappers = ["sccache"]
```

Then `[build] rustc-wrapper = "sccache"` is accepted. A wrapper set in the CI environment (`RUSTC_WRAPPER`) is part of the trusted environment and is not checked.

## How Shoalscan proves it

**Opengrep's own parser does the proving.** Shoalscan ships a small rule pack, `scope/rust-test-scope.yaml`, pinned with Shoalscan like its other rules. When `[test_scope]` lists a rule, the pack runs in the same Opengrep scan as the security rules, so the code is parsed once, and its matches give the exact byte ranges of the items above. Comments and strings that contain `#[cfg(test)]` are never matches, because the parser does not see them as attributes. The pack's matches are input for Shoalscan, never findings: they are taken out of the results before anything counts or writes them, and out of the SARIF file. No policy setting, such as `exclude_rules`, can turn them off.

Opengrep cannot bind a module's name to a metavariable (`mod $M { ... }` matches nothing), so Shoalscan writes one pattern per module name that follows a `#[cfg(test)]` or `#[cfg(all(...))]` attribute in the repository's Rust files, after removing comments and strings. A name only proposes a pattern: Opengrep still has to find a module of that name, with exactly `#[cfg(test)]`, in the parsed code. Up to 2,000 names are used, which is several times what a large monorepo needs; when there are more, the scan warns and records how many were left out (`test_scope.module_names_dropped`), and findings in those modules are not accepted.

## What happens to a test-scoped finding

A finding is test-scoped when the policy lists its rule, it is an Opengrep finding in a `.rs` file, and its whole byte range, from its first byte to its last, lies inside a proven item (the outermost one is named). Then:

- **findings.json** keeps it, with `"test_scope": {"kind": "cfg_test_module", "path": "src/lib.rs", "line": 7}`. The SARIF result keeps it too, with the same object under `properties["shoalscan/test_scope"]`; it is not a SARIF suppression, so code-scanning tools still show it.
- **`check`** never counts it as blocking, even when it is new, and it is not in the blocking class. The report lists the new ones with their scope, and the summary line and `check.json` count `test_scoped` (and `new_test_scoped` and `baseline_test_scoped`); `check.json` lists each with its scope. `check` applies its own policy again: a mark for a rule its policy does not list is ignored.
- **The history** stores the scope with the finding. The newest scheduled run gives each test-scoped finding without a review an automatic review: **accepted risk**, by `shoalscan (test scope)`, with the description `test-only code: <kind> at <path>:<line>`, a time and the run ([Reviewing findings](reviewing-findings.md#automatic-reviews-for-test-only-code)). A person's review is never replaced.
- **The dashboard** shows an **Accepted: test-only code** tile on the Overview, a filter of the same name on the Findings page, a "test-only" note next to each such finding's review, and the proving scope on its review page.

If the code later moves out of test scope (the `#[cfg(test)]` is removed, or the code moves into shipped code), the finding is normal again at once: it blocks per the policy unless the baseline accepts it. The next scheduled run sets its automatic review back to **open**, with a description saying the test-scope review is superseded. A scheduled run that proves nothing (recorded without `check.json`, or with test scope off) supersedes the automatic reviews of the findings it saw in the same way.

## Existing baseline entries

When you turn the feature on, the baseline may already accept findings that are now test-scoped. Those entries still match a finding, so they are not stale, and `check` does not fail on them. It lists them under "Baseline entries now covered by test scope" and counts them as `baseline_test_scoped`. To remove them, run a scan with the new policy and then:

```sh
shoalscan scan --out "$OUT"
shoalscan baseline prune --test-scope --out "$OUT"
```

`baseline prune --test-scope` removes exactly those entries from the baseline file, after checking that the findings come from this configuration and this tree. Commit the result as its own pull request. Shoalscan does not fail the check on them, because turning the policy on must not break every open pull request, and because removing accepted entries should be a deliberate, reviewed change, not a side effect. Once they are gone, the findings are accepted by test scope alone, and if their code ever ships, they block.

## Limits

- Opengrep sees only top-level attributed items, so test code nested in ordinary modules is not recognised; whole files and test functions are never test scope.
- A repository with a build script gets no test scope at all.
- A pull request that changes anything but Rust source gets no test scope for that run.
- The base branch and the CI environment are trusted, not checked line by line: settings from outside the checkout (the runner's environment, a parent directory's Cargo configuration, a dependency's build script) and the base's own scripts and workflows are not searched.
- With the feature on, a scan takes a little longer: the pack adds a few rules to the Rust files, and Shoalscan walks the whole tree once.

**See also:** [Configuration](configuration.md), [The baseline and the check](baseline-and-check.md), [Security model](security-model.md).
