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
| `test_fn` | A function with the built-in `#[test]` attribute |

`#[cfg(all(test, ...))]`, which needs `test` and something more, counts like `#[cfg(test)]`. The scope's location is the file and line of the attribute. Other attributes may sit next to the one that matters (`#[allow(...)]`, `#[should_panic]`), an attribute may be split over several lines, and doc comments may come between the attribute and the item.

This is sound wherever the file is used. Code inside a `#[cfg(test)]` item is removed from every build without `cfg(test)`, however the file that holds it is included. A `#[cfg(test)]` module that is `pub` and is referred to elsewhere is still test-only: in a build without `cfg(test)` the module does not exist, so code that refers to it would not compile unless it is itself compiled only for tests. The compiler removes `#[test]` functions from builds that are not tests.

## What does not count

Anything Shoalscan cannot prove stays a normal finding. In particular:

- **`#[tokio::test]`, `#[rstest]` and other test macros.** They are names that a dependency or an import can redefine: a path dependency whose library is called `tokio`, a `[patch]`, a glob import of a module named `tokio`, or `extern crate other as tokio;` all make `#[tokio::test]` mean something else, and Shoalscan cannot prove which crate a name resolves to. A finding in such a function counts as test-only only when it is also inside a `#[cfg(test)]` module. This may change in a later release.
- **Whole files.** A crate's `tests/` and `benches/` directories, and the file a `#[cfg(test)] mod NAME;` declaration loads, are not test scope. Whether a file is reachable only from tests cannot be proved from the source: shipped code can include it with a path built at compile time (`include!(concat!(env!("CARGO_MANIFEST_DIR"), ...))`), through a macro, or from another crate. Inside such files, `#[cfg(test)]` items and `#[test]` functions still count. For other findings there, decide in review: exclude test fixtures with `excludes`, or accept findings in the baseline with a reason.
- **Conditions that also hold outside tests:** `#[cfg(any(test, ...))]`, `#[cfg(not(test))]` (also inside `all(...)`), `#[cfg(feature = "...")]` (even `feature = "test"`), `#[cfg_attr(test, ...)]` and `#[cfg_attr(..., cfg(test))]`.
- **Any spelling Shoalscan does not recognise**, such as `#[cfg(r#test)]`. Every match is checked again: the item's own attributes, with comments and white space removed, must include exactly `#[cfg(test)]`, `#[cfg(all(..., test, ...))]` or `#[test]`. An attribute never carries over to the next item: `#[cfg(test)] struct S;` covers only `S`.
- **`#[test_case(...)]` functions.** The `test-case` crate keeps the original function, with its body, as a plain function outside `cfg(test)`.
- **Attributed items inside another module.** Opengrep's Rust parser keeps the attributes of a file's top-level items only. So `mod outer { #[cfg(test)] mod inner { ... } }` and a `#[test]` function inside an ordinary module are not test scope.
- **Other items:** `#[cfg(test)] use ...`, structs, traits, macros and inner attributes (`#![cfg(test)]`).
- **`examples/`, `build.rs` and `src/bin/`**, whatever their attributes.
- **A file Opengrep reported an error for** (invalid Rust, a partial parse, a timeout): a parser that recovered from an error could place an item's end wrongly.

### A rebound `#[test]`

`test` is a name a file can rebind: `use test_log::test;` (a documented pattern), `use tokio::test;`, `use x::passthrough as test;`. Then `#[test]` may not mean a test at all. So a file that binds `test` itself gets no `test_fn` scope: one with `... as test`, an item or macro named `test`, or a `use` that imports a `test`. No file gets `test_fn` scope when the repository has any `extern crate`, which can bring names into scope for a whole crate. The search ignores comments and strings and is deliberately broad: a false alarm only means a missed scope. A glob import (`use helpers::*;`) is not searched: rustc rejects an attribute named `test` brought in by a glob import as ambiguous with the built-in one (E0659). `cfg(test)` cannot be rebound, so `cfg_test_module` and `cfg_test_item` are not affected.

### When the build could set `cfg(test)` itself

`cfg(test)` means "compiled for tests" only if nothing else sets it, and a build script, a compiler wrapper, compiler flags or a patched dependency can. Shoalscan does not try to guess what such things do. It accepts only what it can read and recognise, and otherwise test scope is **off for the whole repository**: the scan prints a loud warning and records the reason in `findings.json` under `test_scope.off`. Shoalscan reads every file but `.git`:

- **Build scripts.** Any `build.rs`, and any script a `Cargo.toml` names with `build = "..."`, turns test scope off, unless the policy trusts it by its repository path and SHA-256:

  ```toml
  [test_scope]
  trusted_build_scripts = { "crates/ffi/build.rs" = "3b4c...e9" }
  ```

  A script whose content no longer matches turns it off again. Trusting a script means reviewing everything it does: every file it reads, includes or runs, and every crate it uses, since any of them could make it emit `cargo:rustc-cfg=test`. Like the rest of the policy, the list comes from the base branch under `--policy-ref`.
- **Every `Cargo.toml`**, read as TOML. It turns test scope off when it does not parse, has `[replace]` or `cargo-features`, has a `[patch]` entry that is not a path inside the repository (a patched crate in the repository is held to these same rules), has `rustflags` in a profile, or has any key Shoalscan does not know (the package, target, dependency, feature, workspace, profile, badge and lint settings Cargo documents are known).
- **Every `.cargo/config` and `.cargo/config.toml`**, read as TOML. Only `[build]` `target`, `target-dir`, `jobs`, `incremental` and `rustflags`, `[unstable]` `build-std` and `build-std-features`, and `[target.<triple>]` `rustflags`, `linker` and `runner` are accepted. A compiler or wrapper (`build.rustc`, `build.rustc-wrapper`, `build.rustc-workspace-wrapper`), `[patch]`, `[source]`, `paths`, `[env]` or anything else turns test scope off. Each `rustflags` entry must be `-C`, `-L` or `-l` with its value, or a lint level (`-A`, `-W`, `-D`, `-F`); `--cfg`, `-Z`, `--crate-attr`, `@file` and anything else turn it off.
- **Symbolic links** to a directory, or named like a Rust file, turn it off, because Shoalscan does not follow them.

Shoalscan cannot see what is outside the repository: the `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS` environment variables, a `.cargo/config.toml` in a parent directory or the Cargo home, a wrapper set in the environment (`RUSTC_WRAPPER`), or a build script in a dependency from a registry. Building release artifacts without `--cfg test` is the operator's responsibility.

## How Shoalscan proves it

**Opengrep's own parser does the proving.** Shoalscan ships a small rule pack, `scope/rust-test-scope.yaml`, pinned with Shoalscan like its other rules. When `[test_scope]` lists a rule, the pack runs in the same Opengrep scan as the security rules, so the code is parsed once, and its matches give the exact line ranges of the items above. Comments and strings that contain `#[cfg(test)]` are never matches, because the parser does not see them as attributes. The pack's matches are input for Shoalscan, never findings: they are taken out of the results before anything counts or writes them, and out of the SARIF file. No policy setting, such as `exclude_rules`, can turn them off.

Opengrep cannot bind a module's name to a metavariable (`mod $M { ... }` matches nothing), so Shoalscan writes one pattern per module name that follows a `#[cfg(test)]` or `#[cfg(all(...))]` attribute in the repository's Rust files, after removing comments and strings. A name only proposes a pattern: Opengrep still has to find a module of that name, with exactly `#[cfg(test)]`, in the parsed code. Up to 2,000 names are used, which is several times what a large monorepo needs; when there are more, the scan warns and records how many were left out (`test_scope.module_names_dropped`), and findings in those modules are not accepted.

## What happens to a test-scoped finding

A finding is test-scoped when the policy lists its rule, it is an Opengrep finding in a `.rs` file, and its line lies in a proven item (the outermost one is named). Then:

- **findings.json** keeps it, with `"test_scope": {"kind": "cfg_test_module", "path": "src/lib.rs", "line": 7}`. The SARIF result keeps it too, with the same object under `properties["shoalscan/test_scope"]`; it is not a SARIF suppression, so code-scanning tools still show it.
- **`check`** never counts it as blocking, even when it is new, and it is not in the blocking class. The report lists the new ones with their scope, and the summary line and `check.json` count `test_scoped` (and `new_test_scoped` and `baseline_test_scoped`); `check.json` lists each with its scope. `check` applies its own policy again: a mark for a rule its policy does not list is ignored.
- **The history** stores the scope with the finding. The newest scheduled run gives each test-scoped finding without a review an automatic review: **accepted risk**, by `shoalscan (test scope)`, with the description `test-only code: <kind> at <path>:<line>`, a time and the run ([Reviewing findings](reviewing-findings.md#automatic-reviews-for-test-only-code)). A person's review is never replaced.
- **The dashboard** shows an **Accepted: test-only code** tile on the Overview, a filter of the same name on the Findings page, a "test-only" note next to each such finding's review, and the proving scope on its review page.

If the code later moves out of test scope (the `#[cfg(test)]` is removed, or the function moves into shipped code), the finding is normal again at once: it blocks per the policy unless the baseline accepts it. The next scheduled run sets its automatic review back to **open**, with a description saying the test-scope review is superseded. A scheduled run that proves nothing (recorded without `check.json`, or with test scope off) supersedes the automatic reviews of the findings it saw in the same way.

## Existing baseline entries

When you turn the feature on, the baseline may already accept findings that are now test-scoped. Those entries still match a finding, so they are not stale, and `check` does not fail on them. It lists them under "Baseline entries now covered by test scope" and counts them as `baseline_test_scoped`. To remove them, run a scan with the new policy and then:

```sh
shoalscan scan --out "$OUT"
shoalscan baseline prune --test-scope --out "$OUT"
```

`baseline prune --test-scope` removes exactly those entries from the baseline file, after checking that the findings come from this configuration and this tree. Commit the result as its own pull request. Shoalscan does not fail the check on them, because turning the policy on must not break every open pull request, and because removing accepted entries should be a deliberate, reviewed change, not a side effect. Once they are gone, the findings are accepted by test scope alone, and if their code ever ships, they block.

## Limits

- Opengrep sees only top-level attributed items, so test code nested in ordinary modules is not recognised, and whole files are never test scope.
- Flags set outside the repository (`RUSTFLAGS`, a parent directory's Cargo configuration, a dependency's build script) are not seen.
- With the feature on, a scan takes a little longer: the pack adds a few rules to the Rust files, and Shoalscan reads each Rust file and Cargo file once.

**See also:** [Configuration](configuration.md), [The baseline and the check](baseline-and-check.md), [Security model](security-model.md).
