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
| `test_fn` | A function with `#[test]`, `#[tokio::test]` (with or without arguments) or `#[rstest]` |

The scope's location is the file and line of the attribute. Other attributes may sit next to the one that matters (`#[allow(...)]`, `#[should_panic]`, `#[case(...)]`), an attribute may be split over several lines, and doc comments may come between the attribute and the item.

This is sound wherever the file is used. Code inside a `#[cfg(test)]` item is removed from every build without `cfg(test)`, however the file that holds it is included. A `#[cfg(test)]` module that is `pub` and is referred to elsewhere is still test-only: in a build without `cfg(test)` the module does not exist, so code that refers to it would not compile unless it is itself compiled only for tests. The compiler removes `#[test]` functions from non-test builds, and `#[tokio::test]` and `#[rstest]` expand to `#[test]` functions (and `#[cfg(test)]` items).

## What does not count

Anything Shoalscan cannot prove stays a normal finding. In particular:

- **Whole files.** A crate's `tests/` and `benches/` directories, and the file a `#[cfg(test)] mod NAME;` declaration loads, are not test scope. Whether a file is reachable only from tests cannot be proved from the source: shipped code can include it with a path built at compile time (`include!(concat!(env!("CARGO_MANIFEST_DIR"), ...))`), through a macro, or from another crate. Inside such files, `#[cfg(test)]` items and `#[test]` functions still count. For other findings there, decide in review: exclude test fixtures with `excludes`, or accept findings in the baseline with a reason.
- **Conditions that also hold outside tests:** `#[cfg(any(test, ...))]`, `#[cfg(all(test, ...))]` (Shoalscan does not reason about the other predicates), `#[cfg(not(test))]`, `#[cfg(feature = "...")]` (even `feature = "test"`) and `#[cfg_attr(test, ...)]`.
- **`#[test_case(...)]` functions.** The `test-case` crate keeps the original function, with its body, as a plain function outside `cfg(test)`.
- **Attributed items inside another module.** Opengrep's Rust parser keeps the attributes of a file's top-level items only. So `mod outer { #[cfg(test)] mod inner { ... } }` and a `#[test]` function inside an ordinary module are not test scope.
- **Other items:** `#[cfg(test)] use ...`, structs, traits, macros and inner attributes (`#![cfg(test)]`).
- **`examples/`, `build.rs` and `src/bin/`**, whatever their attributes.
- **A file Opengrep reported an error for** (a partial parse, a timeout): a parser that recovered from an error could place an item's end wrongly.
- **Macros that generate tests** other than `#[tokio::test]` and `#[rstest]`.

### Shadowed test attributes

`#[test]`, `#[tokio::test]` and `#[rstest]` are names, and a file can rebind them: `use test_log::test;` (a documented pattern), `use x::passthrough as test;`, a `mod tokio`, or `extern crate other as tokio;`. Then `#[test]` may not mean a test at all. So a file that binds `test`, `tokio` or `rstest` itself gets no `test_fn` scope: one with `... as test` (or `rstest`, `tokio`), an item or `macro_rules!` of that name, or a `use` that imports one, except a `use` of the real crates (`use tokio::test;`, `use rstest::rstest;`). No file gets `test_fn` scope when any crate uses `#[macro_use] extern crate`, or a `Cargo.toml` takes `tokio` or `rstest` from a path, git or another registry, or renames another crate to that name. The search ignores comments and strings and is deliberately broad: a false alarm only means a missed scope. `cfg(test)` cannot be shadowed, so `cfg_test_module` and `cfg_test_item` are not affected. A glob import (`use helpers::*;`) is not searched: Shoalscan relies on rustc reporting an attribute named `test` brought in by a glob import as ambiguous with the built-in one.

### When the repository can set `cfg(test)` itself

`cfg(test)` means "compiled for tests" only if nothing else sets it. A build script can (`cargo:rustc-cfg=test`), and so can compiler flags (`--cfg test`). If anything in the repository might, test scope is **off for the whole repository**: the scan prints a loud warning and records the reason in `findings.json` under `test_scope.off`. Shoalscan looks, ignoring nothing but `.git`, for:

- a Rust file (a build script or a helper it uses, under any name) that emits a `rustc-cfg` whose value is or starts with `test`, or one built from a variable or a macro (`cargo:rustc-cfg={name}`, `autocfg`'s `emit_rustc_cfg(name)`, `cfg_aliases!`);
- `--cfg` followed by `test` in any `.cargo/config` or `.cargo/config.toml`, or anywhere in a `Cargo.toml` (such as a `[profile]` section).

Shoalscan cannot see flags set outside the repository: the `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS` environment variables, a `.cargo/config.toml` in a parent directory or the home directory, or a build script in a dependency. Building release artifacts without `--cfg test` is the operator's responsibility.

## How Shoalscan proves it

**Opengrep's own parser does the proving.** Shoalscan ships a small rule pack, `scope/rust-test-scope.yaml`, pinned with Shoalscan like its other rules. When `[test_scope]` lists a rule, the pack runs in the same Opengrep scan as the security rules, so the code is parsed once, and its matches give the exact line ranges of the items above. Comments and strings that contain `#[cfg(test)]` are never matches, because the parser does not see them as attributes. The pack's matches are input for Shoalscan, never findings: they are taken out of the results before anything counts or writes them, and out of the SARIF file. No policy setting, such as `exclude_rules`, can turn them off.

Opengrep cannot bind a module's name to a metavariable (`mod $M { ... }` matches nothing), so Shoalscan writes one pattern per module name that follows a `#[cfg(test)]` attribute in the repository's Rust files, after removing comments and strings. A name only proposes a pattern: Opengrep still has to find a module of that name, with exactly `#[cfg(test)]`, in the parsed code. Up to 2,000 names are used, which is several times what a large monorepo needs; when there are more, the scan warns and records how many were left out (`test_scope.module_names_dropped`), and findings in those modules are not accepted.

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
