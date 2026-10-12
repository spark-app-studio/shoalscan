# Test scope: findings in Rust code that never ships

Some findings are real patterns in code that is never built into what you ship: a temporary directory used by a unit test, `unsafe` that sets an environment variable inside a test module, a plain `http://` URL in an integration test. Shoalscan can accept such a finding automatically, but only when it can prove the code is compiled for tests alone, and only for the rules your policy names. The finding is still recorded everywhere; it just does not block.

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

Entries are matched the way `opengrep.exclude_rules` matches them: an exact rule id, or a prefix ending in `.*` (`repo.rules.*`). Rule ids carry the prefix of their source (`community.`, `shoalscan.` or `repo.`); see [Rule selection](configuration.md#rule-selection).

The configuration refuses:

- **Any Gitleaks rule.** A real secret in test code is still a leaked secret: it sits in the repository's history, and anyone who can read the code can use it. Rotate it, or record a false positive in the baseline.
- **Rules of any scanner other than Opengrep** (Hadolint, zizmor, Trivy), and anything that is not an Opengrep rule id.
- **Shoalscan's suppression lint.** A suppression comment must name a rule and an issue in test code too.

Like the rest of the policy, `[test_scope]` is read from the base branch when you run with `--policy-ref`, so a pull request cannot accept its own findings by adding a rule here ([Pull requests](baseline-and-check.md#pull-requests-the-policy-comes-from-the-base-branch)).

## What counts as test-only code

| Kind | What it is | The scope's location |
| --- | --- | --- |
| `cfg_test_module` | A `#[cfg(test)] mod NAME { ... }` block | The attribute's file and line |
| `cfg_test_file` | The whole file that a `#[cfg(test)] mod NAME;` declaration loads: `NAME.rs` or `NAME/mod.rs` next to the declaring file, or the `#[path = "..."]` target | The declaration's file and line |
| `cfg_test_item` | A function, `impl` block (inherent or trait), constant or static with `#[cfg(test)]` | The attribute's file and line |
| `test_fn` | A function with `#[test]`, `#[tokio::test]` (with or without arguments) or `#[rstest]` | The attribute's file and line |
| `test_target` | Any file under a crate's `tests/` or `benches/` directory, where the crate is the directory with the nearest `Cargo.toml` (one with a `[package]` table) | The `tests` or `benches` directory, line 0 |

Other attributes may sit next to the one that matters (`#[allow(...)]`, `#[should_panic]`, `#[case(...)]`), an attribute may be split over several lines, and doc comments may come between the attribute and the item.

## What does not count

Anything Shoalscan cannot prove stays a normal finding. In particular:

- **Conditions that also hold outside tests:** `#[cfg(any(test, ...))]`, `#[cfg(all(test, ...))]` (Shoalscan does not reason about the other predicates), `#[cfg(not(test))]`, `#[cfg(feature = "...")]` (even `feature = "test"`) and `#[cfg_attr(test, ...)]`, which only adds attributes under test.
- **`#[test_case(...)]` functions.** The `test-case` crate keeps the original function, with its body, as a plain function outside `cfg(test)`; only the generated module is test-only. `#[rstest]` is different: its output is all `#[test]` functions or `#[cfg(test)]` code.
- **Attributed items inside another module.** Opengrep's Rust parser keeps the attributes of a file's top-level items only and drops the attributes of items inside a module body. So `mod outer { #[cfg(test)] mod inner { ... } }` and a `#[test]` function inside an ordinary module are not test scope. Everything inside a top-level `#[cfg(test)]` module is, nested modules included.
- **Other items:** `#[cfg(test)] use ...`, structs, traits, macros and inner attributes (`#![cfg(test)]`) are not matched.
- **`examples/`, `build.rs` and `src/bin/`.** Code under these paths is never test scope, whatever its attributes, and neither are `tests/` directories of crates under `examples/`.
- **Macros that generate tests** (other than `#[tokio::test]` and `#[rstest]`).
- **An ambiguous module file.** For `#[cfg(test)] mod NAME;`, the file must be certain: exactly one of the files the declaration could load exists, the declaration is at the top of its file, and a `#[path]` value is a plain string. Both `NAME.rs` and `NAME/mod.rs`, or neither, means no scope.
- **A `tests/` or `benches/` directory that Cargo builds into something else:** when any `Cargo.toml` in the repository names a library, binary, example or build script under it. A `Cargo.toml` that does not parse turns `test_target` off for the whole run.

## How Shoalscan proves it

**Opengrep's own parser does the proving.** Shoalscan ships a small rule pack, `scope/rust-test-scope.yaml`, pinned with Shoalscan like its other rules. When `[test_scope]` lists a rule, the pack runs in the same Opengrep scan as the security rules, so the code is parsed once, and its matches give the exact line ranges of the items above. Comments and strings that contain `#[cfg(test)]` are never matches, because the parser does not see them as attributes. The pack's matches are input for Shoalscan, never findings: they are taken out of the results before anything counts or writes them, and out of the SARIF file. No policy setting, such as `exclude_rules`, can turn them off.

Opengrep cannot bind a module's name to a metavariable (`mod $M { ... }` matches nothing), so for modules Shoalscan writes one pattern per module name it finds in a Rust file that mentions `cfg(test)`. A name only proposes a pattern: Opengrep still has to find a module of that name, with exactly `#[cfg(test)]`, in the parsed code. A missed name only means a missed scope.

**Text can only take scope away.** A file-level scope (`test_target`, `cfg_test_file`) is safe only if no shipped code compiles the file. Shoalscan reads every `.rs` file in the repository (excluded ones too, but not `.git` or the `target` build directory) and drops a file-level scope when code outside test scope could load the file:

- a `mod NAME;` declaration that could resolve to it, from any file in a directory above it;
- a `#[path = "..."]` attribute or an `include!("...")` with the same file name;
- a `#[path]` or `include!` whose path is not a plain string (such as `include!(concat!(env!("OUT_DIR"), ...))`), which drops every file-level scope in that crate;
- a symbolic link that points at the file or a directory above it.

This is a plain text search, so a comment or a string can only make it drop more scope, never less. It is repeated until nothing changes, because a file that loses its scope may load others. A Rust file Shoalscan cannot read, or one over 16 MiB, turns file-level scopes off for the run. This also covers a pull request that plants a `Cargo.toml` to make shipped modules look like integration tests: the `mod` declaration that loads them still drops the scope.

**`pub` items in a test module.** A `#[cfg(test)]` module that is `pub` and is referenced from elsewhere is still test-only. In a build without `cfg(test)` the module does not exist, so any code that refers to it would not compile; such code must itself be compiled only for tests. The same holds for a `#[cfg(test)]` function, `impl`, constant or static. `#[test]` functions are removed from non-test builds by the compiler, and `#[tokio::test]` and `#[rstest]` expand to `#[test]` functions (and `#[cfg(test)]` items).

## What happens to a test-scoped finding

A finding is test-scoped when the policy lists its rule, it is an Opengrep finding in a `.rs` file, and its line lies in a proven scope (the outermost one is named). Then:

- **findings.json** keeps it, with `"test_scope": {"kind": "cfg_test_module", "path": "src/lib.rs", "line": 7}`. The SARIF result keeps it too, with the same object under `properties["shoalscan/test_scope"]`; it is not a SARIF suppression, so code-scanning tools still show it.
- **`check`** never counts it as blocking, even when it is new, and it is not in the blocking class. The report lists the new ones with their scope, and the summary line and `check.json` count `test_scoped` (and `new_test_scoped` and `baseline_test_scoped`); `check.json` lists each with its scope. `check` applies its own policy again: a mark for a rule its policy does not list is ignored.
- **The history** stores the scope with the finding. The newest scheduled run gives each test-scoped finding without a review an automatic review: **accepted risk**, by `shoalscan (test scope)`, with the description `test-only code: <kind> at <path>:<line>`, a time and the run, like every review change ([Reviewing findings](reviewing-findings.md#automatic-reviews-for-test-only-code)). A person's review is never replaced.
- **The dashboard** shows an **Accepted: test-only code** tile on the Overview, a filter of the same name on the Findings page, a "test-only" note next to each such finding's review, and the proving scope on its review page.

If the code later moves out of test scope (the `#[cfg(test)]` is removed, or the function moves into shipped code), the finding is normal again at once: it blocks per the policy unless the baseline accepts it, and the next scheduled run sets its automatic review back to **open**, with a description saying the test-scope review is superseded.

## Existing baseline entries

When you turn the feature on, the baseline may already accept findings that are now test-scoped. Those entries still match a finding, so they are not stale, and `check` does not fail on them. It lists them under "Baseline entries now covered by test scope" and counts them as `baseline_test_scoped`. To remove them, run a scan with the new policy and then:

```sh
shoalscan scan --out "$OUT"
shoalscan baseline prune --test-scope --out "$OUT"
```

`baseline prune --test-scope` removes exactly those entries from the baseline file, after checking that the findings come from this configuration and this tree. Commit the result as its own pull request. Shoalscan does not fail the check on them, because turning the policy on must not break every open pull request, and because removing accepted entries should be a deliberate, reviewed change, not a side effect. Once they are gone, the findings are accepted by test scope alone, and if their code ever ships, they block.

## Limits

- Opengrep sees only top-level attributed items (see above), so test code nested in ordinary modules is not recognised.
- `cfg_test_file` and `test_target` trust that the repository is built with Cargo. A build script that copies a test file from another crate into its output, or a build system other than Cargo, is outside what Shoalscan can see.
- With the feature on, a scan takes a little longer: the pack adds a few rules to the Rust files.

**See also:** [Configuration](configuration.md), [The baseline and the check](baseline-and-check.md), [Security model](security-model.md).
