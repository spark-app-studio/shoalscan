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

### When the build could set `cfg(test)` itself

`cfg(test)` means "compiled for tests" only if nothing else sets it, and a build script, a compiler wrapper, compiler flags, a toolchain override or a patched dependency can. Shoalscan does not try to guess what such things do. It accepts only what it can read and recognise, and otherwise test scope is **off for the whole repository**: the scan prints a loud warning and records the reason, with the file (and line, for a text file), in `findings.json` under `test_scope.off`. Shoalscan reads every file but `.git`:

- **Build scripts.** Any `build.rs`, and any Cargo.toml with `build = ...` (other than `false`), turns test scope off. There is no way to trust one: a build script can read, include or run anything, so no review of one file vouches for what it does.
- **Every `Cargo.toml`**, read as TOML. It turns test scope off when it does not parse, has `[replace]` or `cargo-features`, has a `[patch]` entry that is not a path inside the repository (a patched crate in the repository is held to these same rules), has `rustflags` in a profile, or has any key Shoalscan does not know (the package, target, dependency, feature, workspace, profile, badge and lint settings Cargo documents are known).
- **Every `.cargo/config` and `.cargo/config.toml`**, read as TOML. Only `[build]` `target`, `target-dir`, `jobs`, `incremental` and `rustflags`, `[unstable]` `build-std` and `build-std-features`, and `[target.<triple>]` `rustflags`, `linker` and `runner` are accepted, plus `[build] rustc-wrapper` set to a wrapper the policy allows. A compiler (`build.rustc`), another wrapper, `[patch]`, `[source]`, `paths`, `[env]` or anything else turns test scope off. Each `rustflags` entry must be `-C`, `-L` or `-l` with its value, or a lint level (`-A`, `-W`, `-D`, `-F`); `--cfg`, `-Z`, `--crate-attr`, `@file` and anything else turn it off.
- **`rust-toolchain` and `rust-toolchain.toml`** may name a channel, `components`, `targets` and a `profile`; a `path` or anything else turns it off.
- **Every other text file**, Rust source excepted: shell scripts, Dockerfiles, Makefiles, justfiles, `.envrc`, CI workflows and the rest. A line turns test scope off when it has `--cfg` followed by anything but white space and a plain name other than `test` (so `--cfg tokio_unstable` is fine, and `--cfg test`, `--cfg=x`, `--cfg "x"`, `--cfg $X` and `--cfg test="x"` are not), `RUSTC_WORKSPACE_WRAPPER`, `CARGO_ENCODED_RUSTFLAGS`, `RUSTC=`, `cargo rustc`, a compiler or wrapper given to Cargo with `--config`, `--test` together with `rustflags`, `RUSTC_WRAPPER` other than an allowed one, `RUSTFLAGS`, `CARGO_BUILD_RUSTFLAGS`, `CARGO_TARGET_<triple>_RUSTFLAGS` or `RUSTDOCFLAGS` set to a value with `$(`, a backtick, `${` or `$NAME` (a value built at run time, which could read any file, CI expressions such as `${{ vars.FLAGS }}` included).

  Three kinds of text are not searched, because a build cannot run them as they are:

  - **Prose:** `.md`, `.rst` and `.adoc` files. The scan lists them as unchecked. A flag variable built from a command or a variable turns test scope off (above), so `RUSTFLAGS=$(cat notes.md)` cannot read one in. A script that passes a prose file's content to Cargo some other way, such as `cargo build $(cat notes.md)`, is not caught: Dockerfiles and scripts use command substitution on `cargo` lines too often (`--target "$(uname -m)-..."`) for that to be a useful signal.
  - **Whole-line comments** in files whose comments are `#`, known from the name or extension: shell scripts (`.sh`, `.bash`, `.zsh`), YAML, Dockerfiles, Makefiles (`Makefile`, `.mk`), TOML, Python, `.ini` and `.cfg` files, and `.envrc`. A line is skipped only when its first character after white space is `#` and it is not a `#!` line. A file with a heredoc (`<<`) keeps all its comments in the search, because a heredoc's body becomes another file's content, where `#` may not start a comment.
  - **Binary and large files:** those with a NUL byte in their first 8 KiB or larger than 2 MiB, and `node_modules` and Cargo `target` directories. The scan lists them as unchecked.
- **Names in another letter case.** Cargo and rustup look for `Cargo.toml`, `build.rs`, `.cargo/config(.toml)` and `rust-toolchain(.toml)`, and a case-insensitive file system (the default on macOS and Windows) finds `BUILD.RS` or `.Cargo/Config.Toml` too. Any such name in another letter case turns test scope off.
- **Symbolic links** to a directory, a Rust file, one of the names above, or anything outside the repository, and any directory Shoalscan cannot list, turn it off.

To use a compiler cache such as sccache, allow it by name in the policy (read from the base branch under `--policy-ref`):

```toml
[test_scope]
allowed_rustc_wrappers = ["sccache"]
```

Then a line that sets `RUSTC_WRAPPER` to exactly `sccache`, and nothing else (`export RUSTC_WRAPPER=sccache`, `ENV RUSTC_WRAPPER=sccache`, `RUSTC_WRAPPER: sccache`), is accepted, and so is `rustc-wrapper = "sccache"` in `.cargo/config.toml`. Any other value, a variable, a path, or more on the line turns test scope off.

What Shoalscan cannot see is anything set from outside the checkout: the CI runner's environment (`RUSTFLAGS`, `RUSTC_WRAPPER` and the like set in a runner's configuration or by the system), a `.cargo/config.toml` in a parent directory or the Cargo home, a build script in a dependency from a registry, and commands typed or run by tools outside the repository. Building release artifacts without `--cfg test` there is the operator's responsibility.

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
- Settings from outside the checkout (the CI runner's environment, a parent directory's Cargo configuration, a dependency's build script) are not seen.
- With the feature on, a scan takes a little longer: the pack adds a few rules to the Rust files, and Shoalscan reads every file of the repository once.

**See also:** [Configuration](configuration.md), [The baseline and the check](baseline-and-check.md), [Security model](security-model.md).
