# Configuration

Each repository keeps a `.shoalscan.toml` at its root. Every key is optional, and an unknown key is an error, so a typo never turns a setting off silently. A repository without the file uses the defaults. The example below sets every key; the values are examples, not all of them defaults.

On a pull request run with `--policy-ref`, this file is read from the base branch, not from the change; see [Pull requests: the policy comes from the base branch](baseline-and-check.md#pull-requests-the-policy-comes-from-the-base-branch).

## Every key

```toml
# Which scanners run (see Scanners). Default: ["opengrep"].
scanners = ["opengrep", "gitleaks", "hadolint", "zizmor", "trivy"]

# Paths every scanner skips, in gitignore style. Opengrep receives them as
# --exclude patterns; the repository's own .semgrepignore files are ignored.
# Gitleaks and Trivy findings under them are dropped; Hadolint and zizmor never see them.
excludes = ["target", "node_modules", "vendor", "**/fixtures/**"]
# A pattern that could match every file (such as **, * or *e*) is refused:
# each must name a directory or file, or have a literal prefix, suffix or
# part of at least four characters.

# Severities that fail a pull request. INFO never blocks.
blocking = ["ERROR", "WARNING"]

# Path prefixes whose findings are recorded and reported but never fail the
# check, for example demo or example code. Stale baseline entries still fail.
non_blocking_paths = ["demo/", "examples/"]

# Changed files whose partial parses only warn (see "Partial parses" below).
# Use it only for languages whose Opengrep parser is experimental.
parse_warn_only = ["**/Dockerfile", "deploy/charts/**/templates/*.yaml"]

baseline = ".shoalscan/baseline.toml"

[hadolint]
# Hadolint and ShellCheck rules to leave out (see Scanners).
ignore = ["DL3008"]

[zizmor]
# zizmor audits to leave out (see Scanners).
ignore = ["artipacked"]

[trivy]
# Trivy checks to leave out (see Scanners).
ignore = ["KSV-0011"]

[trivy.helm_values]
# Extra values files for rendering a Helm chart, by chart directory ("." for a
# chart at the root); repository-relative. The chart's values.yaml is always used.
"deploy/helm/app" = ["deploy/helm/app/values-ci.yaml"]

[opengrep]
community_rules = true    # the pinned opengrep-rules snapshot
shoalscan_rules = true    # the rules in this repository's rules/ directory
rule_dirs = ["security/rules"]   # your own rules, relative to the repository
# Categories of community rules to run (their metadata.category). Rules with
# no category count as "uncategorised". This applies to the community
# snapshot only; Shoalscan's own rules and yours always run.
categories = ["security"]
# Rules to leave out, by exact id or by prefix ending in ".*".
exclude_rules = ["community.python.lang.security.audit.dangerous-subprocess-use-audit"]

[test_scope]
# Opengrep rules whose findings in proven test-only Rust code never block, by
# exact id or by prefix ending in ".*", as in opengrep.exclude_rules. Off when
# empty (the default). Secret rules, Gitleaks rules, other scanners' rules and
# wildcards such as community.* are refused.
non_blocking = ["community.rust.lang.security.temp-dir", "shoalscan.rust-plain-http-url"]

[limits]
scan_timeout_seconds = 1800
rule_timeout_seconds = 30       # per rule and file
max_target_bytes = 1000000      # larger files are skipped
jobs = 4

# Path prefixes to component names. The longest prefix wins; anything else
# is "other".
[components]
"services/api/" = "api"
"web/" = "web"
```

## Rule selection

Rule selection happens before the scan: Shoalscan copies only the selected rules into a temporary directory and runs Opengrep on that copy, so the installed snapshot is never changed and left-out rules cost nothing. The community snapshot has the categories security, correctness, best-practice, compatibility, maintainability, performance, portability and caching. `exclude_rules` cannot turn off the suppression lint.

Rule ids get a prefix that says where they come from: `community.` for the community snapshot, `shoalscan.` for Shoalscan's own rules, and `repo.` for your rule directories. [Rules](rules.md) describes Shoalscan's own rules and the community snapshot.

## Partial parses

Opengrep's parsers for some languages are experimental. Its Dockerfile and Bash parsers, and its YAML parser when it meets Helm templates, often leave more than half of a real file unparsed. Under the normal rule, any change to such a file then fails the check, even though nothing is wrong with the change. `parse_warn_only` lists globs (the same syntax as `excludes`) for changed files whose partial parses are reported as warnings instead. Their unparsed lines are not checked by any rule, so the report lists each one loudly.

Template files are a special case. A Helm template is a Go template, not YAML, so Opengrep cannot parse it at all and reports a syntax error for the whole file. For a changed file that matches `parse_warn_only`, such a syntax error is also only a warning, listed loudly as `SYNTAX ERROR (warn-only by policy)` and counted in the summary. Opengrep's generic (text) rules still scan the file; the language-aware rules cannot. A skipped file, a timeout, running out of memory or any other error still fails. List only template-language files this way: Helm templates, Jinja-templated YAML and the like. Be aware of the trade-off: a change that deliberately breaks a listed template's syntax keeps the language-aware rules away from it (the generic rules still run). That is acceptable only because, under `--policy-ref`, the list comes from the base branch, so a change cannot add its own files to it.

Use it only for languages whose parser is experimental: Dockerfiles, shell scripts and YAML templates. Never use it for Rust, Python, JavaScript or TypeScript. Their parsers are mature, so a partial parse there usually means the code is broken or is hiding something.

Each entry must name the files it covers. It is a file name (`Dockerfile`), a file name with any extension (`Dockerfile.*`), an extension (`*.sh`, `*.yaml`), or a path with `/` whose last part is one of those (`deploy/**/templates/*.yaml`). An entry without `/` matches a file's own name only, never a directory on its path. Patterns that could cover any file, such as `*e*`, `**` or `src/*`, are refused.

The setting only protects pull requests that run under `--policy-ref`: then the list comes from the base branch, like the rest of the policy, and a change cannot make its own files warn-only. Without `--policy-ref`, or in adoption mode (the first run, before the base branch has a configuration), the configuration in the change itself applies, including its `parse_warn_only`.

## Test scope

`[test_scope] non_blocking` lists Opengrep rules whose findings Shoalscan accepts automatically when it can prove they are in a Rust item compiled only for tests: a top-level `#[cfg(test)]` module, function, `impl`, constant or static, or a `#[test]`, `#[tokio::test]` or `#[rstest]` function. Whole files, such as a crate's `tests/`, are not. Such findings stay in every output, marked with their scope, and never block. Only Opengrep findings in `.rs` files are eligible. Rules that find secrets, Gitleaks rules, other scanners' rules and wildcards broader than three dotted parts are refused. When the repository can set `cfg(test)` itself (a build script's `rustc-cfg`, or `--cfg test` in Cargo configuration), test scope is off for the run. [Test scope](test-scope.md) explains what counts, what does not, and why it is safe.

How `check` treats partial parses and other unscanned files is described in [The baseline and the check](baseline-and-check.md#the-check).

**Next:** [The baseline and the check](baseline-and-check.md).
