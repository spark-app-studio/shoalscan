#!/usr/bin/env bash
# Nightly scan of a repository's default branch, recorded in the history
# database that `shoalscan serve` shows.
#
# Usage: examples/scheduled-scan.sh CLONE_DIR
#
# CLONE_DIR is a git clone of the repository. The script fetches it and scans
# the default branch in a temporary worktree, so the clone's own checkout and
# any local changes are never touched.
#
# Environment:
#   SHOALSCAN_SPEC        what pip installs; pin it to a reviewed commit, for
#                         example "shoalscan @ git+https://github.com/spark-app-studio/shoalscan@<sha>"
#   SHOALSCAN_REPO_NAME   the repository's name on the dashboard, such as
#                         owner/project (default: the clone directory's name)
#   SHOALSCAN_BRANCH      the branch to scan (default: the remote's default branch)
#   SHOALSCAN_REMOTE      the remote to fetch (default: origin)
#   SHOALSCAN_PYTHON      the Python that creates the virtual environment;
#                         it must be 3.11 or later (default: python3)
#   SHOALSCAN_HOME        where the virtual environment and tools live
#                         (default: $HOME/.cache/shoalscan)
#   SHOALSCAN_DB          the history database (default: Shoalscan's default,
#                         $XDG_DATA_HOME/shoalscan/history.sqlite3)
#   SHOALSCAN_REQUIRE_NETWORK_SANDBOX
#                         1 (the default) makes the scan fail unless the
#                         scanners can run without network access
#                         (sandbox-exec on macOS, unshare --net on Linux);
#                         0 allows the environment-only fallback
#
# Exit codes: 0 when the run was recorded (whether the check passed or
# failed; the dashboard shows which), 2 when the scan or the setup failed and
# nothing was recorded. Nothing here needs a token or secret.

set -euo pipefail

clone="${1:?usage: scheduled-scan.sh CLONE_DIR}"
clone="$(cd "$clone" && pwd)"
home="${SHOALSCAN_HOME:-$HOME/.cache/shoalscan}"
spec="${SHOALSCAN_SPEC:?set SHOALSCAN_SPEC to a pinned Shoalscan install spec}"
remote="${SHOALSCAN_REMOTE:-origin}"
name="${SHOALSCAN_REPO_NAME:-$(basename "$clone")}"
db=()
if [ -n "${SHOALSCAN_DB:-}" ]; then
  db=(--db "$SHOALSCAN_DB")
fi

fail() {
  echo "shoalscan scheduled scan: $*; nothing was recorded" >&2
  exit 2
}

python="${SHOALSCAN_PYTHON:-python3}"
if ! "$python" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
  found="$("$python" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo "not runnable")"
  fail "Shoalscan needs Python 3.11 or later, but $python is $found; set SHOALSCAN_PYTHON to a newer python"
fi

mkdir -p "$home"
# Reinstall when the pinned spec changes, so a new pin takes effect.
if [ ! -x "$home/venv/bin/shoalscan" ] || [ "$(cat "$home/venv/.shoalscan-spec" 2>/dev/null)" != "$spec" ]; then
  rm -rf "$home/venv"
  "$python" -m venv "$home/venv"
  "$home/venv/bin/python" -m pip install --quiet --no-deps "$spec"
  printf '%s' "$spec" > "$home/venv/.shoalscan-spec"
fi
shoalscan="$home/venv/bin/shoalscan"
"$shoalscan" install --dir "$home/tools" || fail "shoalscan install failed"

# A worktree left by an interrupted run (its directory already gone) is forgotten first.
git -C "$clone" worktree prune
git -C "$clone" fetch --quiet --prune "$remote" || fail "git fetch failed"
branch="${SHOALSCAN_BRANCH:-}"
if [ -z "$branch" ]; then
  head="$(git -C "$clone" symbolic-ref --quiet "refs/remotes/$remote/HEAD" 2>/dev/null)" \
    || fail "cannot tell the default branch; set SHOALSCAN_BRANCH or run: git -C $clone remote set-head $remote --auto"
  branch="${head#refs/remotes/$remote/}"
fi
ref="refs/remotes/$remote/$branch"
commit="$(git -C "$clone" rev-parse --verify --quiet "$ref^{commit}")" || fail "$ref does not exist"

work="$(mktemp -d)"
cleanup() {
  git -C "$clone" worktree remove --force "$work/src" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
mkdir "$work/out"
git -C "$clone" worktree add --quiet --detach "$work/src" "$commit" || fail "git worktree add failed"

started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sandbox=()
if [ "${SHOALSCAN_REQUIRE_NETWORK_SANDBOX:-1}" != "0" ]; then
  sandbox=(--require-network-sandbox)
fi
"$shoalscan" scan --repo "$work/src" --tools-dir "$home/tools" --out "$work/out" ${sandbox[@]+"${sandbox[@]}"} \
  || fail "the scan failed"

status=0
"$shoalscan" check --repo "$work/src" --out "$work/out" > "$work/out/check.txt" || status=$?
if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then
  cat "$work/out/check.txt" >&2
  fail "the check could not run (exit $status)"
fi

"$shoalscan" record ${db[@]+"${db[@]}"} \
  --findings "$work/out/findings.json" --check-output "$work/out/check.txt" \
  --repo-name "$name" --ref "$branch" --commit "$commit" --kind scheduled --scanned-at "$started" --check-exit "$status" \
  || fail "shoalscan record failed"
echo "shoalscan scheduled scan: $name $branch at ${commit:0:12}: check $([ "$status" -eq 0 ] && echo passed || echo failed)"
