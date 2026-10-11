#!/usr/bin/env bash
# Run Shoalscan on a self-hosted runner or any machine with Python 3.11+.
#
# Usage: examples/self-hosted.sh [REPO_DIR]
#
# Environment:
#   SHOALSCAN_SPEC        what pip installs; pin it to a reviewed commit, for
#                         example "shoalscan @ git+https://github.com/spark-app-studio/shoalscan@<sha>"
#   SHOALSCAN_HOME        where the virtual environment and tools live
#                         (default: $HOME/.cache/shoalscan)
#   SHOALSCAN_OUT         where findings.json and findings.sarif go
#                         (default: a new temporary directory)
#   SHOALSCAN_POLICY_REF  on a pull request, the base commit's full SHA (or a
#                         fully qualified ref such as refs/remotes/origin/main):
#                         the configuration, baseline and rule directories are
#                         then read from it. Short names are refused.
#
# Exit codes: 0 pass, 1 blocking findings or stale baseline entries,
# 2 broken setup or a scanner failure. Nothing here needs a token or secret.

set -euo pipefail

repo="${1:-.}"
home="${SHOALSCAN_HOME:-$HOME/.cache/shoalscan}"
out="${SHOALSCAN_OUT:-$(mktemp -d)}"
spec="${SHOALSCAN_SPEC:?set SHOALSCAN_SPEC to a pinned Shoalscan install spec}"
policy=()
if [ -n "${SHOALSCAN_POLICY_REF:-}" ]; then
  policy=(--policy-ref "$SHOALSCAN_POLICY_REF")
fi

mkdir -p "$home"
# Reinstall when the pinned spec changes, so a new pin takes effect.
if [ ! -x "$home/venv/bin/shoalscan" ] || [ "$(cat "$home/venv/.shoalscan-spec" 2>/dev/null)" != "$spec" ]; then
  rm -rf "$home/venv"
  python3 -m venv "$home/venv"
  "$home/venv/bin/python" -m pip install --quiet --no-deps "$spec"
  printf '%s' "$spec" > "$home/venv/.shoalscan-spec"
fi
shoalscan="$home/venv/bin/shoalscan"

# Idempotent: verifies what is already installed and downloads only what is
# missing or does not match tools.lock.
"$shoalscan" install --dir "$home/tools"

status=0
"$shoalscan" scan --repo "$repo" --tools-dir "$home/tools" --out "$out" ${policy[@]+"${policy[@]}"} || status=$?
if [ "$status" -ne 0 ]; then
  echo "shoalscan: the scan failed (exit $status); this run does not pass" >&2
  exit 2
fi

"$shoalscan" check --repo "$repo" --out "$out" ${policy[@]+"${policy[@]}"} || status=$?
echo "findings: $out/findings.json and $out/findings.sarif"
exit "$status"
