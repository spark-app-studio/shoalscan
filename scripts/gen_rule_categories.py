"""Regenerate tests/data/community_rule_categories.json from the installed snapshot.

Run this whenever the opengrep-rules pin in tools.lock changes. It is a
development helper and needs PyYAML (the CLI itself does not):

    python3 scripts/gen_rule_categories.py ~/.cache/shoalscan/tools/rules/opengrep-rules
"""

import json
import sys
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    snapshot = Path(sys.argv[1])
    lock = tomllib.loads((ROOT / "tools.lock").read_text(encoding="utf-8"))
    rules = {}
    for path in sorted(snapshot.rglob("*")):
        if path.suffix not in (".yaml", ".yml") or not path.is_file():
            continue
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules[path.relative_to(snapshot).as_posix()] = [
            [str(r["id"]), str((r.get("metadata") or {}).get("category", "uncategorised")).lower()]
            for r in doc["rules"]
        ]
    out = {"commit": lock["rules"]["commit"], "generated_with": "PyYAML safe_load", "rules": rules}
    target = ROOT / "tests" / "data" / "community_rule_categories.json"
    target.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {sum(len(v) for v in rules.values())} rules from {len(rules)} files to {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
