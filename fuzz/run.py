"""Run one fuzz target under Atheris (coverage-guided, libFuzzer).

    python fuzz/run.py <target> [libFuzzer options, such as -max_total_time=60 corpus/]

The targets are in `fuzz/targets.py`. Atheris is a development tool, pinned
by hash in `requirements-fuzz.txt`; Shoalscan itself never imports it.
"""

import sys
import tempfile
from pathlib import Path

import atheris

with atheris.instrument_imports(include=["shoalscan", "targets"]):
    import targets


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in targets.TARGETS:
        sys.exit(f"usage: run.py <{'|'.join(targets.TARGETS)}> [libFuzzer options]")
    name = sys.argv[1]
    # Start from the target's seeds; new inputs go to a corpus directory given first, if any.
    seeds = Path(tempfile.mkdtemp(prefix=f"seeds-{name}-"))
    for i, seed in enumerate(targets.SEEDS[name]):
        (seeds / f"seed-{i}").write_bytes(seed)
    atheris.Setup([sys.argv[0], *sys.argv[2:], str(seeds)], targets.TARGETS[name])
    atheris.Fuzz()


if __name__ == "__main__":
    main()
