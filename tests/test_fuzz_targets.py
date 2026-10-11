"""The fuzz targets (fuzz/targets.py), over their seeds and some random input, without Atheris."""

import random
import sys
import unittest
from pathlib import Path

import helpers  # noqa: F401

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "fuzz"))
import targets  # noqa: E402

RANDOM_INPUTS = 150


def mutations(seed: bytes, rng: random.Random):
    """The seed, then random bytes and random edits of the seed."""
    yield seed
    for _ in range(RANDOM_INPUTS // 3):
        yield rng.randbytes(rng.randrange(0, 200))
        data = bytearray(seed)
        for _ in range(rng.randrange(1, 8)):
            if data and rng.random() < 0.5:
                data[rng.randrange(len(data))] = rng.randrange(256)
            else:
                data.insert(rng.randrange(len(data) + 1), rng.choice(b'[]{}"\\=.,:#`*<>|\n\x00'))
        yield bytes(data)


class FuzzTargetTests(unittest.TestCase):
    def test_every_target_has_seeds(self):
        self.assertEqual(set(targets.TARGETS), set(targets.SEEDS))

    def test_targets_hold_their_contracts(self):
        rng = random.Random(1729)
        for name, target in targets.TARGETS.items():
            for seed in targets.SEEDS[name]:
                for data in mutations(seed, rng):
                    with self.subTest(target=name, data=data[:60]):
                        target(data)

    def test_the_fuzz_runner_imports_atheris(self):
        # OpenSSF Scorecard finds Python fuzzing by this import.
        self.assertIn("import atheris", (Path(targets.__file__).parent / "run.py").read_text())


if __name__ == "__main__":
    unittest.main()
