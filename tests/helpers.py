"""Shared test helpers. Puts `src/` on the import path for a source checkout."""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

DATA = Path(__file__).resolve().parent / "data"


def tools_dir() -> Path:
    """Where the end-to-end tests look for installed tools."""
    return Path(os.environ.get("SHOALSCAN_TOOLS_DIR", ROOT / ".shoalscan" / "tools"))
