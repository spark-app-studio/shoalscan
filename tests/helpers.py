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
    """Where the end-to-end tests look for installed tools: SHOALSCAN_TOOLS_DIR, else
    `.shoalscan/tools` in the checkout when it exists, else the default tools directory."""
    if os.environ.get("SHOALSCAN_TOOLS_DIR"):
        return Path(os.environ["SHOALSCAN_TOOLS_DIR"])
    local = ROOT / ".shoalscan" / "tools"
    if local.is_dir():
        return local

    from shoalscan.locations import default_tools_dir

    return default_tools_dir()
