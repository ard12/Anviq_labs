"""Lets the tests import `control` and the sibling Q3 `harness` package without installing either
(same trick as q3_tool_harness/tests/conftest.py). `tasks.py test` runs bare `pytest` in this folder."""

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
for _p in (_HERE, _HERE.parent.parent / "q3_tool_harness"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
