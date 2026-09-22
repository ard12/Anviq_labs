"""The core of the harness: turns two recordings of the same tool(s) into `Finding`s.

`differ.diff_recordings()` is the entry point Q4 imports; everything else in this package is
its building blocks (`schema_diff`, `description_diff`, `behavior_diff`).
"""

from __future__ import annotations

from harness.diff.differ import Report, diff_recordings
from harness.diff.types import Finding, Severity

__all__ = ["Finding", "Report", "Severity", "diff_recordings"]
