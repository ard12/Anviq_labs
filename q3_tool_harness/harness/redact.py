"""Default redaction hook applied to args/results before they are written to a recording.

Secrets must never hit disk. The default is a conservative key-name match; callers with a
richer secret model can pass their own `redact` callable to `Recorder`.
"""

from __future__ import annotations

import re
from typing import Any

DEFAULT_SECRET_KEY_PATTERN = re.compile(r"(password|token|secret|api[_-]?key|authorization)", re.IGNORECASE)
REDACTED = "***REDACTED***"


def default_redact(value: Any, *, key_pattern: re.Pattern[str] = DEFAULT_SECRET_KEY_PATTERN) -> Any:
    """Recursively walk `value`, replacing the value of any dict key matching `key_pattern`."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if isinstance(k, str) and key_pattern.search(k):
                out[k] = REDACTED
            else:
                out[k] = default_redact(v, key_pattern=key_pattern)
        return out
    if isinstance(value, list):
        return [default_redact(v, key_pattern=key_pattern) for v in value]
    if isinstance(value, tuple):
        return tuple(default_redact(v, key_pattern=key_pattern) for v in value)
    return value
