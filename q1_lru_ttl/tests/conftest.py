import sys
from pathlib import Path

import pytest

# Let tests import lru_ttl without installing anything (mirrors schema/conftest.py).
sys.path.insert(0, str(Path(__file__).parent.parent))


class FakeClock:
    """A `clock: Callable[[], float]` stand-in with an explicit, controllable
    notion of "now". Tests never use `time.sleep`; they advance this instead, so
    TTL/expiry tests are exact and instant."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, dt: float) -> None:
        if dt < 0:
            raise ValueError(f"FakeClock is monotonic, can't advance by {dt} < 0")
        self.now += dt


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()
