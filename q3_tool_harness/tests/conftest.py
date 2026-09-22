import sys
from pathlib import Path

# Let tests import `harness` without installing the package (mirrors schema/conftest.py).
sys.path.insert(0, str(Path(__file__).parent.parent))
