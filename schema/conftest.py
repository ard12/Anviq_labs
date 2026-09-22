import sys
from pathlib import Path

# Let tests import canonical.py without installing anything.
sys.path.insert(0, str(Path(__file__).parent))
