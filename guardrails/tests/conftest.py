import sys
from pathlib import Path

# Make `import check_plan` work without packaging the script.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
