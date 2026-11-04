"""Write openapi.json, the description of the API this service serves.

CONTRIBUTING asks every interface change to update its description in the same
PR. Regenerate it from the code with:

    uv run python -m coordinator.openapi
"""

import json
from pathlib import Path

from coordinator.main import app

Path("openapi.json").write_text(json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n")
