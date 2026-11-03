"""Shared experiment logger. Writes CONTRACT.md log lines:
{"t":..., "node":..., "term_or_round":..., "event":..., "detail":...}
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


class ExperimentLog:
    def __init__(self, exp_dir: Path):
        self.path = Path(exp_dir) / "log.jsonl"
        self.path.unlink(missing_ok=True)
        self.lines = 0

    def __call__(self, node, term_or_round, event, detail=None):
        entry = {"t": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                 "node": node, "term_or_round": term_or_round, "event": event, "detail": detail or {}}
        with self.path.open("a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
        self.lines += 1

    def phase(self, name, **detail):
        self("experiment", 0, "phase", {"name": name, **detail})


def load_data(name: str):
    return json.loads((PROJECT_ROOT / "data" / f"{name}.json").read_text())
