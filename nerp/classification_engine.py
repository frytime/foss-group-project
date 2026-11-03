"""
Classification Engine (Part C2).

Single source of truth for classification is nerp.information_flow (CLASSIFIERS).
This module is the command-line entry point: it runs the classifiers over the
raw datasets, writes classified/<dataset>.json (the C -> D handoff in CONTRACT.md)
and a flat results file for the evidence portfolio.
"""
import json
from pathlib import Path

from nerp.information_flow import CLASSIFIERS, write_classified_datasets, load_classified


def classify(dataset: str, record: dict):
    """Classify one record. Returns (Classification, Integrity, reasons, review_flags)."""
    review: list = []
    label, integrity, reasons, _ = CLASSIFIERS[dataset](record, review)
    return label, integrity, reasons, review


def run() -> dict:
    summary = write_classified_datasets()
    results = {
        name: [{"id": next(iter(r.values())), "_label": r["_label"], "_integrity": r["_integrity"],
                "_reasons": r["_reasons"], "_review": r.get("_review", [])}
               for r in load_classified(name)]
        for name in CLASSIFIERS
    }
    exp_dir = Path(__file__).parent / "experiments"
    exp_dir.mkdir(parents=True, exist_ok=True)
    (exp_dir / "classification_results.json").write_text(json.dumps(results, indent=2))
    return summary


if __name__ == "__main__":
    run()
