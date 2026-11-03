#!/usr/bin/env python3
"""
NERP Launcher - Run from any directory
Auto-detects project root and executes run_all.py
"""
import sys
from pathlib import Path

# Find project root (directory containing nerp/ and data/)
current = Path(__file__).resolve().parent
project_root = None

for parent in [current] + list(current.parents):
    if (parent / "nerp").exists() and (parent / "data").exists():
        project_root = parent
        break

if project_root is None:
    # Fallback: assume we're in nerp/ and parent is project root
    if current.name == "nerp":
        project_root = current.parent
    else:
        project_root = current

sys.path.insert(0, str(project_root))

# Change to project root for relative paths
import os
os.chdir(project_root)

# Now run the main module
from nerp.run_all import run_full_prototype

if __name__ == "__main__":
    run_full_prototype()