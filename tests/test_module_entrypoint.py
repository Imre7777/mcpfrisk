"""Feature 028: `python -m mcpfrisk` muss laufen.

Bisher gab es nur `mcpfrisk/cli.py` mit dem __main__-Guard, also lief nur
`python -m mcpfrisk.cli`. `python -m mcpfrisk` (die erwartete Konvention) brach
mit 'No module named mcpfrisk.__main__' ab. Ein `mcpfrisk/__main__.py` behebt das.
"""
from __future__ import annotations

import subprocess
import sys


def test_python_m_mcpfrisk_version_runs():
    proc = subprocess.run(
        [sys.executable, "-m", "mcpfrisk", "--version"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    # --version gibt die Paketversion aus (mind. eine Ziffer).
    assert any(ch.isdigit() for ch in proc.stdout)


def test_python_m_mcpfrisk_nonexistent_path_exits_2():
    # Konsistenz mit der CLI: nicht-existenter Pfad -> Exit-Code 2.
    proc = subprocess.run(
        [sys.executable, "-m", "mcpfrisk", "scan", "does_not_exist_xyz"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2, (proc.returncode, proc.stderr)
