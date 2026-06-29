"""Regression test: scanning a single FILE path must run the checks.

Bug (fixed): the checks discovered files via `target_path.rglob(pattern)`,
which yields nothing when `target_path` is a file. So `mcpfrisk scan server.py`
silently skipped almost every check (only the no-applies_to-override check
"ran", and even it found nothing). It went unnoticed because the existing
suite always copies fixtures into a *directory* before scanning, and the CI
dogfood scanned a single file behind `|| true`.

The fix (core/fs.py::rglob_or_file) handles file and directory targets
uniformly. This locks the behavior in.
"""
from __future__ import annotations

from pathlib import Path

from mcpfrisk.core.runner import run_static_scan

VULNERABLE_SERVER = Path(__file__).parent / "fixtures" / "vulnerable_server.py"


def test_scanning_a_single_file_path_runs_all_applicable_checks():
    # Scan the FILE directly (not a containing directory).
    result = run_static_scan(VULNERABLE_SERVER)

    for check_id in ("CMD_INJECTION", "PATH_TRAVERSAL", "TOOL_POISONING", "HARDCODED_SECRETS"):
        assert check_id in result.checks_run, (
            f"{check_id} was skipped on a single-file scan; "
            f"checks_run={result.checks_run}, skipped={result.checks_skipped}"
        )

    # And it must actually find the known vulnerabilities in that file.
    assert result.findings, "single-file scan produced no findings on the vulnerable fixture"


def test_single_file_and_directory_scan_find_the_same_findings(tmp_path):
    # Scanning the file directly and scanning a dir that contains only that
    # file must yield the same number of findings.
    file_result = run_static_scan(VULNERABLE_SERVER)

    target_dir = tmp_path / "isolated"
    target_dir.mkdir()
    (target_dir / VULNERABLE_SERVER.name).write_text(
        VULNERABLE_SERVER.read_text(encoding="utf-8"), encoding="utf-8"
    )
    dir_result = run_static_scan(target_dir)

    assert len(file_result.findings) == len(dir_result.findings)
