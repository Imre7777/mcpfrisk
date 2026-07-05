"""Clean fixture for cross-function taint (PATH_TRAVERSAL, feature 012).

Same cross-function shape as crossfn_vuln.py, but the helper VALIDATES the
path before opening it -> must stay finding-free (no new false positives).
Also includes a helper that opens a non-tainted (constant) value -> no taint,
no finding.
"""
from pathlib import Path

BASE = Path("/srv/data").resolve()


def read_file(filename):
    return _load_safe(filename)


def _load_safe(x):
    # Validation inside the helper: the resolved path must stay under BASE.
    resolved = (BASE / x).resolve()
    if not resolved.is_relative_to(BASE):
        raise ValueError("path escapes base directory")
    with open(resolved) as f:
        return f.read()


def read_config(filename):
    # The tool param is NOT passed to the helper; the helper opens a constant.
    _log(filename)
    return _load_constant()


def _log(msg):
    return len(msg)


def _load_constant():
    with open("/etc/myapp/config.toml") as f:  # no taint reaches this sink
        return f.read()
