"""Vulnerable fixture for cross-function taint (PATH_TRAVERSAL, feature 012).

The path-like tool parameter flows into a helper whose parameter is NOT
path-like-named, and the helper opens it without validation. The old
intra-procedural logic misses this (source and sink are in different
functions); the cross-function pass must catch both the positional and the
keyword flow.
"""


def read_file(filename):
    # positional: filename (path-like source) -> helper _load(x) -> open(x)
    return _load(filename)


def _load(x):
    with open(x) as f:  # sink reached via cross-function taint
        return f.read()


def fetch_doc(filepath):
    # keyword: filepath -> helper _fetch(target=...) -> open(target)
    return _fetch(target=filepath)


def _fetch(target):
    with open(target) as f:  # sink reached via keyword-bound cross-function taint
        return f.read()
