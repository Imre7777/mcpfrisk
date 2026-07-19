"""Ermöglicht `python -m mcpfrisk ...` (delegiert an die CLI).

`python -m mcpfrisk.cli` lief bereits; die erwartete Konvention `python -m
mcpfrisk` braucht dieses Modul, damit der Paketaufruf ausführbar ist.
"""
import sys

from mcpfrisk.cli import main

if __name__ == "__main__":
    sys.exit(main())
