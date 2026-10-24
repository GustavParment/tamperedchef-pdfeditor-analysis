"""Static deobfuscation helpers for obfuscator.io string-array protection.

The package reconstructs the hidden string table and rewrites the script into a
readable form **without ever executing the input**. See :mod:`obfuscatorio.decoder`
for the entry point :func:`build_string_table`.
"""
from __future__ import annotations

from .decoder import StringTable, build_string_table
from .transform import deobfuscate

__all__ = ["StringTable", "build_string_table", "deobfuscate"]
