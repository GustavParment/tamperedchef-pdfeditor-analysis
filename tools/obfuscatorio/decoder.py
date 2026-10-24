"""Reconstruct the string table: solve the array rotation and decode indices.

The obfuscator rotates the string array at load time (``push(shift())``) until an
internal checksum equals a magic constant. We replay that checksum over every possible
rotation using pure arithmetic — the malicious script itself is never run.
"""
from __future__ import annotations

from dataclasses import dataclass

from .extraction import ChecksumTerm, Extracted, extract
from .jsutils import js_parse_int

# Floating-point tolerance when comparing the replayed checksum to the magic value.
_EPSILON = 1e-6


@dataclass
class StringTable:
    """Decoded string table: maps a decoder index to its original string."""

    elements: list[str]
    offset: int
    rotation: int

    @property
    def rotated(self) -> list[str]:
        r = self.rotation
        return self.elements[r:] + self.elements[:r]

    def decode(self, index: int) -> str:
        """Return the string for a decoder call ``decoder(index)``."""
        return self.rotated[index - self.offset]

    def as_mapping(self) -> dict[int, str]:
        """Return ``{index: string}`` for every slot in the table."""
        rotated = self.rotated
        return {self.offset + i: value for i, value in enumerate(rotated)}


def _checksum(rotated: list[str], offset: int, terms: list[ChecksumTerm]) -> float | None:
    """Replay the rotation self-check for a given rotation. ``None`` == JS ``NaN``."""
    total = 0.0
    for term in terms:
        value = js_parse_int(rotated[term.index - offset])
        if value is None:
            return None
        part = value / term.divisor
        if term.index2 is not None:
            value2 = js_parse_int(rotated[term.index2 - offset])
            if value2 is None:
                return None
            part *= value2 / term.divisor2  # type: ignore[operator]
        total += term.sign * part
    return total


def _solve_rotation(data: Extracted) -> int:
    """Find the rotation count whose checksum equals the magic constant."""
    count = len(data.elements)
    for rotation in range(count):
        rotated = data.elements[rotation:] + data.elements[:rotation]
        value = _checksum(rotated, data.offset, data.terms)
        if value is not None and abs(value - data.magic) < _EPSILON:
            return rotation
    raise ValueError("no rotation satisfied the checksum (unsupported variant?)")


def build_string_table(src: str) -> StringTable:
    """Extract and solve the string table for an obfuscator.io-protected script."""
    data = extract(src)
    rotation = _solve_rotation(data)
    return StringTable(elements=data.elements, offset=data.offset, rotation=rotation)
