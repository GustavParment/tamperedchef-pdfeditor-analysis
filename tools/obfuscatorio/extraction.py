"""Locate the three obfuscator.io constructs inside a protected script.

A typical obfuscator.io payload contains:

* a **string-array function** ``function _0xAAAA(){const _0xBBBB=[...];...}``
* a **decoder** ``function _0xCCCC(a,b){...a=a-OFFSET;return array[a];}``
* a **rotation IIFE** that shuffles the array until a checksum equals a magic value.

All three are found with regular expressions and brace matching — the text is never
evaluated.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .jsutils import parse_string_array

# One checksum term, e.g. ``parseInt(_0xd(0x29b))/0x1`` optionally ``*(parseInt(..)/0x7)``.
_TERM = re.compile(
    r"([+\-]*)parseInt\(\w+\((0x[0-9a-f]+)\)\)/(0x[0-9a-f]+)"
    r"(?:\*\(parseInt\(\w+\((0x[0-9a-f]+)\)\)/(0x[0-9a-f]+)\))?"
)


@dataclass(frozen=True)
class ChecksumTerm:
    """A single additive term of the rotation self-check expression."""

    sign: int
    index: int
    divisor: int
    index2: int | None
    divisor2: int | None


@dataclass(frozen=True)
class Extracted:
    """Everything needed to rebuild the string table."""

    array_fn_name: str
    elements: list[str]
    decoder_name: str
    offset: int
    terms: list[ChecksumTerm]
    magic: int


def _match_balanced_block(src: str, open_index: int) -> str:
    """Return the ``{...}`` block starting at the first ``{`` at/after ``open_index``."""
    start = src.index("{", open_index)
    depth = 0
    for pos in range(start, len(src)):
        if src[pos] == "{":
            depth += 1
        elif src[pos] == "}":
            depth -= 1
            if depth == 0:
                return src[start:pos + 1]
    raise ValueError("unbalanced braces while extracting block")


def _find_string_array(src: str) -> tuple[str, list[str]]:
    header = re.search(r"function (_0x[0-9a-f]+)\(\)\s*\{\s*const _0x[0-9a-f]+\s*=\s*\[", src)
    if not header:
        raise ValueError("could not locate string-array function")
    name = header.group(1)
    lbracket = src.index("[", header.start())
    rbracket = src.index("];", lbracket)
    return name, parse_string_array(src[lbracket + 1:rbracket])


def _find_decoder(src: str) -> tuple[str, int]:
    # The decoder reassigns itself: `function NAME(a,b){const t=ARR();return NAME=function...`
    name_match = re.search(
        r"function (_0x[0-9a-f]+)\([^)]*\)\s*\{\s*const \w+\s*=\s*_0x[0-9a-f]+\(\)\s*;\s*"
        r"return \1\s*=\s*function",
        src,
    )
    # Inside it the index is normalised as `x = x - OFFSET`.
    offset_match = re.search(r"(\w+)\s*=\s*\1\s*-\s*(0x[0-9a-f]+)", src)
    if not name_match or not offset_match:
        raise ValueError("could not locate decoder function / offset")
    return name_match.group(1), int(offset_match.group(2), 16)


def _find_rotation(src: str, array_fn_name: str) -> tuple[list[ChecksumTerm], int]:
    tail = re.search(rf"\}}\(\s*{re.escape(array_fn_name)}\s*,\s*(0x[0-9a-f]+)\s*\)\s*\)", src)
    if not tail:
        raise ValueError("could not locate rotation IIFE / magic constant")
    magic = int(tail.group(1), 16)

    # The checksum expression lives shortly before the magic tail.
    window = src[max(0, tail.start() - 4000):tail.start()]
    terms: list[ChecksumTerm] = []
    for sign_str, idx, div, idx2, div2 in _TERM.findall(window):
        terms.append(
            ChecksumTerm(
                sign=-1 if sign_str.count("-") % 2 else 1,
                index=int(idx, 16),
                divisor=int(div, 16),
                index2=int(idx2, 16) if idx2 else None,
                divisor2=int(div2, 16) if div2 else None,
            )
        )
    if not terms:
        raise ValueError("could not parse rotation checksum expression")
    return terms, magic


def extract(src: str) -> Extracted:
    """Pull out the array, decoder offset and rotation checksum from ``src``."""
    array_fn_name, elements = _find_string_array(src)
    decoder_name, offset = _find_decoder(src)
    terms, magic = _find_rotation(src, array_fn_name)
    return Extracted(
        array_fn_name=array_fn_name,
        elements=elements,
        decoder_name=decoder_name,
        offset=offset,
        terms=terms,
        magic=magic,
    )
