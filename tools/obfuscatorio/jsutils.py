"""Small JavaScript-compatible helpers used during deobfuscation.

Nothing in here executes JavaScript; it only parses text and mimics a couple of JS
semantics (``parseInt`` and string-literal escapes) in pure Python.
"""
from __future__ import annotations

import re

_LEADING_INT = re.compile(r"\s*[+-]?\d+")

# Standard single-character escapes understood by a JS string literal.
_SIMPLE_ESCAPES = {
    "n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f",
    "v": "\v", "0": "\0", "'": "'", '"': '"', "\\": "\\", "/": "/",
}


def js_parse_int(value: str) -> int | None:
    """Replicate ``parseInt(value, 10)`` for the leading-number case.

    Returns the parsed integer, or ``None`` where JavaScript would yield ``NaN``
    (i.e. the string does not start with an optional sign followed by digits).
    """
    match = _LEADING_INT.match(value)
    return int(match.group()) if match else None


def decode_js_escapes(raw: str) -> str:
    """Decode the escape sequences allowed inside a JS string literal.

    Handles ``\\xHH``, ``\\uHHHH`` and the common single-character escapes. Unknown
    escapes fall back to the literal character, matching JS behaviour closely enough
    for analysis.
    """
    out: list[str] = []
    i = 0
    n = len(raw)
    while i < n:
        ch = raw[i]
        if ch != "\\" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        nxt = raw[i + 1]
        if nxt == "x" and i + 3 < n + 1:
            out.append(chr(int(raw[i + 2:i + 4], 16)))
            i += 4
        elif nxt == "u" and raw[i + 2:i + 3] == "{":
            end = raw.index("}", i + 3)
            out.append(chr(int(raw[i + 3:end], 16)))
            i = end + 1
        elif nxt == "u":
            out.append(chr(int(raw[i + 2:i + 6], 16)))
            i += 6
        else:
            out.append(_SIMPLE_ESCAPES.get(nxt, nxt))
            i += 2
    return "".join(out)


def parse_string_array(array_body: str) -> list[str]:
    """Parse the comma-separated quoted elements of a JS array literal body.

    ``array_body`` is the text between ``[`` and ``]``. Supports single- and
    double-quoted elements with escape sequences; non-string elements are ignored.
    """
    elements: list[str] = []
    i = 0
    n = len(array_body)
    while i < n:
        ch = array_body[i]
        if ch in "'\"":
            quote = ch
            j = i + 1
            buf: list[str] = []
            while j < n:
                c = array_body[j]
                if c == "\\":
                    buf.append(array_body[j:j + 2])
                    j += 2
                    continue
                if c == quote:
                    break
                buf.append(c)
                j += 1
            elements.append(decode_js_escapes("".join(buf)))
            i = j + 1
        else:
            i += 1
    return elements
