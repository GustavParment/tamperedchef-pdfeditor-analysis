"""Rewrite a protected script into a readable form using the decoded string table.

Two passes:

1. **Substitution** — replace ``decoder(0x..)`` calls (and all aliases of the decoder)
   with the real string literals, and rewrite ``obj["name"]`` as ``obj.name``.
2. **Renaming** *(best effort)* — original variable names are destroyed by the
   obfuscator and cannot be recovered; we give meaningful names where the surrounding
   code makes the intent obvious, and collapse the rest to ``v1, v2, …``.
"""
from __future__ import annotations

import json
import re

from .decoder import StringTable, build_string_table
from .extraction import extract

_HEX_ID = re.compile(r"_0x[0-9a-f]+")
_IDENT = re.compile(r"\b[A-Za-z_$][\w$]*\b")
_MEMBER_STR = re.compile(r'\[("([A-Za-z_$][\w$]*)")\]')


def _collect_aliases(src: str, decoder_name: str) -> set[str]:
    """Return the decoder name plus every identifier transitively aliased to it."""
    aliases = {decoder_name}
    assignments = re.findall(r"(_0x[0-9a-f]+)\s*=\s*(_0x[0-9a-f]+)\b", src)
    changed = True
    while changed:
        changed = False
        for target, source in assignments:
            if source in aliases and target not in aliases:
                aliases.add(target)
                changed = True
    return aliases


def substitute_strings(src: str, table: StringTable, decoder_name: str) -> str:
    """Replace decoder calls with their decoded strings and simplify member access."""
    mapping = table.as_mapping()
    aliases = _collect_aliases(src, decoder_name)
    call = re.compile(
        r"(?:" + "|".join(re.escape(a) for a in sorted(aliases, key=len, reverse=True)) + r")"
        r"\((0x[0-9a-f]+)\)"
    )

    def replace_call(match: re.Match[str]) -> str:
        index = int(match.group(1), 16)
        if index in mapping:
            return json.dumps(mapping[index], ensure_ascii=False)
        return match.group(0)

    src = call.sub(replace_call, src)
    return _MEMBER_STR.sub(lambda m: "." + m.group(2), src)


def _guess_names(src: str) -> dict[str, str]:
    """Best-effort semantic names derived from how identifiers are used."""
    names: dict[str, str] = {}

    def first(pattern: str, name: str) -> None:
        match = re.search(pattern, src)
        if match:
            names.setdefault(match.group(1), name)

    first(r"(\w+)\s*=\s*\w+\(\s*[\"'][^\"']*Utilityaddon\.node[\"']\s*\)", "addon")
    first(r"(\w+)\s*=\s*app\.commandLine\.getSwitchValue\('cm'\)", "mode")
    first(r"(\w+)\s*=\s*app\.commandLine\.getSwitchValue\('c'\)", "argC")
    first(r"(\w+)\s*=\s*__dirname\b", "dirName")
    # Every catch binding can safely share the name (each catch is its own scope).
    for match in re.finditer(r"catch\s*\((\w+)\)", src):
        names[match.group(1)] = "err"
    return names


def rename_variables(src: str) -> str:
    """Apply best-effort names, then collapse remaining ``_0x…`` ids to ``v1, v2, …``."""
    names = _guess_names(src)
    counter = 0
    for token in _HEX_ID.findall(src):
        if token not in names:
            counter += 1
            names[token] = f"v{counter}"
    return _IDENT.sub(lambda m: names.get(m.group(0), m.group(0)), src)


def deobfuscate(src: str, *, rename: bool = True) -> str:
    """Return a readable version of ``src``.

    Set ``rename=False`` to keep the original (``_0x…``) variable names and only
    substitute the decoded strings.
    """
    decoder_name = extract(src).decoder_name
    table = build_string_table(src)
    out = substitute_strings(src, table, decoder_name)
    return rename_variables(out) if rename else out
