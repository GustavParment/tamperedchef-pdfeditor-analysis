#!/usr/bin/env python3
"""Statically deobfuscate an obfuscator.io-protected JavaScript file.

The input script is parsed as text and **never executed**: the string decoder and the
array rotation are reimplemented in Python, so analysing a malicious file is safe.

Examples
--------
    python deobfuscate.py suspicious.js -o suspicious.decoded.js
    python deobfuscate.py suspicious.js --dump-table strings.json
    python deobfuscate.py suspicious.js -o out.js --no-rename
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from obfuscatorio import build_string_table
from obfuscatorio.transform import deobfuscate


def _read_source(path: Path) -> str:
    # latin-1 never fails and preserves bytes 1:1, which suits minified/obfuscated input.
    return path.read_text(encoding="latin-1")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", type=Path, help="obfuscated .js file to analyse")
    parser.add_argument("-o", "--output", type=Path, help="write the readable script here")
    parser.add_argument("--dump-table", type=Path, metavar="FILE",
                        help="write the decoded {index: string} table as JSON and exit")
    parser.add_argument("--no-rename", action="store_true",
                        help="keep original _0x… variable names (strings only)")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress the summary")
    args = parser.parse_args(argv)

    if not args.input.is_file():
        parser.error(f"no such file: {args.input}")

    source = _read_source(args.input)

    try:
        table = build_string_table(source)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.dump_table:
        args.dump_table.write_text(
            json.dumps(table.as_mapping(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        if not args.quiet:
            print(f"wrote {len(table.elements)} strings to {args.dump_table}", file=sys.stderr)
        return 0

    result = deobfuscate(source, rename=not args.no_rename)

    if args.output:
        args.output.write_text(result, encoding="utf-8")
        destination = str(args.output)
    else:
        sys.stdout.write(result)
        destination = "stdout"

    if not args.quiet:
        print(
            f"decoded {len(table.elements)} strings "
            f"(rotation {table.rotation}, offset {hex(table.offset)}) -> {destination}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
