#!/usr/bin/env python3
"""Decrypt a Tuya LAN discovery broadcast (UDP port 6667).

Tuya devices broadcast a small encrypted JSON blob every few seconds to announce
themselves on the LAN. Protocol v3.1–v3.4 encrypt it with AES-ECB under a *well-known*
global default key (``md5("yGAdlopoPVldABfn")``), so the announcement can be read by
anyone on the segment. This decodes that blob for inventory/triage.

Examples
--------
    python tuya_discovery.py 000055aa0000...        # hex payload on the command line
    python tuya_discovery.py -f packet.hex          # hex payload from a file
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # pragma: no cover
    sys.exit("this tool needs 'cryptography' — pip install -r requirements.txt")

# Tuya's publicly documented global discovery key (not a secret).
_UDP_KEY = hashlib.md5(b"yGAdlopoPVldABfn").digest()

_PREFIX = 0x000055AA            # frame magic
_HEADER_LEN = 20               # prefix(4) seq(4) cmd(4) size(4) + retcode(4)
_SUFFIX_LEN = 8                # crc(4) + suffix(4)


def _strip_frame(frame: bytes) -> bytes:
    """Return the AES-ECB ciphertext body from a Tuya discovery frame."""
    if int.from_bytes(frame[:4], "big") != _PREFIX:
        raise ValueError("not a Tuya frame (bad 0x000055aa prefix)")
    body = frame[_HEADER_LEN:-_SUFFIX_LEN]
    # The body must be a whole number of AES blocks; trim any stray trailing bytes.
    return body[: len(body) - (len(body) % 16)]


def decrypt_discovery(frame: bytes) -> dict:
    """Decrypt a discovery frame and parse its JSON payload."""
    body = _strip_frame(frame)
    decryptor = Cipher(algorithms.AES(_UDP_KEY), modes.ECB()).decryptor()
    plaintext = decryptor.update(body) + decryptor.finalize()
    pad = plaintext[-1]
    if 0 < pad <= 16:  # strip PKCS#7 padding if present
        plaintext = plaintext[:-pad]
    return json.loads(plaintext.decode("utf-8", "replace"))


def _load_hex(args: argparse.Namespace) -> bytes:
    raw = Path(args.file).read_text() if args.file else args.payload
    return bytes.fromhex("".join(raw.split()))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("payload", nargs="?", help="discovery payload as a hex string")
    group.add_argument("-f", "--file", help="read the hex payload from a file")
    args = parser.parse_args(argv)

    try:
        info = decrypt_discovery(_load_hex(args))
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(info, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
