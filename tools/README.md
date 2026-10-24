# Analysis tools

Small, self-contained tools used during the case study. They are **generic** security
helpers — they contain no malware and operate on files you provide as input.

> **Safety:** the deobfuscator never *executes* its input. The obfuscator.io string
> decoder and array rotation are reimplemented statically in Python, so analysing a
> malicious script cannot run it.

## Contents

```
tools/
├── deobfuscate.py          # CLI: statically deobfuscate an obfuscator.io-protected JS file
├── tuya_discovery.py       # CLI: decrypt a Tuya LAN discovery (UDP/6667) broadcast
└── obfuscatorio/           # library behind deobfuscate.py
    ├── jsutils.py          # JS string-array parsing + JS-compatible parseInt
    ├── extraction.py       # locate the string array, decoder, and rotation IIFE
    ├── decoder.py          # solve the rotation and decode indices → strings
    └── transform.py        # substitute decoded strings + best-effort variable renaming
```

## Usage

Deobfuscate a protected script (produces a readable copy; input is never executed):

```bash
python tools/deobfuscate.py suspicious.js -o suspicious.decoded.js
python tools/deobfuscate.py suspicious.js --dump-table strings.json   # just the string table
python tools/deobfuscate.py suspicious.js -o out.js --no-rename       # keep original var names
```

Decrypt a Tuya discovery packet (payload as a hex string or a file of hex):

```bash
python tools/tuya_discovery.py 000055aa0000...        # hex on the command line
python tools/tuya_discovery.py -f packet.hex          # hex from a file
```

## Requirements

- Python 3.10+
- `tuya_discovery.py` needs `cryptography` (`pip install -r tools/requirements.txt`).
- The deobfuscator is standard library only.

## How the deobfuscator works

1. **Extraction** — locate the string-array function, the decoder function
   (`decode(i) = array[i - OFFSET]`), and the rotation IIFE.
2. **Rotation** — the array is rotated at load time until an internal checksum matches a
   magic constant. The tool finds the correct rotation by replaying that checksum over
   every rotation (pure arithmetic, no code execution).
3. **Decode table** — build `index → original string`.
4. **Substitution** — replace every `decoder(0x..)` call (and its aliases) with the real
   string, and rewrite `obj["name"]` as `obj.name`.
5. **Renaming** *(best effort)* — give meaningful names where context allows and collapse
   the remaining `_0x…` identifiers to `v1, v2, …`. Original variable names are destroyed
   by the obfuscator and cannot be recovered.
