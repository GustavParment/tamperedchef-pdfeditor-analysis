# TamperedChef / "AppSuite PDF Editor" — Malware Analysis Case Study

A hands-on write-up of a real incident: starting from routine network inspection on a
home LAN, following the thread onto a Windows host, and ending with the discovery,
reverse-engineering and remediation of a **TamperedChef / AppSuite info-stealer** that
was disguised as a free *"PDF Editor"*.

This repository documents **methodology and findings** — not a malware sample.

---

## ⚠️ Disclaimer — for educational purposes only

This project is published **strictly for educational and defensive-security purposes**.

- All work was performed by the device owner, on **their own equipment and network**, with full authorization.
- **No malware samples, binaries, or runnable malicious code are included** in this
  repository. The actual trojan source (`pdfeditor.js`), the native engine
  (`Utilityaddon.node`) and related artefacts are deliberately excluded via `.gitignore`
  and must never be redistributed.
- Code excerpts in the documentation are **short, non-functional fragments** shown only
  to explain how the threat works, following standard malware-analysis write-up practice.
- Personal and network-identifying details (usernames, hostnames, IP/MAC addresses,
  device secrets) have been redacted.
- Nothing here is intended to enable wrongdoing. Do not attempt to run, rebuild or
  distribute the analysed malware. If you find similar software on your machine, treat it
  as a live threat and follow the remediation guide.

Use this material to learn how such threats are triaged, analysed and removed — nothing else.

---

## What's in here

| Document | Contents |
|----------|----------|
| [`docs/incident-log.md`](docs/incident-log.md) | Full chronological account: network capture → host triage → malware discovery → deobfuscation. |
| [`docs/malware-architecture.md`](docs/malware-architecture.md) | How the threat is built: the three layers, command modes, persistence, and the credential-theft chain. |
| [`docs/remediation.md`](docs/remediation.md) | How to remove it, restore protection, and contain the damage from stolen credentials. |

## TL;DR of the case

- A fake **"PDF Editor by AppSuite"** (Electron app) turned out to be the **TamperedChef**
  info-stealer family.
- Architecture: a benign-looking Electron **facade**, an obfuscated JavaScript
  **orchestrator**, and a compiled native **engine** (`Utilityaddon.node`) that does the
  actual theft.
- Capabilities: browser credential/cookie/card theft via Windows DPAPI
  (`CryptUnprotectData`), process recon, and persistence via scheduled tasks + a Run key.
  It is also a **loader** — it beacons to its C2 and can pull further payloads.
- Microsoft Defender had quarantined the core components; remaining files were removed and
  the machine was cleaned following the remediation guide.

## Key indicators of compromise (IOCs)

| Type | Value |
|------|-------|
| Facade / C2 domain | `pdf-tool.appsuites.ai` (sender `appsuites.ai`) |
| User-Agent | `PDFFusion/93HEU7AJ` |
| Install folder | `C:\Users\<user>\PDFEditor\` |
| Native engine | `...\resources\app\w-electron\bin\release\lib\Utilityaddon.node` |
| Scheduled tasks | `PDFEditorScheduledTask`, `PDFEditorUScheduledTask` |
| Run value | `PDFEditorUpdater` |
| Data file | `<installdir>\mode.data` |
| Detections | `Trojan:Win64/TamperedChef.Z!MTB`, `Trojan:JS/InfoStealer!MSR`, `Trojan:Win32/InfoStealer!MSR` |

## Toolchain

Linux (Parrot OS), `tshark`, `nmap`, OpenSSH, and a custom Python deobfuscator for the
obfuscator.io string-array scheme. No malicious code was executed during analysis; the
decoder was reimplemented in Python to recover strings statically.
