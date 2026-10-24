# Incident Log — Network Analysis, Remote Triage, and Trojan Discovery

**Date:** 2026-10-24
**Context:** Owner-authorized security work on a personal home network.
**Analyst host:** Parrot OS laptop (`<analyst-host>`, Wi-Fi adapter).
**Target host:** Windows desktop `<HOST>` (`<target-host>`), account `<DOMAIN>\<user>`.

> Personal/network identifiers (usernames, hostnames, IP/MAC addresses, IoT device
> secrets) are redacted. Malware IOCs are kept intact.

This document records, chronologically, everything done from the first packet capture to
the final deobfuscation of the trojan.

---

## 1. Network capture (Wireshark / tshark)

Goal: "spin up Wireshark and look at the traffic."

- `dumpcap` is restricted to root / the `wireshark` group; the user account lacked rights
  and `sudo` required a password.
- Workaround: the capture was run manually and written via stdout to avoid the permission
  issue:
  ```
  sudo tshark -i <wifi-iface> -a duration:30 -w - > capture.pcapng
  ```
- Result: ~251 packets in ~30 s, ~0.8 kB/s. Quiet network.

### What the capture showed
| Peer | Meaning |
|------|---------|
| Anthropic endpoint :443 | Claude Code to its API — the only real TLS payload |
| Google Cloud :443 | keep-alive from the `claude` process, no payload |
| 13× UDP/123 to NTP servers | `ntpsec` time sync |
| Router `<router>` | LLDP/STP/ARP/RA — normal |
| `<iot-device>` broadcast UDP/6667 (`0x000055aa`) | Tuya smart device (below) |
| `<target-host>`, mDNS `_dosvc` | Windows host (Delivery Optimization) |

All TCP flows belonged to Claude Code. Nothing suspicious at the network layer.

---

## 2. The Tuya device `<iot-device>`

- MAC vendor prefix → **Tuya Smart**.
- The discovery packet (UDP/6667, every 5 s) was decrypted with Tuya's well-known default
  key (AES-ECB). It contained device id / product key / protocol `version 3.4` (values
  redacted).
- Full TCP scan: only **6668/tcp open** (Tuya's local control protocol). Small attack
  surface.
- Conclusion: an ordinary Tuya / Smart Life device, **not isolated** on a guest network —
  same subnet, directly reachable. Recommendation: move it to an isolated IoT/guest VLAN.

---

## 3. SSH access to the Windows host

Purpose: search the Windows machine for the programs **Paragon** and **HFSExplorer**.
Remote access was set up.

### Steps and problems solved
1. **Key generated** on the analyst host (ed25519).
2. **OpenSSH Server installed** on Windows. `Add-WindowsCapability` failed with
   `0x800f0950` (Windows Update error) → installed instead via
   `winget install Microsoft.OpenSSH.Preview`.
3. **Firewall**: inbound TCP/22 rule restricted to the analyst host's IP only.
4. **Login was repeatedly refused:**
   - `OpenSSH/Operational` log showed "Invalid user …" → the correct local account name
     differed from the first guess.
   - Port 22 was "filtered" despite a correct rule → the network profile was classified
     as **Public**, which blocks inbound. Fix:
     `Set-NetConnectionProfile -NetworkCategory Private`.
5. **Result:** key-based SSH worked; the session had administrator rights.

### Changes made on Windows (be aware)
- OpenSSH Server installed, set to start automatically.
- Inbound firewall rule for TCP/22 from the analyst host.
- Public key added to `administrators_authorized_keys` and the user's `authorized_keys`.
- Network profile changed Public → Private.

---

## 4. Search for Paragon / HFSExplorer

- **Neither Paragon nor HFSExplorer** was installed.
- Found instead **MacDrive 12** (OWC), a legitimate, WHQL-signed product for reading Mac
  disks (HFS+/APFS) on Windows:
  - Boot-start drivers `MDAPFS.sys`, `MDHFS.sys` (Start=0).
  - Services `MacDrive12Service`, `OWCFSEventsService`.
- Assessment: benign, though boot-start filesystem drivers can in theory contribute to
  boot/sleep issues.

---

## 5. Security sweep → trojan found

A broader sweep followed (Defender status, autostart, scheduled tasks, processes, network,
hosts file).

### Findings
- **Windows Defender had flagged a trojan:**
  ```
  Trojan:Win64/TamperedChef.Z!MTB
  C:\Users\<user>\PDFEditor\resources\elevate.exe   (quarantined 2026-10-16)
  ```
- The whole folder **`C:\Users\<user>\PDFEditor\`** was a fake "PDF Editor by AppSuite"
  built in **Electron** — a classic **TamperedChef / AppSuite info-stealer**.
- Separate PUP/adware: **SweetLabs "Host App Service" / "App Explorer"** (Pokki), present
  since 2024, signed, harmless but unwanted.
- No active persistence remained (no PDFEditor scheduled tasks, no Run keys, clean hosts
  file). Autostart was knocked out when Defender quarantined `elevate.exe`.

### Defender quarantine contained three files
```
Trojan:Win32/InfoStealer!MSR   PDFEditorSetup.exe   (2026-07-26)
Trojan:Win64/TamperedChef.Z    elevate.exe          (2026-10-16)
Trojan:JS/InfoStealer!MSR      pdfeditor.js         (2026-10-24, taken on read)
```

---

## 6. Malware analysis

- `package.json`: name "PDF Editor", author **AppSuite <devsupport@appsuites.ai>**,
  dependencies `better-sqlite3` + `node-fetch`.
- `preload.js`: obfuscated Electron bridge (`contextBridge` → `ipcRenderer.send('main', …)`).
- `pdfeditor.js` (the orchestrator) was restored from quarantine for analysis:
  1. An isolated folder was created, a **Defender exclusion** was added (by the user, in
     an elevated PowerShell), and the file was restored there with `MpCmdRun.exe -Restore`.
  2. Copied to the analyst host (`scp`) — unchanged, 189,942 bytes.
- **Deobfuscation** (obfuscator.io):
  - 767-element rotated string array; decoder `array[index - 0x134]`; rotated until a
    checksum = `0x6780c` (correct rotation = 352).
  - The decoder was **reimplemented in Python** (no malicious code executed). 3,566 calls
    were replaced with their real strings; variables were renamed heuristically.
- **Native engine `Utilityaddon.node`** (325 kB) was string-analysed: `CryptUnprotectData`
  (DPAPI), `RegSetValueExW`, `WriteFile`, exported `get_sid`.

See [`malware-architecture.md`](malware-architecture.md) for the full breakdown and the
IOC list.

---

## 7. Status at end of analysis

- Defender had quarantined `elevate.exe`, `PDFEditorSetup.exe`, `pdfeditor.js`.
- No active autostart/persistence found.
- **Remaining to clean:** the `PDFEditor` folder, the restored analysis copy, and the
  Defender exclusion — see [`remediation.md`](remediation.md).
