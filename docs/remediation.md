# Remediation & Countermeasures — Windows Host

**Date:** 2026-10-24
**Goal:** fully remove the TamperedChef/AppSuite trojan, restore protection, and contain
the damage from stolen credentials.

> **Do this first, no matter what:**
> Because this is an info-stealer, **change passwords for all important accounts from a
> DIFFERENT, clean device** (a phone or a trusted computer) and **enable MFA**. Sign out
> of all sessions. See section 5.

---

## 0. Current state (what remains)

- Defender quarantined `elevate.exe`, `PDFEditorSetup.exe`, `pdfeditor.js`.
- **No active persistence** was found (no scheduled tasks, no Run keys).
- Remaining on disk:
  - `C:\Users\<user>\PDFEditor\` (~346 files, incl. `Utilityaddon.node`)
  - `C:\Users\<user>\_analys\pdfeditor.js` (restored analysis copy — live)
  - **Defender exclusion** for the analysis folder (weakens protection — must be removed)
- Separate: SweetLabs "Host App Service" / "App Explorer" (PUP, optional to remove).

---

## 1. Strategy

Two tiers — choose based on how sensitive the data on the machine was.

- **A. Clean and keep the install** (lower effort). Removes known malware and persistence.
  Reasonable if only browser passwords were at stake and you rotate them.
- **B. Reinstall Windows from scratch** (safest). Because the trojan is a **loader** that
  may have pulled additional unknown payloads, a cleaned machine can never be guaranteed
  100% clean. Recommended if the machine is used for banking, work, crypto, or anything
  sensitive.

Tier **A** is detailed below, followed by verification. Tier **B** is summarized in
section 6.

---

## 2. Removal (tier A) — run in an elevated PowerShell on the host

> Run as administrator. Lines can be run one by one.

### 2.1 Kill any running process
```powershell
Get-Process | Where-Object { $_.Path -like "*\PDFEditor\*" } | Stop-Process -Force -ErrorAction SilentlyContinue
```

### 2.2 Remove persistence (in case it returned)
```powershell
schtasks /Delete /TN "PDFEditorScheduledTask"  /F 2>$null
schtasks /Delete /TN "PDFEditorUScheduledTask" /F 2>$null
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'PDFEditorUpdater' -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'PDFEditorUpdater' -ErrorAction SilentlyContinue
```

### 2.3 Delete the malware
```powershell
Remove-Item 'C:\Users\<user>\PDFEditor' -Recurse -Force -ErrorAction SilentlyContinue
```

### 2.4 Delete the analysis copy and RESTORE Defender protection
```powershell
Remove-Item 'C:\Users\<user>\_analys' -Recurse -Force -ErrorAction SilentlyContinue
Remove-MpPreference -ExclusionPath 'C:\Users\<user>\_analys'
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath   # must NOT list _analys anymore
```

### 2.5 Clear Defender quarantine (optional — after everything else)
```powershell
$mp = (Get-ChildItem 'C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe' | Select-Object -Last 1).FullName
& $mp -Restore -ListAll          # review what's there
# & $mp -Restore -All -Delete    # (if supported) or just leave it — harmless in quarantine
```

### 2.6 Full antivirus scan
```powershell
Start-MpScan -ScanType FullScan
Get-MpThreatDetection | Sort-Object InitialDetectionTime | Select-Object -Last 10
```
Also run an **offline scan** (Microsoft Defender Offline) or a second opinion (e.g.
Malwarebytes).

---

## 3. Remove the PUP (SweetLabs Pokki) — optional
```powershell
schtasks /Delete /TN "App Explorer" /F 2>$null
& "$env:LOCALAPPDATA\Host App Service\Uninstall.exe"   # run its uninstaller
# if missing / fails:
Remove-Item "$env:LOCALAPPDATA\Host App Service" -Recurse -Force -ErrorAction SilentlyContinue
```

---

## 4. Verification (is the machine clean?)

Run and confirm everything is empty/gone:
```powershell
Test-Path 'C:\Users\<user>\PDFEditor'                        # should be False
Get-ScheduledTask | Where-Object TaskName -match 'PDFEditor' # should be empty
Get-ItemProperty 'HKCU:\...\Run','HKLM:\...\Run' | Select PDFEditorUpdater  # should be absent
Get-MpPreference | Select -Expand ExclusionPath              # _analys should be gone
Get-NetTCPConnection -State Established | ? RemoteAddress -notmatch '^(127|192\.168|::1|fe80)'
```
Also confirm nothing is beaconing to `appsuites.ai`.

---

## 5. Contain the damage from stolen data (do this from a clean device)

The trojan targeted browser passwords, cookies and card data. Assume exposure since the
install date (2026-07-26).

1. **Change passwords** for: email (first!), Google/Microsoft account, bank, social media,
   Steam/Discord/Riot, and anything saved in the browser.
2. **Enable MFA** everywhere possible.
3. **Sign out of all sessions** ("log out of all devices") — stolen cookies bypass
   passwords.
4. **Clear the browser's saved passwords and cookies** on the host after cleanup; consider
   resetting the browser profile.
5. **Watch** bank/card activity and account logins for a while. Freeze/replace cards that
   were saved.
6. If crypto wallets were used on the machine: move funds to new wallets with new keys.

---

## 6. Tier B — reinstall Windows (recommended for sensitive use)

1. Back up **documents/pictures only** (no programs, no `.exe`) to external media.
2. Reinstall Windows cleanly ("remove everything").
3. Change all passwords (section 5) **before** signing in with accounts on the fresh
   install.
4. Install software only from official sources. Never download "PDF editors" or free tools
   from search ads / unknown sites — that's how TamperedChef got in.

---

## 7. Cleanup on the analysis host & revert remote access

When finished:

- Analysis files include a live (but non-runnable on Linux) `pdfeditor.js` and
  `Utilityaddon.node`. Delete if you don't want to keep them (keep the `.md` docs if you
  like).
- If SSH to the host is no longer needed, disable it on Windows:
  ```powershell
  Stop-Service sshd; Set-Service sshd -StartupType Disabled
  Remove-NetFirewallRule -Name OpenSSH-Server-In-TCP
  ```
- The network profile was set to **Private** during troubleshooting — leave as-is
  (correct for a home network) or adjust.

---

## 8. Prevention going forward

- Put IoT devices on an isolated guest/IoT VLAN.
- Keep Windows Defender and real-time protection on (it did catch the core components).
- Download software only from the vendor's own site; avoid search ads.
- Prefer a password manager with MFA over the browser's saved passwords.

---

## Quick checklist

- [ ] Change passwords + MFA from a clean device (section 5) ← **first**
- [ ] Kill process, remove persistence (2.1–2.2)
- [ ] Delete `PDFEditor` + `_analys`, remove Defender exclusion (2.3–2.4)
- [ ] Full Defender scan (2.6)
- [ ] (Optional) remove Pokki (3)
- [ ] Verify clean (4)
- [ ] Consider reinstall for sensitive use (6)
- [ ] Clean up analysis host / disable SSH (7)
