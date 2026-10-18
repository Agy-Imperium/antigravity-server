# Quickstart Guide: Antigravity Zero-Privilege Bypass & Auto-Patcher

Get up and running with Antigravity and `agy-cli` in 1 minute without administrator or root rights.

---

## Recommended: Interactive Console Manager (`antigravity-ui`)

Launch the English terminal dashboard:

### Linux & macOS:
```bash
./antigravity-ui
```

### Windows (Command Prompt or PowerShell):
```cmd
antigravity-ui.cmd
```
or in PowerShell:
```powershell
.\antigravity-ui.ps1
```

### In the UI:
1. Select **`[1] One-Click Auto-Unlock`**
2. Everything is configured automatically:
   - Starts the background bypass forwarder.
   - Installs the transparent CLI hook for `agy`.
   - Patches Antigravity IDE `settings.json` (`jetski.cloudCodeUrl`).
   - Configures user auto-start.
3. **Done!** You can now simply type `agy` anywhere without thinking!

---

## Non-Interactive One-Line Auto-Patch

To unlock everything silently in a single command:

### Linux / macOS:
```bash
python3 client/antigravity_ui.py --auto-patch
agy -p "Hello from Antigravity!"
```

### Windows (PowerShell):
```powershell
python .\client\antigravity_ui.py --auto-patch
agy -p "Hello from Antigravity!"
```

---

## Clean Revert / Rollback

To restore everything to its clean original state at any time:
```bash
./antigravity-ui --revert
```
or select **`[7] Restore & Clean Rollback`** inside the console UI.

---

## Verification & Diagnostics

Run self-test diagnostics directly from the menu (`[6] Run Connection Diagnostics`) or via CLI:
```bash
./antigravity-ui --diagnose
```
All green checkmarks indicate the bypass tunnel is healthy and ready for development.
