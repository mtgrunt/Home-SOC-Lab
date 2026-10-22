# 02 · Enable Windows Logging (Windows 11 endpoint)

Out of the box, Windows logs far less than a SOC needs. This guide turns on the audit policies, process command-line capture, and PowerShell Script Block Logging that the lab's detection scenarios depend on. The Wazuh agent then forwards these events to the server.

> Run everything on the **Windows 11 endpoint** in **PowerShell as Administrator** (window title starts with "Administrator:"). Windows PowerShell 5.1 or PowerShell 7 both work.

---

## 1. Apply the settings

Paste the whole block into an elevated PowerShell:

```powershell
# 1. Make Advanced Audit Policy (subcategories) override the legacy categories
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f

# 2. Enable the audit subcategories the scenarios need
$subs = "Credential Validation","Logon","Special Logon","Account Lockout",
        "Process Creation","User Account Management","Security Group Management",
        "Other Object Access Events","Audit Policy Change","Security System Extension"
foreach ($s in $subs) { auditpol /set /subcategory:"$s" /success:enable /failure:enable }
auditpol /set /subcategory:"Logoff" /success:enable

# 3. Include the full command line in process-creation events (4688)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# 4. PowerShell Script Block Logging (4104)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

# 5. Grow the Security log to 500 MB so events aren't overwritten quickly
wevtutil sl Security /ms:524288000
```

Expected output: a series of `The operation completed successfully.` / `The command was successfully executed.` lines and no errors.

> The `auditpol` subcategory names are English. On a non-English Windows install, use the localized names (see `auditpol /list /subcategory:*`).

---

## 2. What each setting gives you

| Setting                                 | Event IDs             | Used for                                     |
| --------------------------------------- | --------------------- | -------------------------------------------- |
| Credential Validation, Logon, Logoff    | 4624, 4625, 4634, 4776 | Brute force (Scenario 1)                     |
| Special Logon                           | 4672                  | Privileged (admin) logons                    |
| Account Lockout                         | 4740                  | Brute-force lockouts                         |
| Process Creation + command line         | 4688                  | What ran, with full arguments (Scenario 2)   |
| User Account / Security Group Management | 4720, 4732           | New local admin (Scenario 4)                 |
| Other Object Access Events              | 4698                  | Scheduled task created (Scenario 5)          |
| Security System Extension               | 4697                  | Service installed                            |
| Audit Policy Change                     | 4719                  | Someone tampering with auditing              |
| Script Block Logging                    | 4104                  | Decoded PowerShell content (Scenario 2)      |

Already logged by default, no change needed: **1102** (Security log cleared, Scenario 6) and **7045** (new service, System log).

> Script Block Logging covers **Windows PowerShell** (`powershell.exe`), which is what most attack tooling uses. PowerShell 7 (`pwsh.exe`) has its own separate policy and log, not enabled here.

---

## 3. Verify

```powershell
# Registry settings: each should print 1
(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).SCENoApplyLegacyAuditPolicy
(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit).ProcessCreationIncludeCmdLine_Enabled
(Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging).EnableScriptBlockLogging

# Audit policy (admin): should read "Success and Failure"
auditpol /get /subcategory:"Process Creation"

# Security log size: maxSize: 524288000
wevtutil gl Security | Select-String maxSize
```

**End-to-end test with Wazuh.** Generate a failed logon on purpose:
```powershell
runas /user:fakeuser cmd     # type any wrong password, press Enter
```
Within a minute, the Wazuh dashboard (**Threat Hunting** / **Discover**, filtered to agent `win-endpoint`) should show an alert for **Event ID 4625** (failed logon).

> Wazuh only stores events that match a rule as alerts. Plenty of 4688 events are level 0 by default and won't appear as alerts; that's expected, and Sysmon (guide 03) plus custom rules fill the gap.

---

## Troubleshooting

| Symptom                                         | Likely cause                       | Fix                                                                       |
| ----------------------------------------------- | ---------------------------------- | ------------------------------------------------------------------------- |
| `Access is denied` / `auditpol` error 0x00000005 | Shell isn't elevated              | Reopen PowerShell with **Run as administrator**                           |
| `auditpol` says the parameter is incorrect      | Non-English subcategory names      | Use names from `auditpol /list /subcategory:*`                            |
| 4688 events have an empty command line          | Registry value missing / typo      | Re-run step 3 of the block, then start a new process                      |
| Settings revert after a while                   | Domain Group Policy overriding     | Not expected on a standalone home PC; check `gpresult /r`                 |
| No 4625 alert in Wazuh                          | Agent not connected                | Check **Server management → Endpoints Summary** shows `win-endpoint` Active |

---

## Done / Next

The endpoint now records logons, process launches with command lines, account and group changes, scheduled tasks, services, and PowerShell script content, and the Wazuh agent forwards them to the server.

**Next:** [`03-sysmon.md`](03-sysmon.md) — install Sysmon for much richer process, network, and file telemetry.
