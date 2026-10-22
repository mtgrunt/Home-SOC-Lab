# 03 · Install Sysmon and Forward It to Wazuh

Native Windows logs say *that* something happened. **Sysmon** (System Monitor, from Microsoft Sysinternals) records the detail a SOC analyst needs: process trees with hashes and parent processes, network connections, file and registry changes, DNS queries, and access to sensitive processes like LSASS. This guide installs it with the community-standard **SwiftOnSecurity** config and tells the Wazuh agent to forward its log.

> Run on the **Windows 11 endpoint** in **PowerShell as Administrator**. Assumes the Wazuh agent is already installed and connected (agent `win-endpoint`).

---

## 1. Install Sysmon

```powershell
New-Item -ItemType Directory -Force C:\Tools\Sysmon | Out-Null
Set-Location C:\Tools\Sysmon

# Sysmon from Microsoft
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath . -Force

# SwiftOnSecurity config: what Sysmon records and what it filters out as noise
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml

# Install as a service with that config
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Expected tail of the output:
```
Configuration file validated.
Sysmon64 installed.
SysmonDrv installed.
SysmonDrv started.
Sysmon64 started.
```

A copy of the config used in this lab is kept at [`configs/sysmonconfig.xml`](../configs/sysmonconfig.xml).

---

## 2. Forward the Sysmon log with the Wazuh agent

The agent collects Application, Security, and System by default, but not Sysmon. Add the channel to its config and restart it:

```powershell
$conf = "${env:ProgramFiles(x86)}\ossec-agent\ossec.conf"
Copy-Item $conf "$conf.bak" -Force     # backup first

Add-Content $conf @"

<ossec_config>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
"@

Restart-Service WazuhSvc
```

> Wazuh accepts multiple `<ossec_config>` blocks in one file, so appending a new block is safe and leaves the default config untouched. The closing `"@` must start at column 0.

---

## 3. Verify

```powershell
Get-Service Sysmon64, WazuhSvc                       # both Running

# Agent picked up the channel
Get-Content "${env:ProgramFiles(x86)}\ossec-agent\ossec.log" -Tail 50 |
  Select-String 'Sysmon|Connected to'
```
Expect:
```
INFO: (1951): Analyzing event log: 'Microsoft-Windows-Sysmon/Operational'.
INFO: (4102): Connected to the server ([<SERVER_IP>]:1514/tcp).
```

Sysmon is writing events locally (admin):
```powershell
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5
```

In the Wazuh dashboard, **Threat intelligence → Threat Hunting**, filter on:
```
data.win.system.channel:"Microsoft-Windows-Sysmon/Operational"
```

> Many routine Sysmon events match level-0 rules and don't become alerts, so the dashboard shows far fewer Sysmon entries than the local log. That's normal. Suspicious activity (e.g. LSASS access, encoded PowerShell) triggers built-in Sysmon rules, and the lab adds custom rules in [`rules/`](../rules/).

---

## Key Sysmon event IDs

| ID | Event                       | Lab use                         |
| -- | --------------------------- | ------------------------------- |
| 1  | Process create              | Encoded PowerShell, persistence |
| 3  | Network connection          | C2 / lateral movement           |
| 10 | Process access              | LSASS credential dumping (see note) |
| 11 | File create                 | Dropped payloads                |
| 13 | Registry value set          | Run-key persistence             |
| 22 | DNS query                   | Suspicious domains              |

> **Event 10 is disabled in the stock SwiftOnSecurity config** (it can be high-volume). This lab turns it on for `lsass.exe` only, excluding the legitimate system accessors — see the `LSASS access` rule groups in [`configs/sysmonconfig.xml`](../configs/sysmonconfig.xml) and [Scenario 3](../scenarios/03-lsass-credential-dumping.md). After editing the config, re-apply it (see Maintenance).

---

## Maintenance

```powershell
# Apply an updated config without reinstalling
C:\Tools\Sysmon\Sysmon64.exe -c C:\Tools\Sysmon\sysmonconfig.xml

# Show the config currently loaded
C:\Tools\Sysmon\Sysmon64.exe -c

# Uninstall
C:\Tools\Sysmon\Sysmon64.exe -u
```

---

## Troubleshooting

| Symptom                                          | Likely cause                         | Fix                                                                          |
| ------------------------------------------------ | ------------------------------------ | ---------------------------------------------------------------------------- |
| `Sysmon64.exe` access denied                     | Shell isn't elevated                 | Reopen PowerShell with **Run as administrator**                              |
| Config fails to validate                         | Corrupt / partial download           | Re-download `sysmonconfig.xml`, check it opens as XML                        |
| No `Analyzing event log: ...Sysmon` in agent log | Step 2 not applied, or no restart    | Check `ossec.conf` contains the Sysmon `<localfile>`; `Restart-Service WazuhSvc` |
| Agent won't start after editing `ossec.conf`     | Broken XML (e.g. indented `"@`)      | Restore: `Copy-Item "$conf.bak" $conf -Force`, then redo step 2              |
| Sysmon events locally but none in the dashboard  | Only level-0 rules matched (normal)  | Generate suspicious activity or add custom rules                             |

---

## Done / Next

Sysmon is recording detailed endpoint activity, and the Wazuh agent is forwarding the Sysmon log alongside Security, System, and Application.

**Next:** [`04-wazuh-agent.md`](04-wazuh-agent.md) covers the agent install and network path (already done if you followed this lab's order), then the [detection scenarios](../README.md#detection-scenarios).
