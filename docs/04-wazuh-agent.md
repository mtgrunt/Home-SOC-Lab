# 04 · Enroll the Windows Endpoint (Wazuh Agent)

The Wazuh agent runs on the Windows endpoint and ships its event logs to the manager. This guide covers the network path between the two machines, installing the agent from the dashboard's deploy wizard, and confirming it's connected.

> In this lab the agent was installed **right after guide 01**, before logging and Sysmon. The order doesn't matter: the agent forwards whatever channels are enabled, and guides 02 and 03 add to them.

---

## 1. Make sure the endpoint can reach the manager

The agent needs two TCP ports on the Wazuh server:

| Port | Purpose          |
| ---- | ---------------- |
| 1514 | Event stream     |
| 1515 | Enrollment (key) |

(Plus 443 for the dashboard and 22 for SSH, if you manage the server from the Windows PC.)

From the Windows endpoint:
```powershell
foreach ($p in 22,443,1514,1515) {
  "{0,-5} {1}" -f $p, (Test-NetConnection <SERVER_IP> -Port $p -InformationLevel Quiet)
}
```
All four should print `True`.

### If everything times out: separate VLANs

In this lab the endpoint and server sit on **different UniFi VLANs**, and inter-VLAN traffic was blocked: every port, and even ping, failed. With `ufw` inactive on the server, ping failing pointed at the network, not the host.

The fix was a UniFi **zone-based firewall policy** (Settings → Security → Firewall / Policy Engine → **Create Policy**):

| Field            | Value                                          |
| ---------------- | ---------------------------------------------- |
| Name             | `SOC Lab - Win to Wazuh`                       |
| Action           | **Allow**                                      |
| Source           | Zone **Internal** → Specific → IP `<WINDOWS_IP>` |
| Destination      | Zone **Internal** → Specific → IP `<SERVER_IP>`  |
| Port             | **List** (port group): `22, 443, 1514, 1515`   |
| Protocol         | TCP                                            |
| IP version       | IPv4                                           |
| Connection state | All                                            |
| Schedule         | Always                                         |
| Match Opposite   | Off                                            |

Gotchas met along the way:
- **Destination zone must be Internal**, not External (External = the internet).
- **Port → Specific** only takes one port; use **List** for several.
- If the rule exists but traffic still fails, check **Isolate Network** on each VLAN and that no Block rule sits above it.

If the server's `ufw` is active, also allow the ports there:
```bash
sudo ufw allow 1514/tcp && sudo ufw allow 1515/tcp
```

---

## 2. Get the install command from the dashboard

1. Open `https://<SERVER_IP>` and log in as `admin`.
2. ☰ menu → **Server management → Endpoints Summary → Deploy new agent**
   (with 0 agents, the Overview page also shows a **Deploy new agent** link).
3. Choose **Windows → MSI 32/64 bits**.
4. **Server address:** `<SERVER_IP>`
5. **Agent name:** `win-endpoint`
6. **Group:** `default`
7. Copy the generated PowerShell command.

The wizard pins the agent version to the manager's (here **4.9.2**). An agent newer than the manager won't connect, which is why the wizard is safer than a hand-written URL.

---

## 3. Install and start the agent

Open **PowerShell as Administrator** (title bar starts with "Administrator:"; PowerShell 7 or Windows PowerShell both work) and paste the command. It looks like:

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='<SERVER_IP>' WAZUH_AGENT_NAME='win-endpoint'
```

`msiexec` returns before it finishes, so wait ~30 seconds, then:
```powershell
NET START WazuhSvc
```
Expect: `The Wazuh service was started successfully.`

---

## 4. Verify

On the endpoint:
```powershell
Get-Service WazuhSvc                     # Running, StartType Automatic
Get-Content "${env:ProgramFiles(x86)}\ossec-agent\ossec.log" -Tail 40 |
  Select-String 'Valid key|Connected to|ERROR'
```
Expect:
```
INFO: Requesting a key from server: <SERVER_IP>
INFO: Valid key received
INFO: (4102): Connected to the server ([<SERVER_IP>]:1514/tcp).
```

In the dashboard: **Server management → Endpoints Summary** shows **1 agent**, `win-endpoint` **Active**.

On the server (optional, over SSH):
```bash
sudo /var/ossec/bin/manage_agents -l
```

**End-to-end test** (after guide 02): `runas /user:fakeuser cmd` with a wrong password produces an **"Authentication failure"** alert (Event 4625) under **Threat intelligence → Threat Hunting** within a minute.

---

## Troubleshooting

| Symptom                                   | Likely cause                          | Fix                                                                 |
| ----------------------------------------- | ------------------------------------- | ------------------------------------------------------------------- |
| `Test-NetConnection` all `False`, ping fails | Network blocks inter-VLAN traffic  | Add the firewall policy in step 1                                   |
| 1514/1515 `False` but ping works          | Host firewall on the server           | `sudo ufw allow 1514/tcp && sudo ufw allow 1515/tcp`                |
| Installer does nothing / access denied    | Shell isn't elevated                  | Reopen PowerShell with **Run as administrator**                     |
| Agent shows **Never connected**           | Service not started, or wrong manager IP | `NET START WazuhSvc`; check `WAZUH_MANAGER` in `ossec.conf`      |
| `Invalid agent name` / duplicate name     | Name already registered               | Pick a new name, or remove the old agent in the dashboard           |
| Agent version error in the log            | Agent newer than manager              | Reinstall using the dashboard wizard's command                      |
| Can't find **Agents** in the menu         | Renamed in Wazuh 4.9                  | It's **Server management → Endpoints Summary**                      |

---

## Done / Next

`win-endpoint` is enrolled and Active, forwarding the Application, Security, System, and (after guide 03) Sysmon channels.

**Next:** the [detection scenarios](../README.md#detection-scenarios). Microsoft Sentinel (`05-sentinel.md`, planned) adds an optional second SIEM in Azure.
