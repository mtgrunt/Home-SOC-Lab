# 01 · Install the Wazuh Server (Ubuntu)

The Wazuh server is the core of the lab: the manager, indexer, and dashboard that every other component reports to. Install it first. This guide uses the official **all-in-one** installer on a single Ubuntu host.

> Tested against Wazuh 4.x on Ubuntu 22.04 / 24.04 LTS; this lab runs Wazuh 4.9.2 on Ubuntu 26.04.1 LTS. Run everything on the Ubuntu machine unless a step says otherwise.

---

## 0. Before you start

**Check the hardware.** The all-in-one install (indexer + manager + dashboard on one box) needs real resources:

| Resource | Minimum | Comfortable |
| -------- | ------- | ----------- |
| CPU      | 4 cores | 8 cores     |
| RAM      | 8 GB    | 16 GB       |
| Disk     | 50 GB   | 100 GB+     |

```bash
nproc                 # CPU cores
free -h               # RAM (look at the "Mem" total)
df -h /               # free disk on the root filesystem
lsb_release -a        # confirm Ubuntu version
```

**Dedicate the host.** The installer sets up its own indexer and dashboard and expects a clean machine. Don't run it on a box already serving other things.

**Network note.** Earlier we saw the Windows endpoint on a managed UniFi network with separate VLANs. If this Ubuntu machine shares that network, confirm that running a SIEM and later simulating attacks is within policy. The clean approach is a lab on its own network/VLAN where you control the rules.

**Get current first:**
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl        # the installer is fetched with curl
```

Note the server's IP; you'll use it to reach the dashboard:
```bash
hostname -I | awk '{print $1}'
```

---

## 1. Download the installer

```bash
cd ~
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.9/config.yml   # optional, only for multi-node
```

Quick look before running it (good habit with any piped installer):
```bash
less wazuh-install.sh        # q to quit
```

---

## 2. Run the all-in-one install

```bash
sudo bash ./wazuh-install.sh -a
```

- `-a` = all-in-one: indexer, manager, and dashboard on this host.
- It takes roughly 10–15 minutes and is verbose; that's normal.
- Add `-i` to ignore the hardware check **only** if you understand you're under the recommended specs (expect it to run slowly).

When it finishes it prints something like:

```
INFO: --- Summary ---
INFO: You can access the web interface https://<SERVER_IP>
      User: admin
      Password: <GENERATED_PASSWORD>
INFO: Installation finished.
```

**Copy that password now.** If you miss it, recover it with:
```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

---

## 3. Verify the services are healthy

```bash
sudo systemctl status wazuh-manager   --no-pager
sudo systemctl status wazuh-indexer   --no-pager
sudo systemctl status wazuh-dashboard --no-pager
```
All three should read **active (running)**.

Confirm the indexer answers (replace the password):
```bash
curl -sk -u admin:<PASSWORD> https://localhost:9200 | head
```
A JSON block with `"cluster_name" : "wazuh-cluster"` means the indexer is up.

Ports that should be listening:
```bash
sudo ss -tlnp | grep -E '1514|1515|9200|443'
```
| Port | Service   | Purpose            |
| ---- | --------- | ------------------ |
| 443  | dashboard | web UI             |
| 1514 | manager   | agent event stream |
| 1515 | manager   | agent enrollment   |
| 9200 | indexer   | search/storage API |

---

## 4. Log in to the dashboard

From a browser **on the Windows PC**, go to:

```
https://<SERVER_IP>
```

- Accept the self-signed certificate warning (expected; it's a lab cert).
- Log in with `admin` and the generated password.
- You should land on the Wazuh overview with **0 agents** so far; that's correct, you add the endpoint in guide 04.

If the page won't load, open the firewall for the dashboard:
```bash
sudo ufw allow 443/tcp
sudo ufw allow 1514/tcp
sudo ufw allow 1515/tcp
```

---

## 5. Secure it a little (recommended)

Change the default `admin` password to something you control:
```bash
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh \
  --change-all --admin-user admin --admin-password '<CURRENT_PASSWORD>'
```
This rotates the internal passwords and prints the new ones. Store them in your password manager, not in the repo.

---

## Troubleshooting

| Symptom                                  | Likely cause                      | Fix                                                                          |
| ---------------------------------------- | --------------------------------- | ---------------------------------------------------------------------------- |
| Installer aborts on a resource check     | Under 4 cores / 8 GB RAM          | Add resources, or re-run with `-i` to override (slow)                        |
| `wazuh-indexer` won't start              | Low RAM / JVM can't allocate heap | `free -h`; give the VM more RAM, then `sudo systemctl restart wazuh-indexer` |
| Dashboard URL times out from Windows     | Firewall blocking 443             | `sudo ufw allow 443/tcp` on the server                                       |
| "Could not find install files" on re-run | A previous partial install        | Clean up: `sudo bash ./wazuh-install.sh --uninstall` then re-run `-a`        |
| Forgot the admin password                | Not saved at the end              | Extract it from `wazuh-install-files.tar` (see step 2)                       |
| Browser blocks the self-signed cert      | Expected in a lab                 | Click through the warning, or import the cert into the browser               |

---

## Done / Next

You now have a running Wazuh manager, indexer, and dashboard, reachable at `https://<SERVER_IP>` with **0 agents**.

**Record for the README:** server IP, Ubuntu version, and the specs you gave the host (fills the architecture table in the main [README](../README.md)).

**Next:** [`02-windows-logging.md`](02-windows-logging.md) — turn on the Windows audit policies that give Wazuh something worth collecting.
