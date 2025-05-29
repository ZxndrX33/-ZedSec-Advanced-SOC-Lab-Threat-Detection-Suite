# 🛡️ ZedSec Advanced SOC Lab & Threat Detection Suite

> **Version**: 1.0
> **Base OS**: Arch Linux Host + Windows 10 x86 VM
> **Focus**: SOC, SIEM, Threat Detection, Incident Response, Malware Analysis

---

## 📦 Table of Contents
1. [Overview](#overview)
2. [Hardware & Virtualization Requirements](#hardware--virtualization-requirements)
3. [Base OS Configuration (Arch Linux)](#base-os-configuration-arch-linux)
4. [VM Deployment (Windows 10 x86)](#vm-deployment-windows-10-x86)
5. [SOC Core Stack: ELK + Wazuh + Suricata](#soc-core-stack-elk--wazuh--suricata)
6. [Security Monitoring Toolchain](#security-monitoring-toolchain)
7. [Threat Detection & SIEM Rules](#threat-detection--siem-rules)
8. [Incident Response Toolkit](#incident-response-toolkit)
9. [Network & Host Threat Emulation](#network--host-threat-emulation)
10. [Persistence, Logging & Alerting Strategy](#persistence-logging--alerting-strategy)
11. [Scripts & Automation](#scripts--automation)

---

## 🧠 Overview
This SOC lab is designed for:
- Hands-on cyber defense training
- Real-world incident simulation
- Advanced threat emulation and detection
- Logging, analysis, and automated response workflows

All setups are containerized or virtualized, and fully auditable.

---

## 🖥️ Hardware & Virtualization Requirements
- **CPU**: Quad-Core or better (with VT-x/AMD-V)
- **RAM**: 16GB+ (recommended)
- **Storage**: 100GB+ SSD
- **Hypervisor**: VirtualBox or VMware Workstation

---

## 🧰 Base OS Configuration (Arch Linux)

### Install Core Packages
```bash
sudo pacman -Syu --noconfirm
sudo pacman -S virtualbox virtualbox-host-modules-arch dkms \
                 python python-pip docker docker-compose wireshark-qt \
                 suricata nmap git base-devel neovim
```

### Enable Services
```bash
sudo systemctl enable vboxservice docker
sudo usermod -aG vboxusers,docker $USER
```

---

## 🪟 VM Deployment (Windows 10 x86)
1. Download a 32-bit Windows 10 ISO
2. Create a VirtualBox VM with Host-Only Adapter
3. Disable Defender, Firewall
4. Install:
   - Sysmon + Sysmon config (SwiftOnSecurity)
   - Winlogbeat
   - OSQuery
   - EventLog Forwarding via NXLog

---

## 📊 SOC Core Stack: ELK + Wazuh + Suricata

### Install Wazuh Stack (Dockerized)
```bash
git clone https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker
sudo docker-compose -f generate-indexer-certs.yml run --rm generator
sudo docker-compose up -d
```

### Configure Suricata
```bash
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak
sudo vi /etc/suricata/suricata.yaml
# Set default interface: eth0 or vboxnet0
```

### Enable Suricata to log to Elasticsearch
```bash
sudo ln -s /var/log/suricata/eve.json /opt/wazuh/logs/suricata.json
```

---

## 🔭 Security Monitoring Toolchain
| Tool         | Purpose                        |
|--------------|---------------------------------|
| Wireshark    | Deep Packet Inspection         |
| Suricata     | IDS/IPS                        |
| Wazuh        | Agent-based host monitoring    |
| Sysmon       | Event logging on Windows       |
| OSQuery      | Host state queries             |
| Zeek         | Network Security Monitor       |
| TheHive      | Incident Response Management   |
| Cortex       | Observable Analysis Automation |

---

## 🔥 Threat Detection & SIEM Rules
- Sigma Rules → Wazuh custom detection
- MITRE ATT&CK Mapping
- YARA Rules for malware file detection

### Sample Sigma Integration
```yaml
logsource:
  product: windows
  service: security
  category: process_creation
rule:
  detection:
    selection:
      CommandLine|contains: 'rundll32'
    condition: selection
```

---

## 🛠 Incident Response Toolkit
| Tool          | Function                       |
|---------------|--------------------------------|
| Velociraptor  | Endpoint triage                |
| KAPE          | Forensic artifact acquisition  |
| Autopsy       | GUI forensic tool              |
| CyberChef     | Decode/analyze payloads        |
| Loki          | IOC scanner (YARA/SIGMA)       |

---

## 💣 Network & Host Threat Emulation

### Emulation Tools
- Caldera (MITRE ATT&CK automated)
- Atomic Red Team
- Red Team Automation Scripts (PowerShell, Python)

---

## 🗃️ Persistence, Logging & Alerting Strategy
- Enable Wazuh File Integrity Monitoring (FIM)
- Enable anomaly detection with Suricata + Zeek
- Use Wazuh active response for real-time alert blocking
- Centralize logs using Filebeat, Winlogbeat

---

## 🔁 Scripts & Automation

### Log Cleanup + Snapshot
```bash
#!/bin/bash
rm -rf /var/log/suricata/*
sudo docker restart wazuh.manager
vboxmanage snapshot win10 take "PostIncident"
```

### Auto VM Reset
```bash
VBoxManage snapshot win10 restore "Clean"
VBoxManage startvm win10 --type headless
```

### Install Script (Full Stack)
```bash
curl -s https://raw.githubusercontent.com/ZedSec/scripts/soc-lab-init.sh | bash
```

---

## 🔚 Final Notes
This lab architecture follows ZedSec’s operational doctrine: **Controlled Chaos with Measurable Insight**. Red meets Blue. Arch meets Windows. Detection meets Deception.

Deploy, emulate, adapt, escalate. Welcome to the BlackCell.

> **"Logs are your eyes. Responses are your fists." — ZedSec BlackCell Doctrine**
