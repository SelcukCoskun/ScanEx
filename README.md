# SCANEX — Security Scan & Exploit Analyzer

```
 ███████╗ ██████╗ █████╗ ███╗   ██╗███████╗██╗  ██╗
 ██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝╚██╗██╔╝
 ███████╗██║     ███████║██╔██╗ ██║█████╗   ╚███╔╝
 ╚════██║██║     ██╔══██║██║╚██╗██║██╔══╝   ██╔██╗
 ███████║╚██████╗██║  ██║██║ ╚████║███████╗██╔╝ ██╗
 ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
```

> **Professional offensive network scanner with built-in vulnerability engine and AI-powered analysis.**  
> Built on top of nmap — wrapped in a sleek PyQt6 GUI with deep CVE detection, no API key required.

---

## ⚡ Features

- **Modern dark GUI** — PyQt6, deep-space noir theme, monospace aesthetic
- **Full nmap integration** — 30+ configurable scan parameters via checkboxes
- **Deep Vulnerability Engine** — 45+ offline CVE patterns, no internet needed
- **Metasploitable 2 optimised** — detects all classic vulnerabilities out of the box
- **AI Analysis** — Gemini API for advanced analysis, or fully offline fallback
- **Live output** — real-time nmap stream with syntax highlighting
- **Categorised results** — ports, services, OS, scripts — all in separate tabs
- **Vulnerability cards** — severity-coded cards with CVE, description & fix for each finding
- **Save reports** — export scan results to `.txt` with one click





https://github.com/user-attachments/assets/529c14b4-e84c-4ec5-a50a-d8356938b537




---

## 📸 Interface

```
┌─────────────────────────────────────────────────────────────────────┐
│  SCANEX   Security Scan & Exploit Analyzer · v1.0     [clock]       │
│  [NMAP ENGINE]  [VULN DB v3]  [OFFLINE AI]                          │
├──────────────────────┬──────────────────────────────────────────────┤
│  TARGET              │  ⚡ LIVE OUTPUT │ 📋 CATEGORIES │ 🔴 VULNS  │
│  ┌──────────────┐    │                                              │
│  │ IP / CIDR    │    │  $ nmap -sV -sC --script=vuln ...           │
│  │ Custom ports │    │  Discovered open port 21/tcp ...            │
│  │ Gemini key   │    │  Discovered open port 445/tcp ...           │
│  └──────────────┘    │                                              │
│                      ├──────────────────────────────────────────────┤
│  SCAN OPTIONS        │  💀 CRITICAL  vsftpd 2.3.4 Backdoor         │
│  ☑ Service Versions  │  🔴 HIGH      SMB (445) EternalBlue risk     │
│  ☑ Default Scripts   │  🟡 MEDIUM    MySQL (3306) exposed           │
│  ☑ Vuln Scripts      │  🔵 LOW       Finger service disclosure      │
│  ☑ TCP SYN           │                                              │
│  ☑ T4 — Aggressive   ├──────────────────────────────────────────────┤
│  ☑ Open Only         │  🤖 AI ANALYSIS                             │
│  ...                 │  Offline / Gemini-powered analysis           │
│                      │                                              │
├──────────────────────┴──────────────────────────────────────────────┤
│  [▶ START SCAN]  [■ STOP]  [⟳ CLEAR]  [💾 SAVE]   ████░░  72%    │
└─────────────────────────────────────────────────────────────────────┘
```



---

## 🚀 Installation

### Prerequisites

| Dependency | Install |
|---|---|
| Python 3.8+ | [python.org](https://python.org) |
| nmap | See below |
| PyQt6 | `pip install PyQt6` |
| requests *(optional)* | `pip install requests` |

#### Install nmap

```bash
# Debian / Ubuntu / Kali
sudo apt install nmap

# Windows
# Download installer: https://nmap.org/download.html
# Make sure nmap is added to PATH during installation

# macOS
brew install nmap
```

#### Install Python dependencies

```bash
pip install PyQt6
pip install requests     # only needed for Gemini AI analysis
```

> **Note:** SCANEX will auto-install missing packages on first launch if pip is available.

---

### Run

```bash
python scanex.py
```

On Windows you can also rename to `scanex.pyw` to launch without a terminal window.

---

## 🔧 Usage

### 1. Enter Target

In the **TARGET** panel, fill in:

| Field | Example | Notes |
|---|---|---|
| IP / Host / CIDR | `192.168.1.1` | Single IP |
| | `10.0.0.0/24` | Entire subnet |
| | `scanme.nmap.org` | Domain |
| Custom Ports | `21,22,80,443` | Override checkbox port options |
| | `1-1024` | Port range |
| Gemini API Key | `AIza...` | Optional — leave blank for offline AI |

### 2. Configure Scan Options

Use the checkboxes on the left panel to build your scan. Options are grouped by category:

| Category | Key Options |
|---|---|
| **Discovery** | OS Detection, Service Versions, Default Scripts, Aggressive Mode |
| **Scan Type** | TCP SYN (stealth), TCP Connect, UDP, FIN, Xmas, Null |
| **Speed** | T1 Sneaky → T5 Insane |
| **Ports** | All Ports, Top 100/1000, Well-known 1-1024 |
| **Scripts** | Vuln, Auth, Brute, Safe, SMB Vulns, HTTP |
| **Output** | Verbose, Open Only, Reason, Traceroute |

The **COMMAND PREVIEW** bar shows the exact nmap command that will be executed — in real time as you tick options.

### 3. Start Scan

Click **▶ START SCAN** or press Enter. The right panel switches to **LIVE OUTPUT** and streams nmap results as they come in, colour-coded by type.

### 4. View Results

After the scan completes, results are split across 4 tabs:

| Tab | Contents |
|---|---|
| ⚡ Live Output | Raw nmap stream, colour-coded |
| 📋 Categories | Parsed into Host Info, Open Ports, Services, OS, Scripts, Traceroute |
| 🔴 Vulnerabilities | Severity cards — CRITICAL / HIGH / MEDIUM / LOW |
| 🤖 AI Analysis | Gemini (if key provided) or offline pattern-based summary |

---

## 🛡️ Vulnerability Engine

SCANEX includes a built-in offline vulnerability database with **45+ detection patterns**. No internet connection or API key required.

Each finding shows:
- **Severity** — CRITICAL / HIGH / MEDIUM / LOW
- **Vulnerability name**
- **CVE number** (where applicable)
- **Technical description**
- **Remediation / fix** including Metasploit module paths

### Metasploitable 2 — Full Coverage

SCANEX is specifically tuned to detect all classic Metasploitable 2 vulnerabilities:

| Vulnerability | CVE | Severity | MSF Module |
|---|---|---|---|
| vsftpd 2.3.4 Backdoor | CVE-2011-2523 | 💀 CRITICAL | `exploit/unix/ftp/vsftpd_234_backdoor` |
| Samba usermap_script | CVE-2007-2447 | 💀 CRITICAL | `exploit/multi/samba/usermap_script` |
| UnrealIRCd Backdoor | CVE-2010-2075 | 💀 CRITICAL | `exploit/unix/irc/unreal_ircd_3281_backdoor` |
| distccd RCE | CVE-2004-2687 | 💀 CRITICAL | `exploit/unix/misc/distcc_exec` |
| Java RMI Server | CVE-2011-3556 | 💀 CRITICAL | `exploit/multi/misc/java_rmi_server` |
| PHP CGI Arg Injection | CVE-2012-1823 | 💀 CRITICAL | `exploit/multi/http/php_cgi_arg_injection` |
| Ingreslock Backdoor (1524) | N/A | 💀 CRITICAL | Direct shell |
| Webmin RCE | CVE-2019-15107 | 💀 CRITICAL | `exploit/linux/http/webmin_backdoor` |
| ProFTPD mod_copy | CVE-2015-3306 | 💀 CRITICAL | `exploit/unix/ftp/proftpd_modcopy_exec` |
| EternalBlue (SMB) | CVE-2017-0144 | 💀 CRITICAL | `exploit/windows/smb/ms17_010_eternalblue` |
| Heartbleed | CVE-2014-0160 | 💀 CRITICAL | N/A |
| MySQL No Root Password | N/A | 💀 CRITICAL | `auxiliary/scanner/mysql/mysql_login` |
| Apache Tomcat AJP Ghostcat | CVE-2020-1938 | 💀 CRITICAL | N/A |
| Redis Unauthenticated | CVE-2022-0543 | 💀 CRITICAL | N/A |
| MongoDB No Auth | CVE-2013-4650 | 💀 CRITICAL | N/A |
| R-Services (rlogin/rsh) | CVE-1999-0651 | 💀 CRITICAL | N/A |
| Telnet Open | N/A | 🔴 HIGH | N/A |
| NFS World-Readable | CVE-1999-0170 | 🔴 HIGH | `auxiliary/scanner/nfs/nfsmount` |
| X11 Display Server | CVE-1999-0526 | 🔴 HIGH | N/A |
| PostgreSQL Default Creds | N/A | 🔴 HIGH | `auxiliary/scanner/postgres/postgres_login` |
| RDP Exposed (BlueKeep) | CVE-2019-0708 | 🔴 HIGH | N/A |
| Anonymous FTP Login | CVE-1999-0497 | 🔴 HIGH | N/A |
| SSLv2/v3 POODLE/DROWN | CVE-2014-3566 | 🔴 HIGH | N/A |
| Samba 3/4 SambaCry | CVE-2017-7494 | 🔴 HIGH | `exploit/linux/samba/is_known_pipename` |
| SMTP Open Relay | N/A | 🔴 HIGH | N/A |
| Elasticsearch No Auth | CVE-2014-3120 | 🔴 HIGH | N/A |
| Memcached Exposed | CVE-2018-1000115 | 🔴 HIGH | N/A |
| Tomcat Manager Default Creds | CVE-2009-3843 | 🔴 HIGH | `exploit/multi/http/tomcat_mgr_upload` |
| phpMyAdmin Exposed | CVE-2018-12613 | 🔴 HIGH | N/A |
| Old OpenSSH | CVE-2016-6210 | 🟡 MEDIUM | N/A |
| MySQL (3306) Exposed | N/A | 🟡 MEDIUM | N/A |
| PostgreSQL (5432) Exposed | N/A | 🟡 MEDIUM | N/A |
| TLS 1.0 Deprecated | CVE-2011-3389 | 🟡 MEDIUM | N/A |
| CUPS Print Server | CVE-2015-1158 | 🟡 MEDIUM | N/A |
| Zookeeper Exposed | N/A | 🟡 MEDIUM | N/A |
| FTP Port Open | N/A | 🟡 MEDIUM | N/A |
| Finger Service | CVE-1999-0150 | 🔵 LOW | N/A |

---

## 🤖 AI Analysis

### With Gemini API Key

Get a free key at [aistudio.google.com/apikey](https://aistudio.google.com/apikey).

When a key is provided, SCANEX sends the full nmap output to Gemini 1.5 Flash and returns a structured security report including:

1. Executive summary
2. Critical/High vulnerabilities with CVSS scores
3. Attack chain — step-by-step exploitation path
4. Remediation recommendations, prioritised

### Without API Key (Offline Mode)

SCANEX uses its built-in pattern engine and generates an offline analysis summary including:

- Risk score breakdown (CRITICAL / HIGH / MEDIUM / LOW counts)
- All detected open ports
- Flagged vulnerability descriptions with fix guidance

---

## ⚙️ Recommended Scan Profiles

### Quick Reconnaissance
```
Options: Service Versions ☑  Top 100 Ports ☑  T4 ☑  Open Only ☑
```

### Full Vulnerability Scan (Metasploitable / CTF)
```
Options: Service Versions ☑  Default Scripts ☑  Vuln Scripts ☑  SMB Vulns ☑
         TCP SYN ☑  T4 ☑  All Ports ☑  Open Only ☑
```

### Stealth Scan
```
Options: FIN Scan ☑  T2 Polite ☑  No Ping ☑  Top 1000 Ports ☑
```

### Fast Network Discovery
```
Options: Ping Scan Only ☑  T5 Insane ☑  Fast Mode ☑
```

---

## 🐛 Troubleshooting

### Slow `-sV` scans
Service version detection (`-sV`) sends probes to every open port and waits for banners — this is slow by design when many ports are open.

Speed it up with:
```bash
# In Custom Ports field: only scan what you need
21,22,23,25,80,111,139,445,3306,5432
```
Or lower intensity by adding `--version-intensity 2` to the command (coming in future update).

### nmap not found
- **Windows:** Download from [nmap.org](https://nmap.org/download.html) and ensure it's added to `PATH`
- **Linux/Kali:** `sudo apt install nmap`
- **macOS:** `brew install nmap`

### Permission denied (SYN scan)
TCP SYN scan (`-sS`) requires root/administrator:
```bash
sudo python scanex.py     # Linux / macOS
# Windows: Run terminal as Administrator
```
If root is not available, uncheck **TCP SYN** and check **TCP Connect** (`-sT`) instead.

### Window opens slowly on Windows
Run with:
```bash
py scanex.py
```
Or rename to `scanex.pyw` to skip console allocation.

---

## ⚠️ Legal Disclaimer

> SCANEX is intended for **authorised security testing only**.  
> Always obtain **written permission** before scanning any network or system you do not own.  
> Unauthorised scanning may be illegal under computer crime laws in your jurisdiction.  
> The authors accept no liability for misuse of this tool.

---

## 📁 Project Structure

```
scanex/
├── scanex.py          # Main application — single-file
└── README.md          # This file
```

---

## 🔮 Roadmap

- [ ] Version intensity slider in GUI
- [ ] Export to HTML / PDF report
- [ ] CVE lookup integration (NVD API)
- [ ] Network topology map view
- [ ] Scheduled / automated scans
- [ ] Plugin system for custom vuln patterns
- [ ] Dark / light theme toggle

---

## 🛠️ Built With

| Technology | Purpose |
|---|---|
| [Python 3](https://python.org) | Core language |
| [PyQt6](https://pypi.org/project/PyQt6/) | GUI framework |
| [nmap](https://nmap.org) | Network scanning engine |
| [Gemini 1.5 Flash](https://aistudio.google.com) | AI-powered analysis |
| [requests](https://pypi.org/project/requests/) | HTTP client for Gemini API |

---

<p align="center">
  <b>SCANEX</b> · Security Scan &amp; Exploit Analyzer<br>
  Made for security professionals, CTF players, and red teamers.
</p>
