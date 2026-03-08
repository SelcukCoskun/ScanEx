#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║   SCANEX  ·  Security Scan & Exploit Analyzer  ·  v1.0       ║
║   PyQt6  ·  Deep Vuln Engine  ·  Metasploitable2    ║
╚══════════════════════════════════════════════════════╝
"""
# ── stdlib only at startup — keeps launch instant ──────────────
import sys, subprocess, re
from datetime import datetime

# ── PyQt6: explicit imports (faster than wildcard *) ───────────
try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QFrame, QLabel,
        QPushButton, QLineEdit, QCheckBox, QTextEdit,
        QScrollArea, QSplitter, QTabWidget, QProgressBar,
        QVBoxLayout, QHBoxLayout, QFileDialog,
    )
    from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
    from PyQt6.QtGui  import QColor, QFont, QTextCharFormat, QTextCursor, QPainter, QPixmap, QIcon
except ImportError:
    print("PyQt6 bulunamadı — yükleniyor...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "PyQt6", "-q"])
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QFrame, QLabel,
        QPushButton, QLineEdit, QCheckBox, QTextEdit,
        QScrollArea, QSplitter, QTabWidget, QProgressBar,
        QVBoxLayout, QHBoxLayout, QFileDialog,
    )
    from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
    from PyQt6.QtGui  import QColor, QFont, QTextCharFormat, QTextCursor, QPainter, QPixmap, QIcon

# ── requests: lazy — only imported when Gemini API is used ─────
_requests = None
def _get_requests():
    global _requests
    if _requests is None:
        try:
            import requests as _r
        except ImportError:
            subprocess.check_call([sys.executable,"-m","pip","install","requests","-q"])
            import requests as _r
        _requests = _r
    return _requests

# ─────────────────────────────────────────────────────────────
#  STYLESHEET  — deep-space noir
# ─────────────────────────────────────────────────────────────
QSS = """
* {
    font-family: 'Cascadia Code','JetBrains Mono','Fira Code','Consolas',monospace;
    font-size: 12px;
}
QMainWindow { background: #07090f; }

/* ── panels ── */
#pnl {
    background: #0c1017;
    border: 1px solid #1a2535;
    border-radius: 8px;
}
#pnl_hi {
    background: #0c1017;
    border: 1px solid #00e5ff;
    border-radius: 8px;
}

/* ── header ── */
#hdr {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #050810, stop:0.5 #0c1828, stop:1 #050810);
    border-bottom: 1px solid #00e5ff;
    border-radius: 0px;
}
#logo_scanex {
    color: #00e5ff;
    font-size: 32px;
    font-weight: 900;
    letter-spacing: 10px;
}
#logo_sub {
    color: #1e5f8a;
    font-size: 10px;
    letter-spacing: 5px;
}
#badge {
    background: rgba(0,229,255,0.08);
    border: 1px solid #00e5ff;
    border-radius: 4px;
    color: #00e5ff;
    font-size: 10px;
    letter-spacing: 2px;
    padding: 3px 10px;
}
#clock {
    color: #1e5f8a;
    font-size: 11px;
    letter-spacing: 1px;
}

/* ── section titles ── */
#sec {
    color: #00e5ff;
    font-size: 10px;
    font-weight: bold;
    letter-spacing: 4px;
    padding: 2px 0 6px 0;
    border-bottom: 1px solid #1a2535;
    margin-bottom: 4px;
}

/* ── inputs ── */
QLineEdit {
    background: #070b12;
    border: 1px solid #1a2535;
    border-radius: 5px;
    color: #7de8ff;
    padding: 9px 14px;
    selection-background-color: #00e5ff;
    selection-color: #07090f;
}
QLineEdit:focus {
    border-color: #00e5ff;
    background: #0a1220;
}
QLineEdit[readOnly="true"] { color: #1e5f8a; }

/* ── checkboxes ── */
QCheckBox {
    color: #4a6a8a;
    spacing: 8px;
    padding: 2px 0;
}
QCheckBox:hover { color: #a8c8e8; }
QCheckBox::indicator {
    width: 14px; height: 14px;
    border: 1px solid #1e3a55;
    border-radius: 3px;
    background: #070b12;
}
QCheckBox::indicator:hover  { border-color: #00e5ff; }
QCheckBox::indicator:checked {
    background: #00e5ff;
    border-color: #00e5ff;
    image: none;
}

/* ── category dividers ── */
#cat {
    color: #1e5f8a;
    font-size: 10px;
    letter-spacing: 3px;
    font-weight: bold;
    padding: 8px 0 3px 0;
}

/* ── cmd preview ── */
#cmd_box {
    background: #050810;
    border: 1px solid #0e2a44;
    border-left: 3px solid #00e5ff;
    border-radius: 4px;
    color: #00e5ff;
    font-size: 11px;
    padding: 8px 12px;
}

/* ── buttons ── */
#btn_start {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #004466, stop:1 #002233);
    border: 1px solid #00e5ff;
    border-radius: 6px;
    color: #00e5ff;
    font-size: 13px;
    font-weight: bold;
    letter-spacing: 4px;
    padding: 13px 36px;
    min-width: 160px;
}
#btn_start:hover {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #006699, stop:1 #004466);
    color: #fff;
}
#btn_start:disabled {
    background: #0a1220; border-color: #1a2535; color: #1e3a55;
}
#btn_stop {
    background: rgba(200,30,30,0.15);
    border: 1px solid #8b1a1a;
    border-radius: 6px; color: #ff4455;
    font-weight: bold; letter-spacing: 2px;
    padding: 11px 24px;
}
#btn_stop:hover { background: rgba(200,40,40,0.35); border-color: #cc2233; }
#btn_stop:disabled { color: #3a1a1a; border-color: #2a1515; background: transparent; }
#btn_minor {
    background: transparent;
    border: 1px solid #1a2535;
    border-radius: 6px; color: #2a5a7a;
    letter-spacing: 1px; padding: 10px 18px;
}
#btn_minor:hover { border-color: #00e5ff; color: #7de8ff; }
#btn_save {
    background: rgba(0,120,60,0.15);
    border: 1px solid #005530;
    border-radius: 6px; color: #00cc77;
    letter-spacing: 1px; padding: 10px 18px;
}
#btn_save:hover { background: rgba(0,150,80,0.3); border-color: #00aa55; }

/* ── progress ── */
QProgressBar {
    background: #050810;
    border: 1px solid #1a2535;
    border-radius: 3px;
    max-height: 5px;
    text-align: center; color: transparent;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #003355, stop:0.6 #0088aa, stop:1 #00e5ff);
    border-radius: 3px;
}

/* ── tabs ── */
QTabWidget::pane {
    border: 1px solid #1a2535;
    background: #07090f;
    border-radius: 0 6px 6px 6px;
}
QTabBar::tab {
    background: #0c1017;
    border: 1px solid #1a2535;
    border-bottom: none;
    border-radius: 5px 5px 0 0;
    padding: 7px 20px;
    color: #2a5a7a;
    letter-spacing: 1px;
    margin-right: 2px;
    font-size: 11px;
}
QTabBar::tab:selected { background: #07090f; color: #00e5ff; border-color: #00e5ff; }
QTabBar::tab:hover:!selected { color: #7de8ff; border-color: #1e4a6a; }

/* ── text areas ── */
QTextEdit {
    background: #06080e;
    border: none;
    color: #8aabb8;
    font-size: 12px;
    padding: 10px;
    selection-background-color: #1a3a55;
}

/* ── scrollbars ── */
QScrollBar:vertical   { background:#07090f; width:6px; border:none; }
QScrollBar:horizontal { background:#07090f; height:6px; border:none; }
QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
    background:#1a2535; border-radius:3px; min-height:20px;
}
QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover {
    background:#00e5ff;
}
QScrollBar::add-line, QScrollBar::sub-line { height:0; width:0; }

/* ── status bar ── */
QStatusBar { background:#050810; border-top:1px solid #1a2535; color:#1e5f8a; font-size:11px; }
QStatusBar::item { border: none; }

/* ── splitter ── */
QSplitter::handle { background:#1a2535; }
QSplitter::handle:horizontal { width:2px; }

/* ── scroll area ── */
QScrollArea { border:none; background:transparent; }
QScrollArea > QWidget > QWidget { background:transparent; }

/* ── tooltip ── */
QToolTip {
    background:#0c1828; border:1px solid #00e5ff;
    color:#a8d8f0; padding:5px 9px; font-size:11px;
    border-radius: 4px;
}
"""

# ─────────────────────────────────────────────────────────────
#  SCAN OPTIONS
# ─────────────────────────────────────────────────────────────
OPTS = [
    # label, flag, default, category, tooltip
    ("OS Detection",        "-O",               False,"Discovery","Detect OS via TCP/IP fingerprinting"),
    ("Service Versions",    "-sV",              True, "Discovery","Identify service name and version"),
    ("Default Scripts",     "-sC",              True, "Discovery","Run default NSE scripts"),
    ("Aggressive (-A)",     "-A",               False,"Discovery","OS+version+scripts+traceroute"),
    ("Ping Scan Only",      "-sn",              False,"Discovery","Host discovery only"),
    ("No Ping (-Pn)",       "-Pn",              False,"Discovery","Treat all hosts as online"),
    ("TCP SYN",             "-sS",              True, "Scan Type","Stealth half-open (requires root)"),
    ("TCP Connect",         "-sT",              False,"Scan Type","Full connect (no root needed)"),
    ("UDP Scan",            "-sU",              False,"Scan Type","UDP ports (slow, root needed)"),
    ("FIN Scan",            "-sF",              False,"Scan Type","Stealth FIN scan"),
    ("Xmas Scan",           "-sX",              False,"Scan Type","FIN+PSH+URG flags"),
    ("Null Scan",           "-sN",              False,"Scan Type","No flags set"),
    ("T1 — Sneaky",         "-T1",              False,"Speed","Very slow, evades IDS"),
    ("T2 — Polite",         "-T2",              False,"Speed","Slower, low bandwidth"),
    ("T3 — Normal",         "-T3",              False,"Speed","Default timing"),
    ("T4 — Aggressive",     "-T4",              True, "Speed","Fast, reliable network"),
    ("T5 — Insane",         "-T5",              False,"Speed","Max speed, may miss ports"),
    ("Fast (-F)",           "-F",               False,"Speed","Top 100 ports only"),
    ("All Ports",           "-p-",              False,"Ports","Scan all 65535 ports"),
    ("Top 100",             "--top-ports 100",  False,"Ports","100 most common"),
    ("Top 1000",            "--top-ports 1000", False,"Ports","1000 most common"),
    ("Well-known (1-1024)", "-p 1-1024",        False,"Ports","Ports 1–1024"),
    ("Vuln Scripts",        "--script=vuln",    True, "Scripts","NSE vulnerability detection"),
    ("Auth Scripts",        "--script=auth",    False,"Scripts","Authentication checks"),
    ("Brute Scripts",       "--script=brute",   False,"Scripts","Credential brute force"),
    ("Safe Scripts",        "--script=safe",    False,"Scripts","Non-intrusive scripts"),
    ("SMB Vulns",           "--script=smb-vuln-*",False,"Scripts","EternalBlue, MS08-067 etc."),
    ("HTTP Scripts",        "--script=http-*",  False,"Scripts","HTTP enumeration"),
    ("Verbose",             "-v",               False,"Output","Increase verbosity"),
    ("Open Only",           "--open",           True, "Output","Show only open ports"),
    ("Reason",              "--reason",         False,"Output","Why is port in that state"),
    ("Traceroute",          "--traceroute",     False,"Output","Trace route to host"),
]

# ─────────────────────────────────────────────────────────────
#  VULNERABILITY DATABASE
#  Metasploitable2 specialised + general patterns
# ─────────────────────────────────────────────────────────────
VULNDB = [
    # ── METASPLOITABLE 2 CLASSICS ──────────────────────────────
    ("vsftpd 2.3.4",
     r"vsftpd\s*2\.3\.4",
     "CRITICAL",
     "CVE-2011-2523",
     "vsftpd 2.3.4 contains a deliberate backdoor. Connecting to port 6200 after sending ':)' in username gives root shell.",
     "Immediate: Replace vsftpd with patched version. MSF: exploit/unix/ftp/vsftpd_234_backdoor"),

    ("Samba 3.x usermap_script",
     r"samba\s*3\.[0-4]",
     "CRITICAL",
     "CVE-2007-2447",
     "Samba 3.0.20–3.0.25rc3 allows RCE via shell metacharacters in MS-RPC calls (username field).",
     "Upgrade Samba immediately. MSF: exploit/multi/samba/usermap_script"),

    ("UnrealIRCd Backdoor",
     r"unreal\s*ircd|unrealircd\s*3\.2\.8\.1",
     "CRITICAL",
     "CVE-2010-2075",
     "UnrealIRCd 3.2.8.1 shipped with a backdoor in the DEBUG3_DOLOG_SYSTEM function allowing RCE.",
     "Replace immediately. MSF: exploit/unix/irc/unreal_ircd_3281_backdoor"),

    ("Distcc RCE",
     r"distcc.*v1|distccd",
     "CRITICAL",
     "CVE-2004-2687",
     "distccd allows unauthenticated remote code execution by abusing the compile job mechanism.",
     "Disable distccd or restrict to localhost. MSF: exploit/unix/misc/distcc_exec"),

    ("Ingreslock Backdoor (port 1524)",
     r"1524/tcp\s+open|ingreslock",
     "CRITICAL",
     "N/A",
     "Port 1524 (ingreslock) is open — classic Metasploitable backdoor giving direct root shell.",
     "Block port 1524 at firewall. Reinstall if compromised."),

    ("IRC Backdoor (port 6667)",
     r"6667/tcp\s+open",
     "HIGH",
     "N/A",
     "Port 6667 open with UnrealIRCd — likely backdoored. See CVE-2010-2075.",
     "Remove UnrealIRCd. MSF: exploit/unix/irc/unreal_ircd_3281_backdoor"),

    ("Bindshell (port 1099/rmiregistry)",
     r"1099/tcp\s+open|rmiregistry",
     "CRITICAL",
     "CVE-2011-3556",
     "Java RMI registry on port 1099 — vulnerable to remote class loading and RCE.",
     "Disable RMI registry or restrict to localhost. MSF: exploit/multi/misc/java_rmi_server"),

    ("Java RMI Server",
     r"java.*rmi|rmi.*registry",
     "CRITICAL",
     "CVE-2011-3556",
     "Java RMI service allows remote class loading leading to arbitrary code execution.",
     "Disable Java RMI or apply security manager. MSF: exploit/multi/misc/java_rmi_server"),

    ("Apache Tomcat AJP (Ghostcat)",
     r"ajp.*13|8009/tcp\s+open",
     "CRITICAL",
     "CVE-2020-1938",
     "AJP connector on port 8009 enables Ghostcat attack — read arbitrary webapp files or RCE.",
     "Disable AJP connector in server.xml or restrict to localhost."),

    ("Apache Tomcat Manager",
     r"tomcat.*manager|/manager/html",
     "HIGH",
     "CVE-2009-3843",
     "Tomcat Manager exposed — default credentials (tomcat/tomcat) may allow WAR upload → RCE.",
     "Remove Manager app or use strong credentials. MSF: exploit/multi/http/tomcat_mgr_upload"),

    ("PHP CGI Argument Injection",
     r"php.*cgi|5\.3\.[0-9]|5\.4\.[0-3]",
     "CRITICAL",
     "CVE-2012-1823",
     "PHP CGI before 5.3.12/5.4.2 allows argument injection via query string, enabling RCE.",
     "Upgrade PHP. MSF: exploit/multi/http/php_cgi_arg_injection"),

    ("MySQL No Root Password",
     r"mysql.*3306|3306/tcp\s+open",
     "CRITICAL",
     "N/A (Misconfiguration)",
     "MySQL on Metasploitable2 has root account with no password. Full DB compromise likely.",
     "Set root password: mysqladmin -u root password 'STRONG_PASS'"),

    ("PostgreSQL Default Credentials",
     r"postgresql|5432/tcp\s+open",
     "HIGH",
     "N/A (Misconfiguration)",
     "PostgreSQL running — default credentials (postgres/postgres) may be active.",
     "Change default credentials and restrict pg_hba.conf access."),

    ("NFS World-Readable Export",
     r"nfs|111/tcp\s+open|rpcbind|2049/tcp\s+open",
     "HIGH",
     "CVE-1999-0170",
     "NFS/RPC services exposed. World-readable exports may allow mounting filesystem without auth.",
     "Restrict NFS exports in /etc/exports. MSF: auxiliary/scanner/nfs/nfsmount"),

    ("Samba Writeable Share",
     r"445/tcp\s+open|139/tcp\s+open",
     "HIGH",
     "N/A",
     "SMB/Samba shares exposed. Metasploitable2 often has world-writable shares.",
     "Restrict smb.conf shares. Check: smbclient -L //target -N"),

    ("Telnet (Plaintext)",
     r"23/tcp\s+open|telnet",
     "HIGH",
     "N/A (Design flaw)",
     "Telnet transmits all data including credentials in cleartext. MITM trivial.",
     "Replace Telnet with SSH immediately."),

    ("FTP Anonymous Login",
     r"anonymous\s+ftp|ftp.*anonymous|220.*ftp",
     "HIGH",
     "CVE-1999-0497",
     "FTP server allows anonymous login — unauthenticated read/write access to files.",
     "Disable anonymous FTP in vsftpd.conf: anonymous_enable=NO"),

    ("FTP (Port 21 open)",
     r"21/tcp\s+open",
     "MEDIUM",
     "N/A",
     "FTP service running — cleartext protocol. Check for anonymous access and weak credentials.",
     "Switch to SFTP/SCP. If FTP required, enforce TLS (FTPS)."),

    ("OpenSSH Old Version",
     r"openssh[\s_]([1-5]\.[0-9]|6\.[0-6])",
     "MEDIUM",
     "CVE-2016-6210",
     "Old OpenSSH version detected — vulnerable to user enumeration and possibly memory bugs.",
     "Upgrade to latest OpenSSH (9.x+)."),

    ("Apache httpd Old Version",
     r"apache.*(1\.[0-9]|2\.[0-3])\.",
     "HIGH",
     "Multiple",
     "Apache version EOL — multiple unpatched RCE, DoS, and info-disclosure CVEs.",
     "Upgrade Apache to 2.4.x latest."),

    ("Apache 2.2.x",
     r"apache.*2\.2\.",
     "MEDIUM",
     "CVE-2017-7679",
     "Apache 2.2.x — mod_mime buffer overread, several moderate CVEs.",
     "Upgrade to Apache 2.4.x."),

    ("Samba 4.x SambaCry",
     r"samba\s*4\.[0-7]\.",
     "HIGH",
     "CVE-2017-7494",
     "SambaCry — writable share + Samba 3.5.0–4.6.4 allows RCE via malicious shared library.",
     "Upgrade Samba. MSF: exploit/linux/samba/is_known_pipename"),

    ("Redis Unauthenticated",
     r"6379/tcp\s+open",
     "CRITICAL",
     "CVE-2022-0543",
     "Redis exposed with no authentication. Attackers can read/write data, achieve RCE via config.",
     "Enable requirepass in redis.conf and bind to 127.0.0.1."),

    ("MongoDB No Auth",
     r"27017/tcp\s+open",
     "CRITICAL",
     "CVE-2013-4650",
     "MongoDB exposed without authentication — full database read/write access.",
     "Enable MongoDB auth and bind to localhost."),

    ("Elasticsearch No Auth",
     r"9200/tcp\s+open",
     "HIGH",
     "CVE-2014-3120",
     "Elasticsearch exposed — no auth by default, allows data extraction and RCE via Groovy.",
     "Enable X-Pack security or shield plugin. Bind to localhost."),

    ("RDP Exposed",
     r"3389/tcp\s+open|ms-wbt-server",
     "HIGH",
     "CVE-2019-0708",
     "RDP exposed — BlueKeep (CVE-2019-0708) and DejaBlue risk. Brute force common.",
     "Restrict RDP access via VPN/firewall. Patch and enable NLA."),

    ("EternalBlue / MS17-010",
     r"ms17-010|eternalblue|smb.*vuln",
     "CRITICAL",
     "CVE-2017-0144",
     "EternalBlue SMB exploit detected! Allows unauthenticated RCE with SYSTEM privileges.",
     "Apply MS17-010 patch immediately. MSF: exploit/windows/smb/ms17_010_eternalblue"),

    ("Heartbleed OpenSSL",
     r"heartbleed|ssl.*heartbleed",
     "CRITICAL",
     "CVE-2014-0160",
     "Heartbleed — OpenSSL memory disclosure leaks private keys, passwords, session tokens.",
     "Upgrade OpenSSL to 1.0.1g+. Revoke and reissue all certificates."),

    ("SSLv2/SSLv3 POODLE/DROWN",
     r"sslv[23]|ssl.*v[23]",
     "HIGH",
     "CVE-2014-3566",
     "SSLv2/v3 enabled — POODLE (SSLv3) and DROWN (SSLv2) attacks allow decryption of HTTPS.",
     "Disable SSLv2/v3 in OpenSSL config. Enable TLS 1.2+ only."),

    ("TLS 1.0 Deprecated",
     r"tls\s*1\.0",
     "MEDIUM",
     "CVE-2011-3389",
     "TLS 1.0 enabled — BEAST attack and various cipher weaknesses.",
     "Disable TLS 1.0, require TLS 1.2 minimum."),

    ("Memcached Exposed",
     r"11211/tcp\s+open",
     "HIGH",
     "CVE-2018-1000115",
     "Memcached exposed — DDoS amplification factor 50,000x. No auth by default.",
     "Bind to localhost. Never expose Memcached to internet."),

    ("Zookeeper Exposed",
     r"2181/tcp\s+open",
     "MEDIUM",
     "N/A",
     "Zookeeper service exposed — no authentication by default, configuration data readable.",
     "Restrict Zookeeper to internal network only."),

    ("CUPS Print Server",
     r"631/tcp\s+open|ipp",
     "MEDIUM",
     "CVE-2015-1158",
     "CUPS exposed — several RCE vulnerabilities in older versions.",
     "Upgrade CUPS and restrict to localhost."),

    ("X11 Display Server",
     r"6000/tcp\s+open|X11",
     "HIGH",
     "CVE-1999-0526",
     "X11 exposed — allows remote desktop capture and keystroke injection without auth.",
     "Disable X11 TCP listening: X -nolisten tcp"),

    ("R Services (rlogin/rsh/rexec)",
     r"512/tcp|513/tcp|514/tcp|rlogin|rexecd|rsh",
     "CRITICAL",
     "CVE-1999-0651",
     "BSD r-services running — trust-based auth allows unauthenticated login if .rhosts configured.",
     "Disable rlogin/rsh/rexec. Use SSH instead."),

    ("Finger Service",
     r"79/tcp\s+open|finger",
     "LOW",
     "CVE-1999-0150",
     "Finger service reveals usernames and login information — info disclosure.",
     "Disable finger service: remove from /etc/inetd.conf"),

    ("SMTP Open Relay",
     r"smtp.*open\s+relay|relaying\s+allowed",
     "HIGH",
     "N/A",
     "SMTP open relay detected — server can be used to send spam/phishing from any source.",
     "Configure SMTP to reject relaying for non-local domains."),

    ("IRC Service (6667)",
     r"6667/tcp\s+open|ircd",
     "MEDIUM",
     "N/A",
     "IRC service detected — may indicate backdoored IRCd (see UnrealIRCd CVE-2010-2075).",
     "Verify IRCd version. Remove if not needed."),

    ("Bindshell (port 1524)",
     r"1524/tcp\s+open",
     "CRITICAL",
     "N/A",
     "Port 1524 open — Metasploitable root bindshell. Direct root shell access.",
     "Block port 1524. System is fully compromised."),

    ("Drupal RCE (Drupalgeddon)",
     r"drupal",
     "CRITICAL",
     "CVE-2018-7600",
     "Drupal detected — Drupalgeddon2 allows unauthenticated RCE via Form API.",
     "Update Drupal to latest. MSF: exploit/unix/webapp/drupal_drupalgeddon2"),

    ("WordPress Vulnerable",
     r"wordpress|wp-login|wp-content",
     "MEDIUM",
     "Multiple",
     "WordPress detected — check version, plugins, and admin credentials.",
     "Update WordPress core and all plugins. Use WPScan for audit."),

    ("phpMyAdmin Exposed",
     r"phpmyadmin",
     "HIGH",
     "CVE-2018-12613",
     "phpMyAdmin exposed — LFI vulnerability and brute-forceable login.",
     "Restrict phpMyAdmin to localhost or VPN only."),

    ("Default/Weak HTTP Credentials",
     r"default credentials|login.*admin.*admin|tomcat.*tomcat",
     "CRITICAL",
     "N/A",
     "Default credentials detected on web service — immediate admin access.",
     "Change all default passwords before deployment."),

    ("Webmin Vulnerability",
     r"webmin|10000/tcp\s+open",
     "CRITICAL",
     "CVE-2019-15107",
     "Webmin on port 10000 — CVE-2019-15107 allows unauthenticated RCE via password reset.",
     "Upgrade Webmin. MSF: exploit/linux/http/webmin_backdoor"),

    ("ProFTPD mod_copy RCE",
     r"proftpd\s*(1\.[23]\.|1\.3\.[0-5])",
     "CRITICAL",
     "CVE-2015-3306",
     "ProFTPD mod_copy allows unauthenticated file copy to arbitrary locations → RCE.",
     "Upgrade ProFTPD. MSF: exploit/unix/ftp/proftpd_modcopy_exec"),

    ("Exim RCE",
     r"exim\s*[1-3]\.|exim\s*4\.[0-8][0-9]\.",
     "HIGH",
     "CVE-2019-10149",
     "Old Exim — remote command execution via malformed recipient address.",
     "Upgrade Exim to 4.92+."),
]

SEV_ORDER = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
SEV_COLOR = {
    "CRITICAL": "#ff2244",
    "HIGH":     "#ff6600",
    "MEDIUM":   "#e0a800",
    "LOW":      "#4488cc",
}
SEV_ICON = {"CRITICAL":"💀","HIGH":"🔴","MEDIUM":"🟡","LOW":"🔵"}

# ─────────────────────────────────────────────────────────────
#  SCAN WORKER
# ─────────────────────────────────────────────────────────────
class Worker(QThread):
    sig_progress = pyqtSignal(int, str)
    sig_line     = pyqtSignal(str, str)        # text, colour
    sig_done     = pyqtSignal(dict)
    sig_err      = pyqtSignal(str)

    def __init__(self, cmd, ip, api_key, store):
        super().__init__()
        self.cmd     = cmd
        self.ip      = ip
        self.api_key = api_key
        self.store   = store
        self._abort  = False
        self._proc   = None

    def abort(self):
        self._abort = True
        try:
            if self._proc: self._proc.terminate()
        except: pass

    def run(self):
        res = dict(raw="", cats={}, vulns=[], ai="",
                   ts=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                   target=self.ip, cmd=" ".join(self.cmd))

        self.sig_progress.emit(3,"Launching nmap…")
        self.sig_line.emit("$ " + " ".join(self.cmd), "#1e5f8a")
        self.sig_line.emit("", "#000")

        try:
            self._proc = subprocess.Popen(
                self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1)
            lines = []
            for ln in self._proc.stdout:
                if self._abort: break
                lines.append(ln)
                self.sig_line.emit(ln.rstrip(), self._line_col(ln))
                self.sig_progress.emit(min(72, 3 + len(lines)), f"Scanning… ({len(lines)} lines)")
            self._proc.wait()
            err = self._proc.stderr.read()
            res["raw"] = "".join(lines)
            if err and not res["raw"]:
                self.sig_err.emit(err.strip()); return
        except FileNotFoundError:
            self.sig_err.emit("nmap not found! → sudo apt install nmap"); return
        except Exception as e:
            self.sig_err.emit(str(e)); return

        if self._abort:
            self.sig_err.emit("Scan aborted by user."); return

        self.sig_progress.emit(78,"Parsing output…")
        res["cats"] = self._parse(res["raw"])

        self.sig_progress.emit(85,"Running vulnerability engine…")
        res["vulns"] = self._detect(res["raw"])

        self.sig_progress.emit(92,"Building analysis…")
        if self.api_key.strip():
            res["ai"] = self._gemini(self.api_key.strip(), res["raw"])
        else:
            res["ai"] = self._offline_analysis(res)

        self.sig_progress.emit(100,"Scan complete.")
        self.store["raw"] = res["raw"]
        self.sig_done.emit(res)

    # ── helpers ──────────────────────────────────────────────
    def _line_col(self, ln):
        l = ln.lower()
        if re.search(r"\bopen\b",   l): return "#00cc77"
        if re.search(r"closed|filtered", l): return "#2a3a4a"
        if re.search(r"warning|error",   l): return "#ff6600"
        if re.search(r"^\|",            ln): return "#c9a227"
        if re.search(r"nmap scan report",l): return "#00e5ff"
        if re.search(r"^\d+/(tcp|udp)", ln): return "#7de8ff"
        return "#4a6a8a"

    def _parse(self, raw):
        cats = {"Host & Network":[],"Open Ports":[],"Services & Versions":[],"OS Detection":[],"NSE Scripts":[],"Traceroute":[],"Other":[]}
        for ln in raw.splitlines():
            l = ln.strip()
            if not l: continue
            if re.search(r"Nmap scan report|Host is|latency|mac address", l, re.I):
                cats["Host & Network"].append(l)
            elif re.search(r"^\d+/(tcp|udp)", l):
                cats["Open Ports"].append(l)
            elif re.search(r"Service Info|service detected|Product:|Version:|CPE:", l, re.I):
                cats["Services & Versions"].append(l)
            elif re.search(r"^OS:|Running:|OS CPE:|Aggressive OS|Device type:", l, re.I):
                cats["OS Detection"].append(l)
            elif re.search(r"^\|", l):
                cats["NSE Scripts"].append(l)
            elif re.search(r"TRACEROUTE|^\s+\d+\s+[\d.]+\s+ms", l, re.I):
                cats["Traceroute"].append(l)
            elif not re.search(r"^Starting Nmap|^Nmap done|^#", l):
                cats["Other"].append(l)
        return {k:v for k,v in cats.items() if v}

    def _detect(self, raw):
        lower = raw.lower()
        found, seen = [], set()
        for name, pat, sev, cve, desc, fix in VULNDB:
            if re.search(pat, lower) and name not in seen:
                seen.add(name)
                found.append((sev, name, cve, desc, fix))
        found.sort(key=lambda x: SEV_ORDER.get(x[0],9))
        return found

    def _offline_analysis(self, res):
        vulns = res["vulns"]
        counts = {s: sum(1 for v in vulns if v[0]==s) for s in ["CRITICAL","HIGH","MEDIUM","LOW"]}
        open_ports = [l for l in res["raw"].splitlines() if re.search(r"^\d+/tcp.*open", l)]

        lines = [
            "═" * 60,
            "OFFLINE VULNERABILITY ANALYSIS — SCANEX ENGINE v1.0",
            "═" * 60,
            "",
            f"Target    : {res['target']}",
            f"Scan Time : {res['ts']}",
            f"Open Ports: {len(open_ports)}",
            "",
            "RISK SUMMARY:",
            f"  CRITICAL : {counts['CRITICAL']}",
            f"  HIGH     : {counts['HIGH']}",
            f"  MEDIUM   : {counts['MEDIUM']}",
            f"  LOW      : {counts['LOW']}",
            "",
        ]

        if counts["CRITICAL"] > 0:
            lines += [
                "⚠ CRITICAL RISK — Immediate action required!",
                "This host has critical vulnerabilities that allow",
                "unauthenticated remote code execution.",
                "",
            ]

        if open_ports:
            lines += ["OPEN PORTS DETECTED:"]
            for p in open_ports[:20]:
                lines.append(f"  {p.strip()}")
            lines.append("")

        lines += [
            "─" * 60,
            "NOTE: For AI-powered deep analysis with CVE correlation,",
            "attack chain mapping, and remediation priority scoring,",
            "add your Gemini API key in the target panel.",
            "Free key: https://aistudio.google.com/apikey",
        ]
        return "\n".join(lines)

    def _gemini(self, key, raw):
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={key}"
        prompt = (
            "You are a senior offensive security analyst (OSCP/CEH level). "
            "Analyze the nmap output below and provide a structured report:\n\n"
            "1. EXECUTIVE SUMMARY (4 sentences max)\n"
            "2. CRITICAL FINDINGS (CVE, impact, CVSS score)\n"
            "3. HIGH RISK FINDINGS\n"
            "4. MEDIUM/LOW RISK\n"
            "5. ATTACK CHAIN (step-by-step how an attacker would exploit this host)\n"
            "6. REMEDIATION (prioritised, actionable)\n\n"
            "Plain text, no markdown, be specific and technical.\n\n"
            f"NMAP OUTPUT:\n{raw}"
        )
        try:
            req = _get_requests()
            r = req.post(url,
                json={"contents":[{"parts":[{"text":prompt}]}]}, timeout=40)
            r.raise_for_status()
            return r.json()["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as e:
            return f"Gemini error: {e}"

# ─────────────────────────────────────────────────────────────
#  VULN CARD WIDGET
# ─────────────────────────────────────────────────────────────
class VulnCard(QFrame):
    def __init__(self, sev, name, cve, desc, fix):
        super().__init__()
        col = SEV_COLOR.get(sev, "#888")
        self.setStyleSheet(f"""
            QFrame {{
                background: rgba(10,15,22,0.95);
                border-left: 3px solid {col};
                border-top: 1px solid #1a2535;
                border-right: 1px solid #1a2535;
                border-bottom: 1px solid #1a2535;
                border-radius: 0 6px 6px 0;
                margin: 2px 0;
            }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(4)

        # Title row
        h = QHBoxLayout(); h.setSpacing(10)
        icon_lbl = QLabel(SEV_ICON.get(sev,"•"))
        icon_lbl.setStyleSheet("font-size:16px; background:transparent; border:none;")
        sev_lbl = QLabel(sev)
        sev_lbl.setStyleSheet(f"color:{col}; font-weight:bold; font-size:11px; "
                               f"background:rgba(0,0,0,0.3); border:1px solid {col}; "
                               f"border-radius:3px; padding:1px 6px;")
        name_lbl = QLabel(name)
        name_lbl.setStyleSheet(f"color:#d0e8f0; font-weight:bold; font-size:13px; background:transparent; border:none;")
        cve_lbl = QLabel(cve)
        cve_lbl.setStyleSheet("color:#1e5f8a; font-size:10px; background:transparent; border:none;")
        h.addWidget(icon_lbl)
        h.addWidget(sev_lbl)
        h.addWidget(name_lbl)
        h.addStretch()
        h.addWidget(cve_lbl)
        lay.addLayout(h)

        # Description
        desc_lbl = QLabel(desc)
        desc_lbl.setWordWrap(True)
        desc_lbl.setStyleSheet("color:#6a8a9a; font-size:11px; background:transparent; border:none; padding-left:26px;")
        lay.addWidget(desc_lbl)

        # Fix
        fix_lbl = QLabel(f"→ {fix}")
        fix_lbl.setWordWrap(True)
        fix_lbl.setStyleSheet(f"color:{col}; font-size:10px; background:transparent; border:none; padding-left:26px; opacity:0.8;")
        lay.addWidget(fix_lbl)

# ─────────────────────────────────────────────────────────────
#  RESULTS PANEL
# ─────────────────────────────────────────────────────────────
class Results(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0,0,0,0)
        lay.setSpacing(0)

        self.tabs = QTabWidget()
        lay.addWidget(self.tabs)

        # Tab 1 — live output
        self.raw = QTextEdit(); self.raw.setReadOnly(True)

        # Tab 2 — categories
        self.cats = QTextEdit(); self.cats.setReadOnly(True)

        # Tab 3 — vuln cards
        self.vuln_scroll = QScrollArea()
        self.vuln_scroll.setWidgetResizable(True)
        self.vuln_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.vuln_container = QWidget()
        self.vuln_container.setStyleSheet("background:#07090f;")
        self.vuln_layout = QVBoxLayout(self.vuln_container)
        self.vuln_layout.setContentsMargins(10,10,10,10)
        self.vuln_layout.setSpacing(6)
        self.vuln_layout.addStretch()
        self.vuln_scroll.setWidget(self.vuln_container)

        # Tab 4 — AI
        self.ai = QTextEdit(); self.ai.setReadOnly(True)

        self.tabs.addTab(self.raw,         "⚡  LIVE OUTPUT")
        self.tabs.addTab(self.cats,        "📋  CATEGORIES")
        self.tabs.addTab(self.vuln_scroll, "🔴  VULNERABILITIES")
        self.tabs.addTab(self.ai,          "🤖  AI ANALYSIS")

    def append_raw(self, text, color="#4a6a8a"):
        self.raw.moveCursor(QTextCursor.MoveOperation.End)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        cur = self.raw.textCursor()
        cur.setCharFormat(fmt)
        cur.insertText(text + "\n")
        self.raw.moveCursor(QTextCursor.MoveOperation.End)

    def _ins(self, edit, text, color="#8aabb8", bold=False, size=12):
        edit.moveCursor(QTextCursor.MoveOperation.End)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        fmt.setFontWeight(QFont.Weight.Bold if bold else QFont.Weight.Normal)
        fmt.setFontPointSize(size)
        cur = edit.textCursor(); cur.setCharFormat(fmt)
        cur.insertText(text + "\n")
        edit.moveCursor(QTextCursor.MoveOperation.End)

    def populate(self, res):
        # ── Categories ──────────────────────────────────────
        self.cats.clear()
        for cname, entries in res.get("cats",{}).items():
            self._ins(self.cats, f"\n  {cname.upper()}", "#00e5ff", bold=True, size=11)
            self._ins(self.cats, "  " + "─"*55, "#1a2535")
            for e in entries:
                col = "#00cc77" if re.search(r"\bopen\b", e, re.I) else "#5a7a8a"
                self._ins(self.cats, f"    {e}", col)

        # ── Vuln cards ───────────────────────────────────────
        # clear existing cards (keep last stretch)
        while self.vuln_layout.count() > 1:
            item = self.vuln_layout.takeAt(0)
            if item.widget(): item.widget().deleteLater()

        vulns = res.get("vulns", [])
        if not vulns:
            lbl = QLabel("  ✓  No vulnerabilities detected via pattern matching.")
            lbl.setStyleSheet("color:#00cc77; font-size:13px; padding:20px;")
            self.vuln_layout.insertWidget(0, lbl)
        else:
            # Summary bar
            counts = {s: sum(1 for v in vulns if v[0]==s)
                      for s in ["CRITICAL","HIGH","MEDIUM","LOW"]}
            summ = QLabel(
                f"  Found {len(vulns)} issue(s):   "
                f"💀 CRITICAL {counts['CRITICAL']}   "
                f"🔴 HIGH {counts['HIGH']}   "
                f"🟡 MEDIUM {counts['MEDIUM']}   "
                f"🔵 LOW {counts['LOW']}"
            )
            summ.setStyleSheet("color:#d0e8f0; font-size:12px; font-weight:bold;"
                               "background:#0c1017; border:1px solid #1a2535;"
                               "border-radius:6px; padding:10px 14px; margin-bottom:6px;")
            self.vuln_layout.insertWidget(0, summ)
            for i, (sev, name, cve, desc, fix) in enumerate(vulns):
                card = VulnCard(sev, name, cve, desc, fix)
                self.vuln_layout.insertWidget(i+1, card)

        # ── AI ───────────────────────────────────────────────
        self.ai.clear()
        for ln in res.get("ai","").splitlines():
            col = "#8aabb8"
            if re.search(r"critical|rce|exploit|backdoor|CRITICAL", ln): col = "#ff2244"
            elif re.search(r"HIGH|high risk|vulnerab", ln):               col = "#ff6600"
            elif re.search(r"MEDIUM|moderate",         ln):               col = "#e0a800"
            elif re.search(r"recommend|fix|patch|remediat|→", ln):       col = "#00cc77"
            elif re.search(r"^[═─]",                   ln):               col = "#1a3a55"
            elif re.search(r"^[A-Z\s]+:$|^\d+\.",      ln):               col = "#00e5ff"
            self._ins(self.ai, f"  {ln}", col)

        self.tabs.setCurrentIndex(2)

    def clear_all(self):
        for w in (self.raw, self.cats, self.ai):
            w.clear()
        while self.vuln_layout.count() > 1:
            item = self.vuln_layout.takeAt(0)
            if item.widget(): item.widget().deleteLater()
        self.tabs.setCurrentIndex(0)

# ─────────────────────────────────────────────────────────────
#  MAIN WINDOW
# ─────────────────────────────────────────────────────────────
class SCANEX(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SCANEX — Security Scan & Exploit Analyzer")
        self.setMinimumSize(1300, 820)
        self.resize(1500, 940)
        self._worker  = None
        self._store   = {"raw":""}
        self._checks  = {}
        self._build()
        self.setStyleSheet(QSS)
        self.setWindowIcon(self._mk_icon())

    # ── Icon ──────────────────────────────────────────────────
    def _mk_icon(self):
        pm = QPixmap(32,32); pm.fill(Qt.GlobalColor.transparent)
        p  = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QColor("#00e5ff")); p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(2,2,28,28)
        p.setBrush(QColor("#07090f"))
        p.drawEllipse(9,9,14,14)
        p.setBrush(QColor("#00e5ff"))
        p.drawEllipse(13,13,6,6)
        p.end()
        return QIcon(pm)

    # ── Build UI ──────────────────────────────────────────────
    def _build(self):
        root = QWidget(); self.setCentralWidget(root)
        vl   = QVBoxLayout(root)
        vl.setContentsMargins(0,0,0,0)
        vl.setSpacing(0)

        vl.addWidget(self._mk_header())

        body = QWidget()
        bl = QHBoxLayout(body)
        bl.setContentsMargins(14,12,14,0)
        bl.setSpacing(12)

        sp = QSplitter(Qt.Orientation.Horizontal)
        sp.setHandleWidth(2)
        sp.addWidget(self._mk_left())
        sp.addWidget(self._mk_right())
        sp.setStretchFactor(0,5)
        sp.setStretchFactor(1,7)
        bl.addWidget(sp)
        vl.addWidget(body,1)
        vl.addWidget(self._mk_footer())

    # ── Header ────────────────────────────────────────────────
    def _mk_header(self):
        hdr = QFrame(); hdr.setObjectName("hdr")
        hdr.setFixedHeight(76)
        hl  = QHBoxLayout(hdr)
        hl.setContentsMargins(24,0,24,0)

        # left — logo
        ll = QVBoxLayout(); ll.setSpacing(2)
        logo = QLabel("SCANEX"); logo.setObjectName("logo_scanex")
        sub  = QLabel("Security Scan & Exploit Analyzer"); sub.setObjectName("logo_sub")
        ll.addWidget(logo); ll.addWidget(sub)
        hl.addLayout(ll)
        hl.addStretch()

        # centre — badges
        for txt in ["NMAP ENGINE","VULN DB v3","OFFLINE AI"]:
            b = QLabel(txt); b.setObjectName("badge")
            hl.addWidget(b)
            hl.addSpacing(8)

        hl.addStretch()

        # right — clock
        self._clock = QLabel(); self._clock.setObjectName("clock")
        self._clock.setAlignment(Qt.AlignmentFlag.AlignRight)
        hl.addWidget(self._clock)
        t = QTimer(self); t.timeout.connect(self._tick); t.start(1000)
        self._tick()
        return hdr

    # ── Left panel ────────────────────────────────────────────
    def _mk_left(self):
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setContentsMargins(0,0,6,0)
        vl.setSpacing(10)

        # Target
        tp = QFrame(); tp.setObjectName("pnl_hi")
        tl = QVBoxLayout(tp); tl.setContentsMargins(16,14,16,14); tl.setSpacing(8)
        self._sec(tl,"TARGET")
        self.ip_inp   = self._inp("IP / Host / CIDR  —  e.g. 192.168.1.102")
        self.port_inp = self._inp("Custom ports (optional)  —  e.g.  21,22,80,445  or  1-1024")
        self.api_inp  = self._inp("Gemini API key (optional — leave blank for offline analysis)")
        self.api_inp.setEchoMode(QLineEdit.EchoMode.Password)
        for w2 in (self.ip_inp, self.port_inp, self.api_inp):
            tl.addWidget(w2)
        vl.addWidget(tp)

        # Options
        op = QFrame(); op.setObjectName("pnl")
        ol = QVBoxLayout(op); ol.setContentsMargins(16,14,16,10); ol.setSpacing(4)
        self._sec(ol,"SCAN OPTIONS")

        sa = QScrollArea(); sa.setWidgetResizable(True)
        sa.setFrameShape(QFrame.Shape.NoFrame)
        ow = QWidget(); ow.setStyleSheet("background:transparent;")
        og = QVBoxLayout(ow); og.setContentsMargins(0,0,6,0); og.setSpacing(1)

        cats = {}
        for label,flag,default,cat,tip in OPTS:
            cats.setdefault(cat,[]).append((label,flag,default,tip))

        for cname in ["Discovery","Scan Type","Speed","Ports","Scripts","Output"]:
            if cname not in cats: continue
            cl = QLabel(cname.upper()); cl.setObjectName("cat")
            og.addWidget(cl)
            for label,flag,default,tip in cats[cname]:
                cb = QCheckBox(f"  {label}")
                cb.setChecked(default)
                cb.setToolTip(tip)
                cb.stateChanged.connect(self._upd_cmd)
                self._checks[flag] = cb
                og.addWidget(cb)
        og.addStretch()
        sa.setWidget(ow)
        ol.addWidget(sa)
        vl.addWidget(op,1)

        # Command preview
        cp = QFrame(); cp.setObjectName("pnl")
        cl2 = QVBoxLayout(cp); cl2.setContentsMargins(14,10,14,10); cl2.setSpacing(4)
        self._sec(cl2,"COMMAND PREVIEW")
        self.cmd_lbl = QLabel()
        self.cmd_lbl.setObjectName("cmd_box")
        self.cmd_lbl.setWordWrap(True)
        self.cmd_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        cl2.addWidget(self.cmd_lbl)
        vl.addWidget(cp)

        self._upd_cmd()
        return w

    # ── Right panel ───────────────────────────────────────────
    def _mk_right(self):
        w  = QWidget()
        vl = QVBoxLayout(w)
        vl.setContentsMargins(6,0,0,0)
        vl.setSpacing(0)
        self.results = Results()
        vl.addWidget(self.results)
        return w

    # ── Footer ────────────────────────────────────────────────
    def _mk_footer(self):
        w  = QWidget()
        w.setStyleSheet("background:#050810; border-top:1px solid #1a2535;")
        hl = QHBoxLayout(w); hl.setContentsMargins(14,8,14,8); hl.setSpacing(10)

        self.btn_start = QPushButton("▶   START SCAN")
        self.btn_start.setObjectName("btn_start")
        self.btn_start.setFixedHeight(48)
        self.btn_start.clicked.connect(self._start)

        self.btn_stop = QPushButton("■  STOP")
        self.btn_stop.setObjectName("btn_stop")
        self.btn_stop.setFixedHeight(48)
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._stop)

        self.btn_clear = QPushButton("⟳  CLEAR")
        self.btn_clear.setObjectName("btn_minor")
        self.btn_clear.setFixedHeight(48)
        self.btn_clear.clicked.connect(self._clear)

        self.btn_save = QPushButton("💾  SAVE REPORT")
        self.btn_save.setObjectName("btn_save")
        self.btn_save.setFixedHeight(48)
        self.btn_save.clicked.connect(self._save)

        self.prog = QProgressBar()
        self.prog.setRange(0,100); self.prog.setValue(0)
        self.prog.setFixedHeight(5)
        self.prog.setTextVisible(False)

        self.stat_lbl = QLabel("Idle")
        self.stat_lbl.setStyleSheet("color:#1e5f8a; font-size:11px;")

        hl.addWidget(self.btn_start,3)
        hl.addWidget(self.btn_stop,1)
        hl.addWidget(self.btn_clear,1)
        hl.addWidget(self.btn_save,1)

        vr = QVBoxLayout(); vr.setSpacing(4)
        vr.addWidget(self.stat_lbl)
        vr.addWidget(self.prog)
        hl.addLayout(vr,2)
        return w

    # ── Helpers ───────────────────────────────────────────────
    def _sec(self, layout, text):
        l = QLabel(text); l.setObjectName("sec")
        layout.addWidget(l)

    def _inp(self, ph):
        e = QLineEdit(); e.setPlaceholderText(ph)
        e.setFixedHeight(40)
        e.textChanged.connect(self._upd_cmd)
        return e

    def _tick(self):
        self._clock.setText(datetime.now().strftime("%a  %Y-%m-%d  %H:%M:%S"))

    # ── Command build ─────────────────────────────────────────
    def _build_cmd(self):
        cmd = ["nmap"]
        speed = None
        for flag,cb in self._checks.items():
            if cb.isChecked() and re.match(r"^-T[1-5]$", flag):
                speed = flag
        if speed: cmd.append(speed)

        port_flags = {"-p-","--top-ports 100","--top-ports 1000","-p 1-1024"}
        cport = self.port_inp.text().strip() if hasattr(self,"port_inp") else ""

        for flag,cb in self._checks.items():
            if not cb.isChecked(): continue
            if re.match(r"^-T[1-5]$", flag): continue
            if cport and flag in port_flags: continue
            cmd.extend(flag.split())

        if cport:
            cmd += ["-p", cport]

        ip = self.ip_inp.text().strip() if hasattr(self,"ip_inp") else "<target>"
        cmd.append(ip or "<target>")
        return cmd

    def _upd_cmd(self):
        cmd = self._build_cmd()
        self.cmd_lbl.setText("$ " + " ".join(cmd))

    # ── Scan flow ─────────────────────────────────────────────
    def _start(self):
        ip = self.ip_inp.text().strip()
        if not ip:
            self.statusBar().showMessage("⚠  Enter a target first.")
            self.ip_inp.setFocus(); return

        self.results.clear_all()
        self._store["raw"] = ""
        cmd = self._build_cmd()

        self._worker = Worker(cmd, ip, self.api_inp.text(), self._store)
        self._worker.sig_progress.connect(self._on_prog)
        self._worker.sig_line.connect(self.results.append_raw)
        self._worker.sig_done.connect(self._on_done)
        self._worker.sig_err.connect(self._on_err)
        self._worker.start()

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.prog.setValue(0)
        self.statusBar().showMessage(f"Scanning {ip}…")

    def _stop(self):
        if self._worker: self._worker.abort()
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.statusBar().showMessage("Scan stopped.")

    def _on_prog(self, pct, msg):
        self.prog.setValue(pct)
        self.stat_lbl.setText(msg)
        self.statusBar().showMessage(msg)

    def _on_done(self, res):
        self.results.populate(res)
        vulns = res.get("vulns",[])
        crit  = sum(1 for v in vulns if v[0]=="CRITICAL")
        msg   = (f"✓  Scan complete  ·  {len(vulns)} finding(s)"
                 + (f"  ·  {crit} CRITICAL" if crit else "")
                 + f"  ·  {res.get('ts','')}")
        self.statusBar().showMessage(msg)
        self.stat_lbl.setText("Complete")
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)

    def _on_err(self, err):
        self.results.append_raw(f"\n  ERROR: {err}", "#ff2244")
        self.statusBar().showMessage(f"Error: {err}")
        self.stat_lbl.setText("Error")
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)

    def _clear(self):
        self.results.clear_all()
        self.prog.setValue(0)
        self.stat_lbl.setText("Idle")
        self.statusBar().showMessage("Cleared.")

    def _save(self):
        raw = self._store.get("raw","")
        if not raw:
            self.statusBar().showMessage("Nothing to save."); return
        path,_ = QFileDialog.getSaveFileName(
            self,"Save Report",
            f"scanex_{self.ip_inp.text().replace('/','_')}_{datetime.now():%Y%m%d_%H%M%S}.txt",
            "Text (*.txt);;All (*)")
        if path:
            with open(path,"w") as f:
                f.write(f"SCANEX REPORT\nTarget: {self.ip_inp.text()}\n"
                        f"Date  : {datetime.now()}\n{'='*60}\n\n{raw}")
            self.statusBar().showMessage(f"Saved → {path}")

# ─────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────
def main():
    import os

    # ── Windows env tweaks before QApplication ──────────────────
    if sys.platform == "win32":
        os.environ.setdefault("QT_FONT_DPI", "96")
        os.environ.setdefault("QT_SCALE_FACTOR", "1")

    # ── nmap check ──────────────────────────────────────────────
    try:
        subprocess.run(["nmap","--version"], capture_output=True, check=True)
    except FileNotFoundError:
        print("nmap not found.")
        print("  Windows : https://nmap.org/download.html")
        print("  Linux   : sudo apt install nmap")
        sys.exit(1)

    # ── Launch ──────────────────────────────────────────────────
    app = QApplication(sys.argv)
    app.setApplicationName("SCANEX")
    app.setStyle("Fusion")          # Fusion avoids slow platform theme probing on Windows

    w = SCANEX()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()