# 🔍 Automated Network Scanner

A Python-based network scanning tool that wraps **Nmap**, parses its output, and generates clean **text, JSON, and HTML reports**. Built for quick recon during CTFs (TryHackMe, HackTheBox), home network audits, and learning offensive security fundamentals.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

---

## ✨ Features

- 🎯 Scan a single IP, hostname, or entire CIDR range
- 🔓 Detect open ports and running services (via Nmap `-sV`)
- 📄 Parse Nmap's raw XML output into clean, structured results
- 📊 Export reports in **HTML**, **JSON**, or **plain text**
- ⚡ Configurable port ranges, top-ports scanning, and timing templates
- 🛡️ Built-in safety prompt before scanning non-private/public IPs
- 🧩 Zero third-party Python dependencies (standard library only)

---

## 📸 Sample Report

The HTML report renders a dark-themed, per-host breakdown of open ports and services:

| Host | Port | Service | Version |
|------|------|---------|---------|
| 192.168.1.10 | 22/tcp | ssh | OpenSSH 8.9 (Ubuntu) |
| 192.168.1.10 | 80/tcp | http | nginx 1.18.0 |

*(see `sample_report.html` in this repo for a full live example)*

---

## ⚙️ Requirements

- Python 3.8+
- [Nmap](https://nmap.org/download.html) installed and available on your `PATH`

```bash
# Debian/Ubuntu/Kali
sudo apt install nmap -y

# macOS
brew install nmap
```

No `pip install` needed — the script only uses Python's standard library (`subprocess`, `xml.etree.ElementTree`, `argparse`, `json`).

---

## 🚀 Installation

```bash
git clone https://github.com/<your-username>/automated-network-scanner.git
cd automated-network-scanner
```

---

## 🖥️ Usage

### Basic scan
```bash
python3 scanner.py 192.168.1.1
```

### Scan a specific port range
```bash
python3 scanner.py 192.168.1.1 --ports 1-1000
```

### Scan an entire subnet
```bash
python3 scanner.py 192.168.1.0/24 --ports 22,80,443
```

### Scan the top N most common ports
```bash
python3 scanner.py 10.10.10.10 --top-ports 100
```

### Generate an HTML report
```bash
python3 scanner.py 10.10.10.10 --html report.html
```

### Generate all report formats at once
```bash
python3 scanner.py 10.10.10.10 --json report.json --text report.txt --html report.html
```

### Skip service/version detection (faster scan)
```bash
python3 scanner.py 10.10.10.10 --no-service-detection
```

### Skip the confirmation prompt (for automation/CI)
```bash
python3 scanner.py 10.10.10.10 --yes
```

### Full CLI reference
```bash
python3 scanner.py --help
```

---

## 🕵️ Using with TryHackMe / HackTheBox

1. Connect to the platform's VPN (or use their in-browser AttackBox).
2. Copy the target IP they assign you (e.g. `10.10.xx.xx`).
3. Run the scanner against it:

```bash
python3 scanner.py 10.10.xx.xx --top-ports 100 --html report.html
```

4. For a thorough sweep across all ports (recommended if a service seems hidden):

```bash
python3 scanner.py 10.10.xx.xx --ports 1-65535 --html report.html
```

Since CTF platform IPs are private-range (`10.x.x.x`), the script skips the public-target confirmation prompt automatically.

---

## 🧠 How It Works

```
CLI input → subprocess runs Nmap (-oX XML) → parse XML → structured Host/Port objects → render report(s)
```

1. **Scanning** — `subprocess` builds and executes an `nmap` command with service detection (`-sV`) and outputs results as XML (`-oX`), which is far more reliable to parse than scraping terminal text.
2. **Parsing** — `xml.etree.ElementTree` walks the XML tree and extracts host status, open ports, protocols, and service/version info into simple Python objects (`HostResult`, `PortResult`).
3. **Reporting** — the same parsed data feeds three independent renderers (text, JSON, HTML), so nothing is scanned or parsed twice — only formatted differently.

---

## 📁 Project Structure

```
automated-network-scanner/
├── scanner.py          # Main script — scanning, parsing, and reporting logic
├── README.md           # This file
└── sample_report.html  # Example HTML output
```

---

## ⚠️ Legal Disclaimer

This tool is intended for **educational purposes and authorized security testing only**.

Only scan systems you **own** or have **explicit written permission** to test — including:
- Your own devices and home network
- Sanctioned practice targets like [`scanme.nmap.org`](https://nmap.org/book/legal-issues.html)
- Assigned machines on platforms like TryHackMe or HackTheBox

Unauthorized scanning of networks or systems you do not have permission to test may violate laws such as the U.S. **Computer Fraud and Abuse Act (CFAA)**, the UK **Computer Misuse Act**, or equivalent legislation in your country, as well as your ISP's terms of service. **The author assumes no liability for misuse of this tool.**

---

## 🛠️ Roadmap / Ideas for Contribution

- [ ] CSV export format
- [ ] OS detection support (`-O`)
- [ ] NSE script integration (e.g. `--script vuln`)
- [ ] Scan result diffing (compare two scans over time)
- [ ] Dockerfile for containerized usage

Pull requests welcome!

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 👤 Author

TauFique

Built as a learning project for network security fundamentals — Python `subprocess`, XML parsing, and report generation.

If this project helped you, consider giving it a ⭐ on GitHub!
