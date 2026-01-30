<p align="center">
  <img src="http://puu.sh/pq7vH/62d56aa41f.png" alt="CloudFail Example" width="600"/>
</p>

<h1 align="center">☁️ CloudFail</h1>

<p align="center">
  <b>Unmask the origin server behind Cloudflare</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue.svg?style=flat-square&logo=python&logoColor=white" alt="Python 3.11+"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey.svg?style=flat-square" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-MIT-green.svg?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/badge/tor-supported-purple.svg?style=flat-square&logo=tor-project&logoColor=white" alt="Tor Support"/>
  <img src="https://img.shields.io/badge/docker-ready-blue.svg?style=flat-square&logo=docker&logoColor=white" alt="Docker"/>
</p>

<p align="center">
  <a href="#-overview">Overview</a> •
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-data-sources">Data Sources</a> •
  <a href="#-options">Options</a>
</p>

---

## 🔍 Overview

**CloudFail** is a tactical reconnaissance tool that gathers intelligence about targets protected by Cloudflare, aiming to discover the origin server. Using Tor to mask requests, the tool runs three core phases:

| Phase | Description |
|:-----:|-------------|
| **1** | Misconfigured DNS scan using DNSDumpster.com |
| **2** | Crimeflare database lookup |
| **3** | Subdomain bruteforce scan |

> 💡 **Contributions welcome!** Open a pull request if you have an improvement.

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🛡️ Core Capabilities
- DNS misconfiguration detection
- Crimeflare database integration
- Subdomain bruteforce scanning
- Cloudflare IP range detection

</td>
<td width="50%">

### 🚀 Advanced Features
- Multi-threaded scanning
- 9 external data sources
- Resumable scan checkpoints
- JSON export & quiet mode

</td>
</tr>
<tr>
<td width="50%">

### 🔒 Privacy & Security
- Full Tor proxy support
- Anonymous reconnaissance
- No API keys required

</td>
<td width="50%">

### ⚙️ Flexibility
- Phase toggles (skip any phase)
- Custom timeout control
- Duplicate IP filtering

</td>
</tr>
</table>

---

## 📦 Installation

### Prerequisites

> ⚠️ **Python 3.11.7 or higher is required**

### 🐧 Kali/Debian

```bash
# Install Python 3.11+ and pip3
sudo apt-get install python3 python3-pip

# Install dependencies
pip3 install -r requirements.txt

# If missing setuptools
sudo apt-get install python3-setuptools
```

### 🐳 Docker

```bash
# Build the image
docker build -t cloudfail .

# Run CloudFail
docker run -it cloudfail --target seo.com
```

---

## 🎯 Usage

### Basic Scan

```bash
python3 cloudfail.py --target seo.com
```

### 🧅 Scan with Tor

```bash
# Start Tor service (Linux)
service tor start

# Windows/Mac: Install Vidalia or run Tor Browser

# Run scan through Tor
python3 cloudfail.py --target seo.com --tor
```

### Full Power Scan

```bash
python3 cloudfail.py --target seo.com \
    --tor \
    --threads 20 \
    --sources crtsh,wayback,rapiddns \
    --output results.json
```

---

## 📡 Data Sources

CloudFail can query **9 external free data sources** for enhanced subdomain discovery. All sources are opt-in and disabled by default.

| Source | Description | Rate Limit |
|:------:|-------------|:----------:|
| `crtsh` | Certificate Transparency logs via crt.sh | ✅ Unlimited |
| `wayback` | Historical URLs from Wayback Machine | ✅ Unlimited |
| `alienvault` | Passive DNS from AlienVault OTX | ✅ Free tier |
| `hackertarget` | HackerTarget hostsearch | ⚡ 100/day |
| `rapiddns` | RapidDNS subdomain enumeration | ✅ Unlimited |
| `threatcrowd` | ThreatCrowd domain report API | ✅ Free API |
| `urlscan` | URLScan.io search API | ⚡ 100/day |
| `viewdns` | ViewDNS IP history lookup | ✅ Unlimited |
| `bing` | Bing search `site:*.domain.com` | ✅ Unlimited |

### Enable Sources

```bash
# Single source
python3 cloudfail.py --target seo.com --sources crtsh

# Multiple sources (comma-separated)
python3 cloudfail.py --target seo.com --sources crtsh,wayback,rapiddns

# All sources with Tor
python3 cloudfail.py --target seo.com --tor --sources crtsh,wayback,alienvault,hackertarget,rapiddns,threatcrowd,urlscan,viewdns,bing
```

---

## ⚙️ Options

### 🚀 Performance

| Flag | Description | Default |
|------|-------------|---------|
| `--threads N` | Number of concurrent threads | 1 |
| `--resume FILE` | Resume from checkpoint file | - |
| `--skip-duplicate-ips` | Skip already-seen IP addresses | Off |

```bash
python3 cloudfail.py --target seo.com --threads 20 --skip-duplicate-ips
```

### 📤 Output

| Flag | Description | Default |
|------|-------------|---------|
| `--output FILE` | Save results to JSON file | - |
| `--quiet` | Output only discovered IPs | Off |
| `--no-color` | Disable colored output | Off |
| `--timeout SEC` | Request timeout in seconds | 15 |

```bash
# JSON output for scripting
python3 cloudfail.py --target seo.com --output results.json --quiet
```

### 🎛️ Phase Toggles

Skip specific scan phases when needed:

| Flag | Skips |
|------|-------|
| `--no-subdomain` | Subdomain bruteforce phase |
| `--no-dns` | DNSDumpster phase |
| `--no-crimeflare` | Crimeflare database lookup |

```bash
# Only scan external sources
python3 cloudfail.py --target seo.com \
    --no-subdomain --no-dns --no-crimeflare \
    --sources crtsh,rapiddns
```

---

## 📊 Exit Codes

For scripting and automation:

| Code | Meaning |
|:----:|---------|
| `0` | ✅ Success - findings discovered |
| `1` | ❌ User or configuration error |
| `2` | ⚠️ No findings |

---

## 📚 Dependencies

| Package | Purpose |
|---------|---------|
| `beautifulsoup4` | HTML parsing |
| `colorama` | Colored terminal output |
| `requests` | HTTP requests |
| `dnspython` | DNS resolution |
| `PySocks` | Tor/SOCKS proxy support |

Install all dependencies:

```bash
pip3 install -r requirements.txt
```

---

## ⚠️ Disclaimer

<table>
<tr>
<td>
<b>⚖️ Legal Notice</b><br><br>
This tool is a <b>Proof of Concept (PoC)</b> and does not guarantee results. It is possible to configure Cloudflare properly so that the origin IP is never exposed; this is not always the case, hence why this tool exists.<br><br>
<b>This tool is intended for:</b>
<ul>
<li>Academic research</li>
<li>Authorized penetration testing</li>
<li>Security assessments with proper authorization</li>
</ul>
<b>Do not use</b> without obtaining proper authorization from the network owner. The author bears no responsibility for any misuse of this tool.
</td>
</tr>
</table>

---

<p align="center">
  <b>☕ Support the Project</b>
</p>

<p align="center">
  <code>BTC: 13eiCHxmAEaRZDXcgKJVtVnCKK5mTR1u1F</code>
</p>

<p align="center">
  Buy me a beer or coffee... or both!<br>
  If you donate, send me a message and I'll add you to the credits!
</p>

<p align="center">
  <b>Thank you! 🙏</b>
</p>

---

<p align="center">
  Made with ❤️ for the security community
</p>
