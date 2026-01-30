# CloudFail

CloudFail is a tactical reconnaissance tool that gathers intelligence about a target protected by Cloudflare, aiming to discover the origin server. Using Tor to mask requests, the tool currently runs three phases:

1) Misconfigured DNS scan using DNSDumpster.com
2) Crimeflare database lookup
3) Subdomain bruteforce scan

![Example usage](http://puu.sh/pq7vH/62d56aa41f.png "Example usage")

> Contributions are welcome. Open a pull request if you have an improvement.

## Contents
- Overview
- Requirements
- Install
- Usage
- External Data Sources (Optional)
- Performance Options
- Output Options
- Phase Toggles
- Exit Codes
- Dependencies
- Disclaimer
- Donate

## Overview
CloudFail focuses on information gathering around Cloudflare-protected targets. It combines public data sources and subdomain enumeration to find non-Cloudflare infrastructure that may expose an origin IP.

## Requirements
**Python 3.11.7 or higher is required.**

## Install

### Kali/Debian
Install Python 3.11+ and pip3:

```bash
sudo apt-get install python3 python3-pip
```

Install dependencies:

```bash
pip3 install -r requirements.txt
```

If missing setuptools:

```bash
sudo apt-get install python3-setuptools
```

### Docker
The Dockerfile uses Python 3.11 as the base image:

```bash
docker build -t cloudfail .
```

```bash
docker run -it cloudfail --target seo.com
```

## Usage

Basic scan:

```bash
python3 cloudfail.py --target seo.com
```

Scan using Tor:

```bash
service tor start
```

(On Windows or Mac, install Vidalia or run the Tor Browser.)

```bash
python3 cloudfail.py --target seo.com --tor
```

## External Data Sources (Optional)
CloudFail can query external free data sources for additional subdomain discovery. These are opt-in and disabled by default.

Available sources:

| Source | Description | Notes |
| --- | --- | --- |
| `crtsh` | Certificate Transparency logs via crt.sh | Best for subdomain discovery |
| `wayback` | Historical URLs from Wayback Machine | Useful for leaked hosts |
| `alienvault` | Passive DNS from AlienVault OTX | Free tier, no key |
| `hackertarget` | HackerTarget hostsearch | 100/day without key |
| `rapiddns` | RapidDNS subdomain enumeration | Web scraping |
| `threatcrowd` | ThreatCrowd domain report API | Free API |
| `urlscan` | URLScan.io search API | 100/day without key |
| `viewdns` | ViewDNS IP history lookup | Web scraping |
| `bing` | Bing search | `site:*.domain.com` |

Usage:

Enable a single source:
```bash
python3 cloudfail.py --target seo.com --sources crtsh
```

Enable multiple sources (comma-separated):
```bash
python3 cloudfail.py --target seo.com --sources crtsh,wayback,rapiddns
```

Enable all sources:
```bash
python3 cloudfail.py --target seo.com --sources crtsh,wayback,alienvault,hackertarget,rapiddns,threatcrowd,urlscan,viewdns,bing
```

Enable all sources with Tor:
```bash
python3 cloudfail.py --target seo.com --tor --sources crtsh,wayback,alienvault,hackertarget,rapiddns,threatcrowd,urlscan,viewdns,bing
```

## Performance Options

Multi-threaded scanning:
```bash
python3 cloudfail.py --target seo.com --threads 10
```

Resume interrupted scans:
```bash
python3 cloudfail.py --target seo.com --resume checkpoint.txt
```

Skip duplicate IPs:
```bash
python3 cloudfail.py --target seo.com --skip-duplicate-ips
```

Combined example:
```bash
python3 cloudfail.py --target seo.com --threads 20 --resume checkpoint.txt --skip-duplicate-ips --sources crtsh,rapiddns
```

## Output Options

JSON output:
```bash
python3 cloudfail.py --target seo.com --output results.json
```

Quiet mode (IPs only):
```bash
python3 cloudfail.py --target seo.com --quiet
```

Disable colors:
```bash
python3 cloudfail.py --target seo.com --no-color
```

Custom timeout:
```bash
python3 cloudfail.py --target seo.com --timeout 30
```

## Phase Toggles
Skip specific scan phases:

```bash
# Skip subdomain bruteforce
python3 cloudfail.py --target seo.com --no-subdomain

# Skip DNSDumpster
python3 cloudfail.py --target seo.com --no-dns

# Skip Crimeflare database
python3 cloudfail.py --target seo.com --no-crimeflare

# Only scan external sources
python3 cloudfail.py --target seo.com --no-subdomain --no-dns --no-crimeflare --sources crtsh
```

## Exit Codes
- `0` - Success with findings
- `1` - User or configuration error
- `2` - No findings

## Dependencies
**Python 3.11.7+**
- argparse
- beautifulsoup4
- colorama
- requests
- dnspython
- PySocks

## Disclaimer
This tool is a PoC (Proof of Concept) and does not guarantee results. It is possible to set up Cloudflare properly so that the IP is never released or logged anywhere; this is not often the case and hence why this tool exists. This tool is only for academic purposes and testing under controlled environments. Do not use without obtaining proper authorization from the network owner of the network under testing. The author bears no responsibility for any misuse of the tool.

## Donate BTC
> 13eiCHxmAEaRZDXcgKJVtVnCKK5mTR1u1F

Buy me a beer or coffee... or both.
If you donate send me a message and I will add you to the credits!
Thank YOU!
