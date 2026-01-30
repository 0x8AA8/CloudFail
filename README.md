# CloudFail

CloudFail is a tactical reconnaissance tool which aims to gather enough information about a target protected by Cloudflare in the hopes of discovering the location of the server. Using Tor to mask all requests, the tool as of right now has 3 different attack phases.

1. Misconfigured DNS scan using DNSDumpster.com.
2. Scan the Crimeflare.com database.
3. Bruteforce scan over 2500 subdomains.

![Example usage](http://puu.sh/pq7vH/62d56aa41f.png "Example usage")

> Please feel free to contribute to this project. If you have an idea or improvement issue a pull request!

#### Requirements

**Python 3.11.7 or higher is required.**

#### Disclaimer
This tool is a PoC (Proof of Concept) and does not guarantee results.  It is possible to setup Cloudflare properly so that the IP is never released or logged anywhere; this is not often the case and hence why this tool exists.
This tool is only for academic purposes and testing  under controlled environments. Do not use without obtaining proper authorization
from the network owner of the network under testing.
The author bears no responsibility for any misuse of the tool.

#### Install on Kali/Debian

First we need to install Python 3.11+ and pip3:

```$ sudo apt-get install python3 python3-pip```

Then we can install dependencies:

```$ pip3 install -r requirements.txt```

If this fails because of missing setuptools, do this:

```$ sudo apt-get install python3-setuptools```

#### Install with Docker

The Dockerfile uses Python 3.11 as the base image:

```$ docker build -t cloudfail .```

```$ docker run -it cloudfail --target seo.com```

#### Usage

To run a scan against a target:

```python3 cloudfail.py --target seo.com```

To run a scan against a target using Tor:

```service tor start```

(or if you are using Windows or Mac install vidalia or just run the Tor browser)

```python3 cloudfail.py --target seo.com --tor```

#### External Data Sources (Optional)

CloudFail supports querying external free data sources for additional subdomain discovery. These are opt-in and disabled by default.

**Available sources:**
- `crtsh` - Certificate Transparency logs via crt.sh
- `wayback` - Historical URLs from Wayback Machine
- `alienvault` - Passive DNS from AlienVault OTX
- `hackertarget` - HackerTarget hostsearch (100 queries/day free)
- `rapiddns` - RapidDNS subdomain enumeration
- `threatcrowd` - ThreatCrowd domain report API
- `urlscan` - URLScan.io search API
- `viewdns` - ViewDNS IP history lookup
- `bing` - Bing search engine subdomain discovery

**Usage:**

Enable a single source:
```python3 cloudfail.py --target seo.com --sources crtsh```

Enable multiple sources (comma-separated):
```python3 cloudfail.py --target seo.com --sources crtsh,wayback,rapiddns```

Enable all sources:
```python3 cloudfail.py --target seo.com --sources crtsh,wayback,alienvault,hackertarget,rapiddns,threatcrowd,urlscan,viewdns,bing```

Enable all sources with Tor:
```python3 cloudfail.py --target seo.com --tor --sources crtsh,wayback,alienvault,hackertarget,rapiddns,threatcrowd,urlscan,viewdns,bing```

#### Performance Options

**Multi-threaded scanning:**

Speed up subdomain scanning with concurrent threads:
```python3 cloudfail.py --target seo.com --threads 10```

**Resume interrupted scans:**

Save progress to a checkpoint file and resume later:
```python3 cloudfail.py --target seo.com --resume checkpoint.txt```

If interrupted, resume from where you left off:
```python3 cloudfail.py --target seo.com --resume checkpoint.txt```

**Skip duplicate IPs:**

Avoid redundant checks when multiple subdomains resolve to the same IP:
```python3 cloudfail.py --target seo.com --skip-duplicate-ips```

**Combined example:**
```python3 cloudfail.py --target seo.com --threads 20 --resume checkpoint.txt --skip-duplicate-ips --sources crtsh,rapiddns```

#### Dependencies
**Python 3.11.7+**
* argparse
* beautifulsoup4
* colorama
* requests
* dnspython
* PySocks

## Donate BTC
> 13eiCHxmAEaRZDXcgKJVtVnCKK5mTR1u1F

Buy me a beer or coffee... or both! 
If you donate send me a message and I will add you to the credits!
Thank YOU!
