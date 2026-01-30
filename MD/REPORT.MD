# CloudFail Report

Generated: 2026-01-30
Project root: C:\Users\Usui\Desktop\DevOPS\CloudFail

## Index of files
- .gitignore
- cloudfail.py
- DNSDumpsterAPI.py
- Dockerfile
- LICENSE.md
- README.md
- requirements.txt
- socks.py
- sockshandler.py
- data/cf-subnet.txt
- data/subdomains.txt

## Python version
- Current: No explicit version pin. The code uses a python3 shebang and README says "Python3"; Docker installs the system python3 from debian:sid. There is no guarantee this is 3.11.7+.
- Target: Update the project to require Python 3.11.7+ (document it and pin it in tooling, e.g., Docker/base image and packaging metadata).

## Findings

### Broken / error-prone code
- Windows detection bug: uses `platform == 'Windows'` instead of `platform.system() == 'Windows'`, so Windows-specific `win_inet_pton` path is never used. This can break IP parsing on Windows. (cloudfail.py:45)
- NameError on TOR failure: `print(e, net_exc)` references undefined `net_exc`. This will crash the error handler if the request fails. (cloudfail.py:298)
- Progress calculation can divide by zero when the subdomain list has <100 lines. (cloudfail.py:213)
- When `--subdomains` is provided, progress count still reads `data/subdomains.txt` instead of the selected list, and the file handle is not closed. (cloudfail.py:207)

### Legacy / deprecated APIs
- `ssl.wrap_socket` is deprecated; should use `ssl.SSLContext.wrap_socket`. (sockshandler.py:43)
- `sockshandler.py` shebang is `python` (not `python3`), which can run under Python 2 on some systems. (sockshandler.py:1)

### Dependency and compatibility risks (old pins)
- requirements are pinned to very old versions (2017-era), likely missing security fixes and potentially incompatible with Python 3.11+:
  - beautifulsoup4==4.6.0, bs4==0.0.1 (duplicate + very old)
  - certifi==2017.4.17, chardet==3.0.4, idna==2.5, urllib3==1.24.2
  - colorama==0.3.9, dnspython==1.15.0, win_inet_pton==1.0.1
- `bs4==0.0.1` is just a thin meta package; keeping both `bs4` and `beautifulsoup4` is redundant and can confuse dependency resolution.

### External service dependencies / fragility
- DNSDumpster scraping relies on HTML structure and CSRF token extraction; any site change will break results. (DNSDumpsterAPI.py)
- Crimeflare database URL is hardcoded to `https://cf.ozeliurs.com/ipout`; if the site changes or is down, the scan fails. (cloudfail.py:257-259)
- Cloudflare subnet update only fetches IPv4 ranges (`https://www.cloudflare.com/ips-v4`), so IPv6 coverage is missing. (cloudfail.py:250)
- TOR check uses `http://ipinfo.io/ip` (plain HTTP); this can be intercepted or blocked. (cloudfail.py:289)

### Data issues
- `data/ipout` is required at runtime but is not present in the repo; it is fetched dynamically. If update fails, crimeflare scan will break. (cloudfail.py:85, 247-260)
- `data/subdomains.txt` contains wildcard entries like `*.blog` which are not valid DNS labels; these will always fail DNS resolution and add noise to scan output. (data/subdomains.txt)
