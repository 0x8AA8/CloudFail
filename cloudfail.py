#!/usr/bin/env python3
import argparse
import re
import sys
import socket
import binascii
import datetime
import json
import socks
import requests
import colorama
import zipfile
import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, quote_plus
from colorama import Fore, Style
from DNSDumpsterAPI import DNSDumpsterAPI
from bs4 import BeautifulSoup
import dns.resolver

# Thread-safe lock for printing and shared state
print_lock = threading.Lock()
seen_ips_lock = threading.Lock()
findings_lock = threading.Lock()

# Valid data sources for --sources flag
VALID_SOURCES = ['crtsh', 'wayback', 'alienvault', 'hackertarget', 'rapiddns', 'threatcrowd', 'urlscan', 'viewdns', 'bing']

# Default timeout for HTTP requests (seconds)
REQUEST_TIMEOUT = 10

# Global state for output modes and findings collection
QUIET_MODE = False
NO_COLOR = False
FINDINGS = []  # Collect findings for JSON output

# Set default socket timeout to prevent hanging
socket.setdefaulttimeout(REQUEST_TIMEOUT)

colorama.init(Style.BRIGHT)


def print_out(data, end='\n'):
    """Print output with optional color and quiet mode support."""
    if QUIET_MODE:
        return
    datetimestr = str(datetime.datetime.strftime(datetime.datetime.now(), '%H:%M:%S'))
    if NO_COLOR:
        # Strip ANSI color codes
        clean_data = re.sub(r'\x1b\[[0-9;]*m', '', data)
        clean_data = re.sub(' +', ' ', clean_data)
        print("[" + datetimestr + "] " + clean_data, end=end)
    else:
        print(Style.NORMAL + "[" + datetimestr + "] " + re.sub(' +', ' ', data) + Style.RESET_ALL,' ', end=end)


def add_finding(finding_type, data):
    """Add a finding to the global findings list for JSON output."""
    with findings_lock:
        FINDINGS.append({
            'type': finding_type,
            'timestamp': datetime.datetime.now().isoformat(),
            **data
        })


def print_ip_only(ip):
    """Print IP only in quiet mode."""
    if QUIET_MODE:
        print(ip)


def ip_in_subnetwork(ip_address, subnetwork):
    (ip_integer, version1) = ip_to_integer(ip_address)
    (ip_lower, ip_upper, version2) = subnetwork_to_ip_range(subnetwork)

    if version1 != version2:
        raise ValueError("incompatible IP versions")

    return (ip_lower <= ip_integer <= ip_upper)


def ip_to_integer(ip_address):
    # try parsing the IP address first as IPv4, then as IPv6
    for version in (socket.AF_INET, socket.AF_INET6):
        try:
            ip_hex = socket.inet_pton(version, ip_address)
            ip_integer = int(binascii.hexlify(ip_hex), 16)

            return ip_integer, 4 if version == socket.AF_INET else 6
        except:
            pass

    raise ValueError("invalid IP address")


def subnetwork_to_ip_range(subnetwork):
    try:
        fragments = subnetwork.split('/')
        network_prefix = fragments[0]
        netmask_len = int(fragments[1])

        # try parsing the subnetwork first as IPv4, then as IPv6
        for version in (socket.AF_INET, socket.AF_INET6):

            ip_len = 32 if version == socket.AF_INET else 128

            try:
                suffix_mask = (1 << (ip_len - netmask_len)) - 1
                netmask = ((1 << ip_len) - 1) - suffix_mask
                ip_hex = socket.inet_pton(version, network_prefix)
                ip_lower = int(binascii.hexlify(ip_hex), 16) & netmask
                ip_upper = ip_lower + suffix_mask

                return (ip_lower,
                        ip_upper,
                        4 if version == socket.AF_INET else 6)
            except:
                pass
    except:
        pass

    raise ValueError("invalid subnetwork")


def dnsdumpster(target):
    print_out(Fore.CYAN + "Testing for misconfigured DNS using dnsdumpster...")

    try:
        res = DNSDumpsterAPI(False).search(target)
    except Exception as e:
        print_out(Fore.RED + "DNSDumpster lookup failed: " + str(e))
        return

    if not res or 'dns_records' not in res:
        print_out(Fore.YELLOW + "No results from DNSDumpster")
        return

    found_any = False

    if res['dns_records'].get('host'):
        for entry in res['dns_records']['host']:
            provider = str(entry.get('provider', ''))
            if "Cloudflare" not in provider:
                found_any = True
                ip = entry.get('ip', '')
                print_out(
                    Style.BRIGHT + Fore.WHITE + "[FOUND:HOST] " + Fore.GREEN + "{domain} {ip} {as} {provider} {country}".format(
                        **entry))
                print_ip_only(ip)
                add_finding('host', {'source': 'dnsdumpster', **entry})

    if res['dns_records'].get('dns'):
        for entry in res['dns_records']['dns']:
            provider = str(entry.get('provider', ''))
            if "Cloudflare" not in provider:
                found_any = True
                ip = entry.get('ip', '')
                print_out(
                    Style.BRIGHT + Fore.WHITE + "[FOUND:DNS] " + Fore.GREEN + "{domain} {ip} {as} {provider} {country}".format(
                        **entry))
                print_ip_only(ip)
                add_finding('dns', {'source': 'dnsdumpster', **entry})

    if res['dns_records'].get('mx'):
        for entry in res['dns_records']['mx']:
            provider = str(entry.get('provider', ''))
            if "Cloudflare" not in provider:
                found_any = True
                ip = entry.get('ip', '')
                print_out(
                    Style.BRIGHT + Fore.WHITE + "[FOUND:MX] " + Fore.GREEN + "{ip} {as} {provider} {domain}".format(
                        **entry))
                print_ip_only(ip)
                add_finding('mx', {'source': 'dnsdumpster', **entry})

    if not found_any:
        print_out(Fore.YELLOW + "No non-Cloudflare records found via DNSDumpster")


def crimeflare(target):
    print_out(Fore.CYAN + "Scanning crimeflare database...")

    with open("data/ipout", "r") as ins:
        crimeFoundArray = []
        for line in ins:
            lineExploded = line.split(" ")
            if lineExploded[1] == args.target:
                crimeFoundArray.append(lineExploded[2])
            else:
                continue
    if (len(crimeFoundArray) != 0):
        for foundIp in crimeFoundArray:
            ip = foundIp.strip()
            print_out(Style.BRIGHT + Fore.WHITE + "[FOUND:IP] " + Fore.GREEN + "" + ip)
            print_ip_only(ip)
            add_finding('crimeflare_ip', {'source': 'crimeflare', 'ip': ip, 'domain': target})
    else:
        print_out("Did not find anything.")


def init(target):
    if args.target:
        print_out(Fore.CYAN + "Fetching initial information from: " + args.target + "...")
    else:
        print_out(Fore.RED + "No target set, exiting")
        sys.exit(1)

    if not os.path.isfile("data/ipout"):
            print_out(Fore.CYAN + "No ipout file found, fetching data")
            update()
            print_out(Fore.CYAN + "ipout file created")

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print_out(Fore.RED + "Domain is not valid, exiting")
        sys.exit(0)

    print_out(Fore.CYAN + "Server IP: " + ip)
    print_out(Fore.CYAN + "Testing if " + args.target + " is on the Cloudflare network...")

    try:
        ifIpIsWithin = inCloudFlare(ip)

        if ifIpIsWithin:
            print_out(Style.BRIGHT + Fore.GREEN + args.target + " is part of the Cloudflare network!")
        else:
            print_out(Fore.RED + args.target + " is not part of the Cloudflare network, quitting...")
            sys.exit(0)
    except ValueError:
        print_out(Fore.RED + "IP address does not appear to be within Cloudflare range, shutting down..")
        sys.exit(0)


def inCloudFlare(ip):
    with open('{}/data/cf-subnet.txt'.format(os.getcwd())) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                if ip_in_subnetwork(ip, line):
                    return True
            except ValueError:
                continue
        return False

def check_for_wildcard(target):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['1.1.1.1', '1.0.0.1']
    resolver.timeout = 5
    resolver.lifetime = 10
    try:
        answer = resolver.resolve('*.' + target)
        choice = ''
        while choice != 'y' and choice != 'n':
            choice = input("A wildcard DNS entry was found. This will result in all subdomains returning an IP. Do you want to scan subdomains anyway? (y/n): ")
        if choice == 'y':
            return False
        else:
            return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return False
    except Exception:
        return False


def load_checkpoint(checkpoint_file):
    """Load processed subdomains from checkpoint file."""
    processed = set()
    if checkpoint_file and os.path.isfile(checkpoint_file):
        try:
            with open(checkpoint_file, 'r') as f:
                for line in f:
                    processed.add(line.strip())
            print_out(Fore.CYAN + "Loaded {} processed subdomains from checkpoint".format(len(processed)))
        except Exception as e:
            print_out(Fore.YELLOW + "Could not load checkpoint: " + str(e))
    return processed


def save_to_checkpoint(checkpoint_file, subdomain):
    """Append a processed subdomain to checkpoint file."""
    if checkpoint_file:
        try:
            with open(checkpoint_file, 'a') as f:
                f.write(subdomain + '\n')
        except Exception:
            pass


def scan_single_subdomain(subdomain, target, seen_ips, skip_dup_ips, checkpoint_file):
    """Scan a single subdomain and return result tuple."""
    result = {
        'subdomain': subdomain,
        'found': False,
        'on_cloudflare': False,
        'ip': None,
        'http_status': 'N/A',
        'skipped': False
    }

    try:
        ip = socket.gethostbyname(subdomain)
        result['ip'] = ip
    except (socket.gaierror, socket.timeout):
        save_to_checkpoint(checkpoint_file, subdomain)
        return result

    # Check for duplicate IP if enabled
    if skip_dup_ips:
        with seen_ips_lock:
            if ip in seen_ips:
                result['skipped'] = True
                save_to_checkpoint(checkpoint_file, subdomain)
                return result
            seen_ips.add(ip)

    try:
        target_http = requests.get("http://" + subdomain, timeout=REQUEST_TIMEOUT)
        result['http_status'] = str(target_http.status_code)
    except requests.exceptions.RequestException:
        result['http_status'] = "N/A"

    try:
        if not inCloudFlare(ip):
            result['found'] = True
        else:
            result['on_cloudflare'] = True
    except ValueError:
        pass

    save_to_checkpoint(checkpoint_file, subdomain)
    return result


def subdomain_scan(target, subdomains_file, threads=1, checkpoint_file="", skip_dup_ips=False):
    """Scan subdomains with optional threading and resume support."""
    if check_for_wildcard(target):
        print_out(Fore.CYAN + "Scanning finished...")
        return

    if subdomains_file:
        subdomainsList = subdomains_file
    else:
        subdomainsList = "subdomains.txt"

    try:
        subdomainsPath = "data/" + subdomainsList

        # Load checkpoint if resuming
        processed = load_checkpoint(checkpoint_file) if checkpoint_file else set()

        # Count total and build subdomain list
        with open(subdomainsPath, "r") as f:
            all_subdomains = ["{}.{}".format(line.strip(), target) for line in f if line.strip()]

        total = len(all_subdomains)
        # Filter out already processed subdomains
        subdomains_to_scan = [s for s in all_subdomains if s not in processed]

        if processed:
            print_out(Fore.CYAN + "Resuming scan: {} of {} already processed".format(len(processed), total))

        num_to_scan = len(subdomains_to_scan)
        if num_to_scan == 0:
            print_out(Fore.CYAN + "All subdomains already processed.")
            return

        print_out(Fore.CYAN + "Scanning {} subdomains ({}) with {} thread(s)...".format(num_to_scan, subdomainsList, threads))

        found_count = 0
        scanned_count = 0
        seen_ips = set()
        progressInterval = max(1, num_to_scan // 100)

        if threads <= 1:
            # Single-threaded (original behavior)
            for subdomain in subdomains_to_scan:
                scanned_count += 1
                if (scanned_count % progressInterval) == 0:
                    print_out(Fore.CYAN + str(round((scanned_count / float(num_to_scan)) * 100.0, 2)) + "% complete", '\r')

                result = scan_single_subdomain(subdomain, target, seen_ips, skip_dup_ips, checkpoint_file)

                if result['skipped']:
                    continue
                if result['ip'] is None:
                    continue

                if result['found']:
                    found_count += 1
                    print_out(
                        Style.BRIGHT + Fore.WHITE + "[FOUND:SUBDOMAIN] " + Fore.GREEN + subdomain + " IP: " + result['ip'] + " HTTP: " + result['http_status'])
                    print_ip_only(result['ip'])
                    add_finding('subdomain', {'source': 'wordlist', 'subdomain': subdomain, 'ip': result['ip'], 'http_status': result['http_status'], 'on_cloudflare': False})
                elif result['on_cloudflare']:
                    print_out(
                        Style.BRIGHT + Fore.WHITE + "[FOUND:SUBDOMAIN] " + Fore.RED + subdomain + " ON CLOUDFLARE NETWORK!")
        else:
            # Multi-threaded scanning
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(scan_single_subdomain, sd, target, seen_ips, skip_dup_ips, checkpoint_file): sd for sd in subdomains_to_scan}

                for future in as_completed(futures):
                    scanned_count += 1
                    if (scanned_count % progressInterval) == 0:
                        with print_lock:
                            print_out(Fore.CYAN + str(round((scanned_count / float(num_to_scan)) * 100.0, 2)) + "% complete", '\r')

                    try:
                        result = future.result()
                    except Exception:
                        continue

                    if result['skipped']:
                        continue
                    if result['ip'] is None:
                        continue

                    with print_lock:
                        if result['found']:
                            found_count += 1
                            print_out(
                                Style.BRIGHT + Fore.WHITE + "[FOUND:SUBDOMAIN] " + Fore.GREEN + result['subdomain'] + " IP: " + result['ip'] + " HTTP: " + result['http_status'])
                            print_ip_only(result['ip'])
                            add_finding('subdomain', {'source': 'wordlist', 'subdomain': result['subdomain'], 'ip': result['ip'], 'http_status': result['http_status'], 'on_cloudflare': False})
                        elif result['on_cloudflare']:
                            print_out(
                                Style.BRIGHT + Fore.WHITE + "[FOUND:SUBDOMAIN] " + Fore.RED + result['subdomain'] + " ON CLOUDFLARE NETWORK!")

        if found_count == 0:
            print_out(Fore.CYAN + "Scanning finished, we did not find anything, sorry...")
        else:
            print_out(Fore.CYAN + "Scanning finished, found {} non-Cloudflare hosts.".format(found_count))

    except IOError:
        print_out(Fore.RED + "Subdomains file does not exist in data directory, aborting scan...")
        sys.exit(1)

def update():
    print_out(Fore.CYAN + "Just checking for updates, please wait...")
    print_out(Fore.CYAN + "Updating CloudFlare subnet...")
    if(args.tor == False):
        headers = {'User-Agent': 'Mozilla/5.0 (Windows; U; Windows NT 5.1; it; rv:1.8.1.11) Gecko/20071127 Firefox/2.0.0.11'}
        r = requests.get("https://www.cloudflare.com/ips-v4", headers=headers, cookies={'__cfduid': "d7c6a0ce9257406ea38be0156aa1ea7a21490639772"}, stream=True, timeout=REQUEST_TIMEOUT)
        with open('data/cf-subnet.txt', 'wb') as fd:
            for chunk in r.iter_content(4000):
                fd.write(chunk)
    else:
        print_out(Fore.RED + Style.BRIGHT+"Unable to fetch CloudFlare subnet while TOR is active")
    print_out(Fore.CYAN + "Updating Crimeflare database...")
    r = requests.get("https://cf.ozeliurs.com/ipout", stream=True, timeout=REQUEST_TIMEOUT)
    with open('data/ipout', 'wb') as fd:
        for chunk in r.iter_content(4000):
            fd.write(chunk)


def query_crtsh(target):
    """Query crt.sh for certificate transparency subdomains."""
    print_out(Fore.CYAN + "Querying crt.sh for certificate subdomains...")
    subdomains = set()

    try:
        url = "https://crt.sh/?q=%.{}&output=json".format(target)
        response = requests.get(url, timeout=REQUEST_TIMEOUT * 2)

        if response.status_code != 200:
            print_out(Fore.YELLOW + "crt.sh returned status {}".format(response.status_code))
            return subdomains

        try:
            data = response.json()
        except ValueError:
            print_out(Fore.YELLOW + "crt.sh returned invalid JSON")
            return subdomains

        for entry in data:
            name = entry.get('name_value', '')
            # Handle multiple names separated by newlines
            for subdomain in name.split('\n'):
                subdomain = subdomain.strip().lower()
                # Remove wildcard prefix
                if subdomain.startswith('*.'):
                    subdomain = subdomain[2:]
                # Validate it's a subdomain of target
                if subdomain.endswith('.' + target) or subdomain == target:
                    subdomains.add(subdomain)

        print_out(Fore.GREEN + "crt.sh found {} unique subdomains".format(len(subdomains)))

    except requests.exceptions.RequestException as e:
        print_out(Fore.YELLOW + "crt.sh query failed: " + str(e))
    except Exception as e:
        print_out(Fore.YELLOW + "crt.sh error: " + str(e))

    return subdomains


def query_wayback(target):
    """Query Wayback Machine CDX for historical subdomains."""
    print_out(Fore.CYAN + "Querying Wayback Machine for historical URLs...")
    subdomains = set()

    try:
        # CDX API to get URLs matching the domain
        url = "https://web.archive.org/cdx/search/cdx?url=*.{}&output=json&fl=original&collapse=urlkey&limit=5000".format(target)
        response = requests.get(url, timeout=REQUEST_TIMEOUT * 3)

        if response.status_code != 200:
            print_out(Fore.YELLOW + "Wayback Machine returned status {}".format(response.status_code))
            return subdomains

        try:
            data = response.json()
        except ValueError:
            print_out(Fore.YELLOW + "Wayback Machine returned invalid JSON")
            return subdomains

        # Skip header row if present
        for row in data[1:] if len(data) > 1 else []:
            if row:
                url_str = row[0] if isinstance(row, list) else row
                try:
                    parsed = urlparse(url_str)
                    hostname = parsed.netloc.lower()
                    # Remove port if present
                    if ':' in hostname:
                        hostname = hostname.split(':')[0]
                    # Validate it's a subdomain of target
                    if hostname.endswith('.' + target) or hostname == target:
                        subdomains.add(hostname)
                except Exception:
                    continue

        print_out(Fore.GREEN + "Wayback Machine found {} unique subdomains".format(len(subdomains)))

        # Polite rate limiting
        time.sleep(1)

    except requests.exceptions.RequestException as e:
        print_out(Fore.YELLOW + "Wayback Machine query failed: " + str(e))
    except Exception as e:
        print_out(Fore.YELLOW + "Wayback Machine error: " + str(e))

    return subdomains


def query_alienvault(target):
    """Query AlienVault OTX for passive DNS data."""
    print_out(Fore.CYAN + "Querying AlienVault OTX for passive DNS...")
    subdomains = set()

    try:
        url = "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns".format(target)
        headers = {'User-Agent': 'CloudFail/1.0'}
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT * 2)

        if response.status_code != 200:
            print_out(Fore.YELLOW + "AlienVault OTX returned status {}".format(response.status_code))
            return subdomains

        try:
            data = response.json()
        except ValueError:
            print_out(Fore.YELLOW + "AlienVault OTX returned invalid JSON")
            return subdomains

        passive_dns = data.get('passive_dns', [])
        for entry in passive_dns:
            hostname = entry.get('hostname', '').strip().lower()
            if hostname.endswith('.' + target) or hostname == target:
                subdomains.add(hostname)

        print_out(Fore.GREEN + "AlienVault OTX found {} unique subdomains".format(len(subdomains)))

        # Polite rate limiting
        time.sleep(1)

    except requests.exceptions.RequestException as e:
        print_out(Fore.YELLOW + "AlienVault OTX query failed: " + str(e))
    except Exception as e:
        print_out(Fore.YELLOW + "AlienVault OTX error: " + str(e))

    return subdomains


def query_hackertarget(target):
    """Query HackerTarget hostsearch for subdomains."""
    print_out(Fore.CYAN + "Querying HackerTarget for subdomains...")
    subdomains = set()

    try:
        url = "https://api.hackertarget.com/hostsearch/?q={}".format(target)
        response = requests.get(url, timeout=REQUEST_TIMEOUT)

        if response.status_code != 200:
            print_out(Fore.YELLOW + "HackerTarget returned status {}".format(response.status_code))
            return subdomains

        text = response.text.strip()

        # Check for error messages
        if text.startswith('error') or 'API count exceeded' in text:
            print_out(Fore.YELLOW + "HackerTarget: " + text[:100])
            return subdomains

        for line in text.split('\n'):
            if ',' in line:
                hostname = line.split(',')[0].strip().lower()
                if hostname.endswith('.' + target) or hostname == target:
                    subdomains.add(hostname)

        print_out(Fore.GREEN + "HackerTarget found {} unique subdomains".format(len(subdomains)))

    except requests.exceptions.RequestException as e:
        print_out(Fore.YELLOW + "HackerTarget query failed: " + str(e))
    except Exception as e:
        print_out(Fore.YELLOW + "HackerTarget error: " + str(e))

    return subdomains


def query_rapiddns(target):
    """Query RapidDNS for subdomains via web scraping."""
    print_out(Fore.CYAN + "Querying RapidDNS for subdomains...")
    subdomains = set()

    try:
        url = "https://rapiddns.io/subdomain/{}?full=1".format(target)
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT * 2)

        if response.status_code != 200:
            print_out(Fore.YELLOW + "RapidDNS returned status {}".format(response.status_code))
            return subdomains

        soup = BeautifulSoup(response.text, 'html.parser')

        # Find the table with subdomains
        table = soup.find('table', {'class': 'table'})
        if table:
            for row in table.find_all('tr'):
                cells = row.find_all('td')
                if cells:
                    subdomain = cells[0].get_text().strip().lower()
                    if subdomain.endswith('.' + target) or subdomain == target:
                        subdomains.add(subdomain)

        print_out(Fore.GREEN + "RapidDNS found {} unique subdomains".format(len(subdomains)))

        # Polite rate limiting
        time.sleep(1)

    except requests.exceptions.RequestException as e:
        print_out(Fore.YELLOW + "RapidDNS query failed: " + str(e))
    except Exception as e:
        print_out(Fore.YELLOW + "RapidDNS error: " + str(e))

    return subdomains


def query_threatcrowd(target):
    """Query ThreatCrowd API for subdomains."""
    print_out(Fore.CYAN + "Querying ThreatCrowd for subdomains...")
    subdomains = set()

    try:
        url = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}".format(target)
        headers = {'User-Agent': 'CloudFail/1.0'}
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT * 2)

        if response.status_code != 200:
            print_out(Fore.YELLOW + "ThreatCrowd returned status {}".format(response.status_code))
            return subdomains

        try:
            data = response.json()
        except ValueError:
            print_out(Fore.YELLOW + "ThreatCrowd returned invalid JSON")
            return subdomains

        # Extract subdomains
        for subdomain in data.get('subdomains', []):
            subdomain = subdomain.strip().lower()
            if subdomain.endswith('.' + target) or subdomain == target:
                subdomains.add(subdomain)

        print_out(Fore.GREEN + "ThreatCrowd found {} unique subdomains".format(len(subdomains)))

        # Polite rate limiting (ThreatCrowd has strict limits)
        time.sleep(2)

    except requests.exceptions.RequestException as e:
        print_out(Fore.YELLOW + "ThreatCrowd query failed: " + str(e))
    except Exception as e:
        print_out(Fore.YELLOW + "ThreatCrowd error: " + str(e))

    return subdomains


def query_urlscan(target):
    """Query URLScan.io search API for subdomains."""
    print_out(Fore.CYAN + "Querying URLScan.io for subdomains...")
    subdomains = set()

    try:
        url = "https://urlscan.io/api/v1/search/?q=domain:{}".format(target)
        headers = {'User-Agent': 'CloudFail/1.0'}
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT * 2)

        if response.status_code != 200:
            print_out(Fore.YELLOW + "URLScan.io returned status {}".format(response.status_code))
            return subdomains

        try:
            data = response.json()
        except ValueError:
            print_out(Fore.YELLOW + "URLScan.io returned invalid JSON")
            return subdomains

        for result in data.get('results', []):
            page = result.get('page', {})
            domain = page.get('domain', '').strip().lower()
            if domain.endswith('.' + target) or domain == target:
                subdomains.add(domain)

        print_out(Fore.GREEN + "URLScan.io found {} unique subdomains".format(len(subdomains)))

        # Polite rate limiting
        time.sleep(1)

    except requests.exceptions.RequestException as e:
        print_out(Fore.YELLOW + "URLScan.io query failed: " + str(e))
    except Exception as e:
        print_out(Fore.YELLOW + "URLScan.io error: " + str(e))

    return subdomains


def query_viewdns(target):
    """Query ViewDNS IP history via web scraping."""
    print_out(Fore.CYAN + "Querying ViewDNS for IP history...")
    subdomains = set()

    try:
        url = "https://viewdns.info/iphistory/?domain={}".format(target)
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT * 2)

        if response.status_code != 200:
            print_out(Fore.YELLOW + "ViewDNS returned status {}".format(response.status_code))
            return subdomains

        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all tables and look for IP history data
        for table in soup.find_all('table'):
            for row in table.find_all('tr'):
                cells = row.find_all('td')
                if len(cells) >= 2:
                    # First cell might contain IP, check for valid IP pattern
                    ip_text = cells[0].get_text().strip()
                    # Look for historical IPs and report them
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_text):
                        # This is IP history - print it as a finding
                        print_out(Style.BRIGHT + Fore.WHITE + "[FOUND:HISTORY] " + Fore.YELLOW + target + " -> " + ip_text)

        # ViewDNS doesn't provide subdomains, just IP history
        # Add the target itself to be scanned
        subdomains.add(target)

        print_out(Fore.GREEN + "ViewDNS IP history check complete")

        # Polite rate limiting
        time.sleep(1)

    except requests.exceptions.RequestException as e:
        print_out(Fore.YELLOW + "ViewDNS query failed: " + str(e))
    except Exception as e:
        print_out(Fore.YELLOW + "ViewDNS error: " + str(e))

    return subdomains


def query_bing(target):
    """Query Bing search for subdomains."""
    print_out(Fore.CYAN + "Querying Bing search for subdomains...")
    subdomains = set()

    try:
        # Search for subdomains using site: operator
        query = quote_plus("site:*.{}".format(target))
        url = "https://www.bing.com/search?q={}&count=50".format(query)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT * 2)

        if response.status_code != 200:
            print_out(Fore.YELLOW + "Bing returned status {}".format(response.status_code))
            return subdomains

        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract URLs from search results
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('http'):
                try:
                    parsed = urlparse(href)
                    hostname = parsed.netloc.lower()
                    # Remove port if present
                    if ':' in hostname:
                        hostname = hostname.split(':')[0]
                    # Validate it's a subdomain of target
                    if hostname.endswith('.' + target) or hostname == target:
                        subdomains.add(hostname)
                except Exception:
                    continue

        # Also check cite elements which often contain URLs
        for cite in soup.find_all('cite'):
            text = cite.get_text().strip().lower()
            # Extract hostname from cite text
            if '/' in text:
                hostname = text.split('/')[0]
            else:
                hostname = text
            # Remove protocol if present
            hostname = hostname.replace('https://', '').replace('http://', '')
            if hostname.endswith('.' + target) or hostname == target:
                subdomains.add(hostname)

        print_out(Fore.GREEN + "Bing found {} unique subdomains".format(len(subdomains)))

        # Polite rate limiting
        time.sleep(2)

    except requests.exceptions.RequestException as e:
        print_out(Fore.YELLOW + "Bing query failed: " + str(e))
    except Exception as e:
        print_out(Fore.YELLOW + "Bing error: " + str(e))

    return subdomains


def gather_subdomains_from_sources(target, sources):
    """Gather subdomains from enabled external sources."""
    all_subdomains = set()

    source_functions = {
        'crtsh': query_crtsh,
        'wayback': query_wayback,
        'alienvault': query_alienvault,
        'hackertarget': query_hackertarget,
        'rapiddns': query_rapiddns,
        'threatcrowd': query_threatcrowd,
        'urlscan': query_urlscan,
        'viewdns': query_viewdns,
        'bing': query_bing,
    }

    for source in sources:
        source = source.strip().lower()
        if source in source_functions:
            found = source_functions[source](target)
            all_subdomains.update(found)
        else:
            print_out(Fore.YELLOW + "Unknown source: {}".format(source))

    return all_subdomains


def scan_discovered_subdomains(target, subdomains, threads=1, skip_dup_ips=False):
    """Scan subdomains discovered from external sources with optional threading."""
    if not subdomains:
        return

    # Filter out the base domain
    subdomains_to_scan = [s for s in subdomains if s != target]

    if not subdomains_to_scan:
        return

    print_out(Fore.CYAN + "Scanning {} subdomains from external sources with {} thread(s)...".format(len(subdomains_to_scan), threads))

    found_count = 0
    scanned_count = 0
    seen_ips = set()
    num_to_scan = len(subdomains_to_scan)
    progressInterval = max(1, num_to_scan // 20)

    if threads <= 1:
        # Single-threaded
        for subdomain in sorted(subdomains_to_scan):
            scanned_count += 1
            if (scanned_count % progressInterval) == 0:
                print_out(Fore.CYAN + str(round((scanned_count / float(num_to_scan)) * 100.0, 2)) + "% complete", '\r')

            result = scan_single_subdomain(subdomain, target, seen_ips, skip_dup_ips, "")

            if result['skipped'] or result['ip'] is None:
                continue

            if result['found']:
                found_count += 1
                print_out(
                    Style.BRIGHT + Fore.WHITE + "[FOUND:SUBDOMAIN] " + Fore.GREEN + subdomain + " IP: " + result['ip'] + " HTTP: " + result['http_status'])
                print_ip_only(result['ip'])
                add_finding('subdomain', {'source': 'external', 'subdomain': subdomain, 'ip': result['ip'], 'http_status': result['http_status'], 'on_cloudflare': False})
            elif result['on_cloudflare']:
                print_out(
                    Style.BRIGHT + Fore.WHITE + "[FOUND:SUBDOMAIN] " + Fore.RED + subdomain + " ON CLOUDFLARE NETWORK!")
    else:
        # Multi-threaded
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_single_subdomain, sd, target, seen_ips, skip_dup_ips, ""): sd for sd in subdomains_to_scan}

            for future in as_completed(futures):
                scanned_count += 1
                if (scanned_count % progressInterval) == 0:
                    with print_lock:
                        print_out(Fore.CYAN + str(round((scanned_count / float(num_to_scan)) * 100.0, 2)) + "% complete", '\r')

                try:
                    result = future.result()
                except Exception:
                    continue

                if result['skipped'] or result['ip'] is None:
                    continue

                with print_lock:
                    if result['found']:
                        found_count += 1
                        print_out(
                            Style.BRIGHT + Fore.WHITE + "[FOUND:SUBDOMAIN] " + Fore.GREEN + result['subdomain'] + " IP: " + result['ip'] + " HTTP: " + result['http_status'])
                        print_ip_only(result['ip'])
                        add_finding('subdomain', {'source': 'external', 'subdomain': result['subdomain'], 'ip': result['ip'], 'http_status': result['http_status'], 'on_cloudflare': False})
                    elif result['on_cloudflare']:
                        print_out(
                            Style.BRIGHT + Fore.WHITE + "[FOUND:SUBDOMAIN] " + Fore.RED + result['subdomain'] + " ON CLOUDFLARE NETWORK!")

    if found_count == 0:
        print_out(Fore.CYAN + "External source scan complete, no non-Cloudflare hosts found.")
    else:
        print_out(Fore.CYAN + "External source scan complete, found {} non-Cloudflare hosts.".format(found_count))


# END FUNCTIONS

logo = """\
  ____ _                 _ _____     _ _  -  ____  _    _   _ ____
 / ___| | ___  _   _  __| |  ___|_ _(_) | - |  _ \\| |  | | | / ___|
| |   | |/ _ \\| | | |/ _` | |_ / _` | | | - | |_) | |  | | | \\___ \\
| |___| | (_) | |_| | (_| |  _| (_| | | | - |  __/| |__| |_| |___) |
 \\____|_|\\___/ \\__,_|\\__,_|_|  \\__,_|_|_| - |_|   |_____|\\___/|____/
      v1.0.5+  by Usui

"""

print(Fore.RED + Style.BRIGHT + logo + Fore.RESET)
datestr = str(datetime.datetime.strftime(datetime.datetime.now(), '%d/%m/%Y'))
print_out("Initializing CloudFail - the date is: " + datestr)

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", help="target url of website", type=str)
parser.add_argument("-T", "--tor", dest="tor", action="store_true", help="enable TOR routing")
parser.add_argument("-u", "--update", dest="update", action="store_true", help="update databases")
parser.add_argument("-s", "--subdomains", help="name of alternate subdomains list stored in the data directory", type=str)
parser.add_argument("--sources", help="comma-separated list of external sources: crtsh,wayback,alienvault,hackertarget,rapiddns,threatcrowd,urlscan,viewdns,bing", type=str, default="")
parser.add_argument("--threads", help="number of concurrent threads for scanning (default: 1)", type=int, default=1)
parser.add_argument("--resume", help="resume scan from checkpoint file", type=str, default="")
parser.add_argument("--skip-duplicate-ips", dest="skip_dup_ips", action="store_true", help="skip subdomains that resolve to already-seen IPs")
# Output and reporting options
parser.add_argument("--output", help="write JSON results to file", type=str, default="")
parser.add_argument("--quiet", "-q", dest="quiet", action="store_true", help="quiet mode - print found IPs only")
parser.add_argument("--no-color", dest="no_color", action="store_true", help="disable colored output")
# Phase toggles
parser.add_argument("--no-subdomain", dest="no_subdomain", action="store_true", help="skip subdomain scanning")
parser.add_argument("--no-dns", dest="no_dns", action="store_true", help="skip DNSDumpster scan")
parser.add_argument("--no-crimeflare", dest="no_crimeflare", action="store_true", help="skip Crimeflare database scan")
# Timeout control
parser.add_argument("--timeout", help="request timeout in seconds (default: 10)", type=int, default=10)
parser.set_defaults(tor=False)
parser.set_defaults(update=False)
parser.set_defaults(skip_dup_ips=False)
parser.set_defaults(quiet=False)
parser.set_defaults(no_color=False)
parser.set_defaults(no_subdomain=False)
parser.set_defaults(no_dns=False)
parser.set_defaults(no_crimeflare=False)

args = parser.parse_args()

# Set global output modes
QUIET_MODE = args.quiet
NO_COLOR = args.no_color

# Override timeout if specified
if args.timeout != 10:
    REQUEST_TIMEOUT = args.timeout
    socket.setdefaulttimeout(REQUEST_TIMEOUT)

# Reinitialize colorama if no-color is set
if NO_COLOR:
    colorama.deinit()

if args.tor is True:
    ipcheck_url = 'http://ipinfo.io/ip'
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', 9050)
    socket.socket = socks.socksocket
    try:
        tor_ip = requests.get(ipcheck_url, timeout=REQUEST_TIMEOUT)
        tor_ip = str(tor_ip.text)

        print_out(Fore.WHITE + Style.BRIGHT + "TOR connection established!")
        print_out(Fore.WHITE + Style.BRIGHT + "New IP: " + tor_ip)

    except requests.exceptions.RequestException as e:
        print_out(Fore.RED + "TOR connection failed: " + str(e))
        sys.exit(1)

if args.update is True:
    update()

exit_code = 2  # Default: no findings

try:

    # Initialize CloudFail
    init(args.target)

    # Scan DNSdumpster.com (unless --no-dns)
    if not args.no_dns:
        dnsdumpster(args.target)
    else:
        print_out(Fore.CYAN + "Skipping DNSDumpster scan (--no-dns)")

    # Scan Crimeflare database (unless --no-crimeflare)
    if not args.no_crimeflare:
        crimeflare(args.target)
    else:
        print_out(Fore.CYAN + "Skipping Crimeflare scan (--no-crimeflare)")

    # Query external sources if enabled
    if args.sources:
        sources_list = [s.strip() for s in args.sources.split(',') if s.strip()]
        invalid = [s for s in sources_list if s.lower() not in VALID_SOURCES]
        if invalid:
            print_out(Fore.YELLOW + "Warning: Unknown sources ignored: " + ", ".join(invalid))
        valid_sources = [s for s in sources_list if s.lower() in VALID_SOURCES]
        if valid_sources:
            discovered = gather_subdomains_from_sources(args.target, valid_sources)
            if discovered:
                scan_discovered_subdomains(args.target, discovered, args.threads, args.skip_dup_ips)

    # Scan subdomains with or without TOR (unless --no-subdomain)
    if not args.no_subdomain:
        subdomain_scan(args.target, args.subdomains, args.threads, args.resume, args.skip_dup_ips)
    else:
        print_out(Fore.CYAN + "Skipping subdomain scan (--no-subdomain)")

    # Determine exit code based on findings
    if FINDINGS:
        exit_code = 0  # Success with findings

    # Write JSON output if requested
    if args.output:
        output_data = {
            'target': args.target,
            'scan_date': datetime.datetime.now().isoformat(),
            'findings': FINDINGS
        }
        try:
            with open(args.output, 'w') as f:
                json.dump(output_data, f, indent=2)
            print_out(Fore.GREEN + "Results written to " + args.output)
        except Exception as e:
            print_out(Fore.RED + "Failed to write output file: " + str(e))

except KeyboardInterrupt:
    sys.exit(0)

sys.exit(exit_code)
