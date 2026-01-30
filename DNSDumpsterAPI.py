"""
This is the (unofficial) Python API for dnsdumpster.com Website.
Using this code, you can retrieve subdomains

"""
import requests
import re
import sys
import base64

from bs4 import BeautifulSoup

# Default timeout for HTTP requests (seconds)
REQUEST_TIMEOUT = 15


class DNSDumpsterAPI(object):

    """DNSDumpsterAPI Main Handler"""

    def __init__(self, verbose=False, session=None):
        self.verbose = verbose
        if not session:
            self.session = requests.Session()
        else:
            self.session = session

    def display_message(self, s):
        if self.verbose:
            print('[verbose] %s' % s)

    def _empty_result(self, domain):
        """Return an empty result structure for error cases."""
        return {
            'domain': domain,
            'dns_records': {
                'dns': [],
                'mx': [],
                'txt': [],
                'host': []
            },
            'image_data': None,
            'xls_data': None
        }

    def retrieve_results(self, table):
        res = []
        if table is None:
            return res
        trs = table.findAll('tr')
        for tr in trs:
            tds = tr.findAll('td')
            if len(tds) < 3:
                continue
            pattern_ip = r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
            try:
                ip_matches = re.findall(pattern_ip, tds[1].text)
                if not ip_matches:
                    continue
                ip = ip_matches[0]
                domain = str(tds[0]).split('<br/>')[0].split('>')[1].split('<')[0]
                header = ' '.join(tds[0].text.replace('\n', '').split(' ')[1:])
                reverse_dns_span = tds[1].find('span', attrs={})
                reverse_dns = reverse_dns_span.text if reverse_dns_span else ''

                additional_info = tds[2].text
                country_span = tds[2].find('span', attrs={})
                country = country_span.text if country_span else ''
                autonomous_system = additional_info.split(' ')[0]
                provider = ' '.join(additional_info.split(' ')[1:])
                provider = provider.replace(country, '')
                data = {'domain': domain,
                        'ip': ip,
                        'reverse_dns': reverse_dns,
                        'as': autonomous_system,
                        'provider': provider,
                        'country': country,
                        'header': header}
                res.append(data)
            except (IndexError, AttributeError):
                continue
        return res

    def retrieve_txt_record(self, table):
        res = []
        if table is None:
            return res
        for td in table.findAll('td'):
            res.append(td.text)
        return res


    def search(self, domain):
        dnsdumpster_url = 'https://dnsdumpster.com/'
        res = self._empty_result(domain)

        try:
            req = self.session.get(dnsdumpster_url, timeout=REQUEST_TIMEOUT)
        except requests.exceptions.RequestException as e:
            print("Failed to connect to DNSDumpster: %s" % e, file=sys.stderr)
            return res

        soup = BeautifulSoup(req.content, 'html.parser')
        csrf_inputs = soup.findAll('input', attrs={'name': 'csrfmiddlewaretoken'})
        if not csrf_inputs:
            print("Could not find CSRF token on DNSDumpster", file=sys.stderr)
            return res
        csrf_middleware = csrf_inputs[0]['value']
        self.display_message('Retrieved token: %s' % csrf_middleware)

        cookies = {'csrftoken': csrf_middleware}
        headers = {'Referer': dnsdumpster_url, 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'}
        data = {'csrfmiddlewaretoken': csrf_middleware, 'targetip': domain, 'user': 'free'}

        try:
            req = self.session.post(dnsdumpster_url, cookies=cookies, data=data, headers=headers, timeout=REQUEST_TIMEOUT)
        except requests.exceptions.RequestException as e:
            print("Failed to query DNSDumpster: %s" % e, file=sys.stderr)
            return res

        if req.status_code != 200:
            print(
                "Unexpected status code from {url}: {code}".format(
                    url=dnsdumpster_url, code=req.status_code),
                file=sys.stderr,
            )
            return res

        if 'There was an error getting results' in req.content.decode('utf-8'):
            print("There was an error getting results", file=sys.stderr)
            return res

        soup = BeautifulSoup(req.content, 'html.parser')
        tables = soup.findAll('table')

        res['domain'] = domain
        res['dns_records'] = {}
        res['dns_records']['dns'] = self.retrieve_results(tables[0] if len(tables) > 0 else None)
        res['dns_records']['mx'] = self.retrieve_results(tables[1] if len(tables) > 1 else None)
        res['dns_records']['txt'] = self.retrieve_txt_record(tables[2] if len(tables) > 2 else None)
        res['dns_records']['host'] = self.retrieve_results(tables[3] if len(tables) > 3 else None)

        # Network mapping image
        try:
            tmp_url = 'https://dnsdumpster.com/static/map/{}.png'.format(domain)
            image_data = base64.b64encode(self.session.get(tmp_url, timeout=REQUEST_TIMEOUT).content)
        except:
            image_data = None
        res['image_data'] = image_data

        # XLS hosts.
        # eg. tsebo.com-201606131255.xlsx
        try:
            pattern = r'/static/xls/' + re.escape(domain) + r'-[0-9]{12}\.xlsx'
            xls_matches = re.findall(pattern, req.content.decode('utf-8'))
            if xls_matches:
                xls_url = 'https://dnsdumpster.com' + xls_matches[0]
                xls_data = base64.b64encode(self.session.get(xls_url, timeout=REQUEST_TIMEOUT).content)
            else:
                xls_data = None
        except Exception:
            xls_data = None
        res['xls_data'] = xls_data

        return res
