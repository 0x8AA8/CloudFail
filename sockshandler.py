#!/usr/bin/env python3
"""
SocksiPy + urllib handler

version: 0.4
author: e<e@tr0ll.in>

This module provides a Handler which you can use with urllib to allow it to
tunnel your connection through a socks.sockssocket socket, without monkey
patching the original socket.
"""
import ssl
import urllib.request as urllib2
import http.client as httplib

import socks  # $ pip install PySocks

def merge_dict(a, b):
    d = a.copy()
    d.update(b)
    return d

class SocksiPyConnection(httplib.HTTPConnection):
    def __init__(self, proxytype, proxyaddr, proxyport=None, rdns=True, username=None, password=None, *args, **kwargs):
        self.proxyargs = (proxytype, proxyaddr, proxyport, rdns, username, password)
        httplib.HTTPConnection.__init__(self, *args, **kwargs)

    def connect(self):
        self.sock = socks.socksocket()
        self.sock.setproxy(*self.proxyargs)
        if type(self.timeout) in (int, float):
            self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))

class SocksiPyConnectionS(httplib.HTTPSConnection):
    def __init__(self, proxytype, proxyaddr, proxyport=None, rdns=True, username=None, password=None, *args, **kwargs):
        self.proxyargs = (proxytype, proxyaddr, proxyport, rdns, username, password)
        httplib.HTTPSConnection.__init__(self, *args, **kwargs)

    def connect(self):
        sock = socks.socksocket()
        sock.setproxy(*self.proxyargs)
        if type(self.timeout) in (int, float):
            sock.settimeout(self.timeout)
        sock.connect((self.host, self.port))
        # Use SSLContext instead of deprecated ssl.wrap_socket
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if self.key_file and self.cert_file:
            context.load_cert_chain(self.cert_file, self.key_file)
        self.sock = context.wrap_socket(sock, server_hostname=self.host)

class SocksiPyHandler(urllib2.HTTPHandler, urllib2.HTTPSHandler):
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kw = kwargs
        urllib2.HTTPHandler.__init__(self)

    def http_open(self, req):
        def build(host, port=None, timeout=0, **kwargs):
            kw = merge_dict(self.kw, kwargs)
            conn = SocksiPyConnection(*self.args, host=host, port=port, timeout=timeout, **kw)
            return conn
        return self.do_open(build, req)

    def https_open(self, req):
        def build(host, port=None, timeout=0, **kwargs):
            kw = merge_dict(self.kw, kwargs)
            conn = SocksiPyConnectionS(*self.args, host=host, port=port, timeout=timeout, **kw)
            return conn
        return self.do_open(build, req)

if __name__ == "__main__":
    import sys
    try:
        port = int(sys.argv[1])
    except (ValueError, IndexError):
        port = 9050
    opener = urllib2.build_opener(SocksiPyHandler(socks.PROXY_TYPE_SOCKS5, "localhost", port))
    print("HTTP: " + opener.open("http://httpbin.org/ip").read().decode())
    print("HTTPS: " + opener.open("https://httpbin.org/ip").read().decode())
