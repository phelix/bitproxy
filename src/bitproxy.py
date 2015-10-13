#!/usr/bin/env python

"""
bitproxy
phelix / Namecoin Project 2014, 2015

forked from PyMiProxy
Nadeem Douba / PyMiProxy Project 2012

License: GPL


how to install proxy generated certificate on Windows
    Firefox
        Tools->Options->Advanced->Certificates->View_Certificates->Authorities->
            Import...->ca.crt->"Trust this CA to identify websites"->OK->OK
           (it might then be necessary to wait a couple of seconds or even restart)
    Chrome/Internet Explorer/System
        Open ca.crt in file explorer->install_certificate...->local-machine->continue->
            yes->this storage->browse...->trusted root CA->ok->continue->finish->OK->OK

todo
    clean & refactor (modular with internetarchive/warcprox and certauth?)
    use sha256 d/ fingerprints
    instructions: how to add cert to firefox / system
    firefox plugin to add cert?
    firefox plugin to only proxy .bit/tls:.bit
    or use pac file for proxy config only for .bit/tls:.bit (served via bottle?)
    instructions: note about browser "certificate caching"
    test python 2.7.9 - should bail
    ! safes browsing history - can not simply be deleted without conflicting with browser cache
    improve caching (also for .bit?)
    pass on remote cert data in local cert
    occasional SSLEOFError: EOF occurred in violation of protocol (_ssl.c:590)  --> TLSv1 (SO)
    automatic certificate install for firefox via certutil or alternative?
    unclear error during client launch
    better error messages on browser error page
"""

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from urlparse import urlparse, urlunparse, ParseResult
from SocketServer import ThreadingMixIn
from httplib import HTTPResponse
from tempfile import gettempdir
import os
from ssl import wrap_socket
import ssl

import socket
import time
import thread
import traceback
import namerpc
import json

import hashlib

from re import compile
from sys import argv

from OpenSSL.crypto import (X509Extension, X509, dump_privatekey, dump_certificate, load_certificate, load_privatekey,
                            PKey, TYPE_RSA, X509Req)
from OpenSSL.SSL import FILETYPE_PEM

DNSCACHETIME = 3600 * 24


def ensure_dirs(path):
    try:
        os.makedirs(path)
    except OSError:
        if not os.path.isdir(path):
            raise

class CertificateAuthority(object):

    def __init__(self, ca_file, cache_dir=gettempdir(), filetype=FILETYPE_PEM):
        ensure_dirs(cache_dir)
        self.ca_file = ca_file
        self.cache_dir = cache_dir
        self.filetype = filetype
        self._serial = self._get_serial()
        if not os.path.exists(ca_file):
            self._generate_ca()
        else:
            self._read_ca(ca_file)

    def _get_serial(self):
        s = 1
        for c in filter(lambda x: x.startswith('.pymp_'), os.listdir(self.cache_dir)):
            c = load_certificate(self.filetype, open(os.path.sep.join([self.cache_dir, c])).read())
            sc = c.get_serial_number()
            if sc > s:
                s = sc
            del c
        return s

    def _generate_ca(self):
        # Generate key
        self.key = PKey()
        self.key.generate_key(TYPE_RSA, 2048)

        # Generate certificate
        self.cert = X509()
        self.cert.set_version(3)
        self.cert.set_serial_number(1)
        self.cert.get_subject().CN = 'Namecoin .bit proxy'
        self.cert.gmtime_adj_notBefore(0)
        self.cert.gmtime_adj_notAfter(315360000)
        self.cert.set_issuer(self.cert.get_subject())
        self.cert.set_pubkey(self.key)
        self.cert.add_extensions([
            X509Extension("basicConstraints", True, "CA:TRUE, pathlen:0"),
            X509Extension("keyUsage", True, "keyCertSign, cRLSign"),
            X509Extension("subjectKeyIdentifier", False, "hash", subject=self.cert),
            ])
        self.cert.sign(self.key, "sha256")

        with open(self.ca_file, 'wb+') as f:
            f.write(dump_privatekey(self.filetype, self.key))
            f.write(dump_certificate(self.filetype, self.cert))

        # export for Windows
        with open("ca.crt", 'wb+') as f:
            f.write(dump_certificate(self.filetype, self.cert))

    def _read_ca(self, file):
        self.cert = load_certificate(self.filetype, open(file).read())
        self.key = load_privatekey(self.filetype, open(file).read())

    def __getitem__(self, cn):
        cnp = os.path.sep.join([self.cache_dir, '.pymp_%s.pem' % cn])
        if not os.path.exists(cnp):
            # create certificate
            key = PKey()
            key.generate_key(TYPE_RSA, 2048)

            # Generate CSR
            req = X509Req()
            req.get_subject().CN = cn
            req.set_pubkey(key)
            req.sign(key, 'sha256')

            # Sign CSR
            cert = X509()
            cert.set_subject(req.get_subject())
            cert.set_serial_number(self.serial)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(31536000)
            cert.set_issuer(self.cert.get_subject())
            cert.set_pubkey(req.get_pubkey())
            cert.sign(self.key, 'sha256')

            with open(cnp, 'wb+') as f:
                f.write(dump_privatekey(self.filetype, key))
                f.write(dump_certificate(self.filetype, cert))

        return cnp

    @property
    def serial(self):
        self._serial += 1
        return self._serial


class UnsupportedSchemeException(Exception):
    pass

class BitSocket(socket.socket):
    rpc = namerpc.CoinRpc(connectionType="nmcontrol")  # threading/sync?
    original_connect = socket.socket.connect
    ipTable = {}
    def connect(self, (hostname, port)):
        try:
            ip = None            
            if not hostname.endswith(".bit"):  # legacy domains
                ip, fresh = BitSocket.get_ip(hostname)
                try:
                    socket.socket.connect(self, (ip, port))
                except:
                    if not fresh:
                        ip, fresh = BitSocket.get_ip(hostname, force=True)
                        #print "ip, port, fresh:", ip, type(port), fresh
                        socket.socket.connect(self, (ip, port))
                    else:
                        raise
            else:  # .bit                
                r = self.rpc.call("dns", ["getIp4", hostname])
                ip = str(json.loads(r["reply"])[0])
                socket.socket.connect(self, (ip, port))
        except:
            print "###### exception remote connect: ", hostname, ip, port
            traceback.print_exc()
            raise

    @classmethod
    def fetch_ip(cls, hostname):
        ip = socket.gethostbyname(hostname)
        cls.ipTable[hostname] = (ip, time.time())
        return ip

    @classmethod
    def get_ip(cls, hostname, force=False, block=False):
        """returns (ip, cached)"""
        try:
            ipData = cls.ipTable[hostname]
            seen = True
        except KeyError:
            seen = False

        if seen and ipData == None:  # wait for other connection to return
            c = 0
            while c < 100:  # we are only so patient
                time.sleep(0.05)
                c += 1
                if cls.ipTable[hostname]:
                    return cls.ipTable[hostname], False
            else:  # while loop ended without return
                seen = False

        if not seen or force:  # actually fetch
            if not seen or block:
                cls.ipTable[hostname] = None
            ip = BitSocket.fetch_ip(hostname)
            return ip, False

        # update cache?
        if time.time() - ipData[1] > DNSCACHETIME:  # time for background udpate?
            thread.start_new_thread(BitSocket.fetch_ip(hostname, force=True, block=False))

        # cached
        return ipData[0], True


class ProxyHandler(BaseHTTPRequestHandler):
    rpc = namerpc.CoinRpc(connectionType="nmcontrol")  # threading/sync?
    r = compile(r'http://[^/]+(/?.*)(?i)')

    def __init__(self, request, client_address, server):
        self.is_connect = False
        self.remote_context = None
        self.local_context = None
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def _connect_to_host(self):
        # Get hostname and port to connect to
        if self.is_connect:
            self.hostname, self.port = self.path.split(':')
        else:
            u = urlparse(self.path)
            if u.scheme != 'http':
                raise UnsupportedSchemeException('Unknown scheme %s' % repr(u.scheme))
            self.hostname = u.hostname
            self.port = u.port or 80
            self.path = urlunparse(
                ParseResult(
                    scheme='',
                    netloc='',
                    params=u.params,
                    path=u.path or '/',
                    query=u.query,
                    fragment=u.fragment
                )
            )
        self.port = int(self.port)

        # Connect to destination
        self._proxy_sock = BitSocket()
        self._proxy_sock.settimeout(10)
        self._proxy_sock.connect((self.hostname, self.port))

        # Wrap socket if SSL is required
        if self.is_connect:
            if not self.remote_context:
                self.remote_context = ssl.create_default_context()
                self.remote_context.check_hostname = False
            self._proxy_sock = self.remote_context.wrap_socket(self._proxy_sock,
                                                               server_hostname=self.hostname)
            if self.hostname.endswith(".bit"):
                r = self.rpc.call("dns", ["getFingerprint", self.hostname])
                nmcFpr = json.loads(r["reply"])[0].lower().replace(":", "")
                #print "nmcFpr:", nmcFpr, self.hostname

                remoteFpr = hashlib.sha1(self._proxy_sock.getpeercert(True)).hexdigest()
                if not remoteFpr == nmcFpr:
                    raise Exception("tls fingerprint mismatch")

            else:
                ssl.match_hostname(self._proxy_sock.getpeercert(),
                                   self._proxy_sock.server_hostname)
 
    def _transition_to_ssl(self):
        if not self.local_context:
            certfile=self.server.ca[self.path.split(':')[0]]
            self.local_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
            self.local_context.load_cert_chain(certfile=certfile)
            if "RC4" in ssl._DEFAULT_CIPHERS.upper().replace("!RC4", ""):
                raise Exception("Python version seems to old (contains RC4 cipher).")
        self.request = self.local_context.wrap_socket(self.request, server_side=True)

    def do_CONNECT(self):
        self.is_connect = True
        try:
            # Connect to destination first
            self._connect_to_host()

            # If successful, let's do this!
            self.send_response(200, 'Connection established')
            self.end_headers()
            #self.request.sendall('%s 200 Connection established\r\n\r\n' % self.request_version)

            self._transition_to_ssl()
        except Exception, e:
            try:
                print "hostname:", self.hostname,
                print " port:", self.port
            except:
                print "-"            
            traceback.print_exc()
            self.send_error(500, str(e))
            return

        # Reload!
        self.setup()
        self.ssl_host = 'https://%s' % self.path
        self.handle_one_request()


    def do_COMMAND(self):

        # Is this an SSL tunnel?
        if not self.is_connect:
            try:
                # Connect to destination
                self._connect_to_host()
            except Exception, e:
                self.send_error(500, str(e))
                return
            # Extract path

        # Build request
        req = '%s %s %s\r\n' % (self.command, self.path, self.request_version)

        # Add headers to the request
        req += '%s\r\n' % self.headers

        # Append message body if present to the request
        if 'Content-Length' in self.headers:
            req += self.rfile.read(int(self.headers['Content-Length']))

        # Send it down the pipe!
        self._proxy_sock.sendall(req)

        # Parse response
        h = HTTPResponse(self._proxy_sock)
        h.begin()

        # Get rid of the pesky header
        del h.msg['Transfer-Encoding']

        # Time to relay the message across
        res = '%s %s %s\r\n' % (self.request_version, h.status, h.reason)
        res += '%s\r\n' % h.msg
        res += h.read()

        # Let's close off the remote end
        h.close()
        self._proxy_sock.close()

        # Relay the message
        self.request.sendall(res)


    def __getattr__(self, item):
        if item.startswith('do_'):
            return self.do_COMMAND

    def log_message(self, format, *args):
        """Replace default function to suppress logging."""
        return


class MitmProxy(HTTPServer):
    def __init__(self, server_address=('', 8080), RequestHandlerClass=ProxyHandler,
                 bind_and_activate=True, ca_file='ca.pem'):
        HTTPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.ca = CertificateAuthority(ca_file, cache_dir="certs")


class AsyncMitmProxy(ThreadingMixIn, MitmProxy):
    pass


if __name__ == '__main__':
    proxy = AsyncMitmProxy(server_address=('', 8084))

    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        proxy.server_close()

