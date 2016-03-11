#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
from logging import getLogger, StreamHandler, Formatter, INFO
from argparse import ArgumentParser
import urllib3
import certifi
import re

LOGGER = getLogger('xfeutil')
CONSOLE = StreamHandler()
CONSOLE.setLevel(INFO)
FORMATTER = Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
CONSOLE.setFormatter(FORMATTER)
LOGGER.addHandler(CONSOLE)
LOGGER.setLevel(INFO)

class HttpManagerFactory(object):
    u"Factory for HTTP manager of urllib3"
    @classmethod
    def manager(cls, proxy=None):
        kw = {'cert_reqs': 'CERT_REQUIRED', 'ca_certs': certifi.where()}
        return urllib3.PoolManager(**kw) if proxy is None else urllib3.ProxyManager(proxy, **kw)

class XfeManager(object):
    XFORCE_URL = 'https://exchange.xforce.ibmcloud.com/'
    ENDPOINT_URL = 'https://api.xforce.ibmcloud.com:443'
    RATE_THRESHOLD = 3
    SLEEP_SEC = 10

    CATEGORY = '' # CATEGORY should be declare in the concrete classes.

    def __init__(self, http, apikey, password, locale='en-US'):
        self.http = http
        self._headers = urllib3.util.make_headers(
            basic_auth='%s:%s' % (apikey, password))
        self._headers['Accept'] = 'application/json'
        self._headers['Accept-Language'] = locale
        self.logger = getLogger('xfeutil')

    def _full_url(self, sub_url):
        return '%s/%s' % (self.ENDPOINT_URL, sub_url.lstrip('^/'))

    def _get(self, sub_url):
        res = self.http.request('GET', self._full_url(sub_url),
                                headers=self._headers)
        if res.status != 200:
            try:
                msg = '%d %s' % (res.status, json.loads(res.data)['error'])
            except ValueError:
                msg = '%d %s' % (res.status, res.data)
            self.logger.error(msg)
            if res.status == 404: # Not found.
                return {}
            else:
                raise IOError(msg)
        headers = res.headers
        if 'x-ratelimit-limit' in headers:
            remaining = int(headers['x-ratelimit-remaining'])
            if remaining < self.RATE_THRESHOLD:
                self.logger.info('Waiting...')
                time.sleep(self.SLEEP_SEC)
            self.logger.debug('Rate limits: %d/%d'
                              % (remaining, int(headers['x-ratelimit-limit'])))
        return json.loads(res.data)

    def q(self, query):
        u'''CATEGORY should be declare in the concrete classes.'''
        return self._get('%s/%s' % (self.CATEGORY, query))

class IPReputation(XfeManager):
    u'Returns the IP report for the given IP'
    CATEGORY = 'ipr'

class Whois(XfeManager):
    u'Returns an information about the given host address'
    CATEGORY = 'whois'

class Malware(XfeManager):
    u'Returns a malware report for the given md5'
    CATEGORY = 'malware'

class Signatures(XfeManager):
    u'Returns the signature details associated with the given pamId'
    CATEGORY = 'signatures'

class Vulnerabilities(XfeManager):
    u'Returns the vulnerability associated with the given xfdbid'
    CATEGORY = 'vulnerabilities'

class Url(XfeManager):
    u'Returns the URL report for the given URL.'
    CATEGORY = 'url'

class XfeManagerFactory(object):
    CANDIDATES = {
        'ipreputation': IPReputation,
        'signatures': Signatures,
        'malware': Malware,
        'vulnerabilities': Vulnerabilities,
        'url': Url,
        'whois': Whois,
    }
    @classmethod
    def generate(cls, keyword):
        return cls.CANDIDATES[keyword]

def generate_queries(args=[], filename=None):
    for q in args:
        yield q
    if filename is None:
        raise StopIteration()
    IGNORE_LINE = re.compile('(^\s+$|^\s*#)')
    with open(filename, 'r') as f:
        while True:
            line = f.readline()
            if not line:
                raise StopIteration()
            if IGNORE_LINE.match(line):
                continue
            yield line.strip()

if __name__ == '__main__':
    MODES = XfeManagerFactory.CANDIDATES.keys()
    PARSER = ArgumentParser(description="Utility for IBM X-Force Exchange")
    PARSER.add_argument('mode', metavar='MODE',
                        choices=MODES, help='mode %s' % MODES)
    PARSER.add_argument('queries', nargs='*', metavar='QUERY', help='Queries')
    PARSER.add_argument('-k', '--apikey', dest='apikey', help='API key')
    PARSER.add_argument('-p', '--password', dest='password',
                        help='API password')
    PARSER.add_argument('--proxy', dest='proxy', help='Proxy server')
    PARSER.add_argument('-f', '--file', dest='file',
                        help='File included list of queries')
    PARSER.add_argument('--locale', dest='locale', default='en-US',
                        help='Locale for responses of IBM X-Force Exchange')

    ARGS = PARSER.parse_args()
    APIKEY = ARGS.apikey if ARGS.apikey else os.environ['IBMXFE_APIKEY']
    PASSWORD = ARGS.password if ARGS.password else os.environ['IBMXFE_PASSWORD']

    HTTP = HttpManagerFactory.manager(ARGS.proxy)
    CLAZZ = XfeManagerFactory.generate(ARGS.mode)
    XFE = CLAZZ(HTTP, APIKEY, PASSWORD, locale=ARGS.locale)

    queries = generate_queries(args=ARGS.queries, filename=ARGS.file)
    print(json.dumps([XFE.q(q) for q in queries], sort_keys=True, indent=2,
                     ensure_ascii=False).encode("utf-8"))
