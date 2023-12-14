# !/usr/bin/env python3
# -*- coding: utf-8 -*-
__author__ = 'laolao'
__version__ = '20230526'
__email__ = 'xxx@xxx.com'

import sys
import time
import datetime
import whois
import re
import sys
import socket
import asyncio
import asyncwhois
import fuzzer_plus
import pandas as pd
import threading
import os
import queue
from dependent_function import _debug, UrlParser, my_reshape, save_domains

socket.setdefaulttimeout(12.0)

try:
    import idna
except ImportError as e:
    class idna:
        @staticmethod
        def decode(domain):
            return domain.encode().decode('idna')

        @staticmethod
        def encode(domain):
            return domain.encode('idna')

VALID_FQDN_REGEX = re.compile(r'(?=^.{4,253}$)(^((?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z0-9-]{2,63}$)',
                              re.IGNORECASE)
USER_AGENT_STRING = 'Mozilla/5.0 ({} {}-bit) dnstwist/{}'.format(sys.platform, sys.maxsize.bit_length() + 1,
                                                                 __version__)
THREAD_COUNT_DEFAULT = min(32, os.cpu_count() + 4)


def search_whois_async_plus(domains, num=500):
    __ = []

    async def check(i, semaphore):
        async with semaphore:
            try:
                whoisq = await asyncwhois.aio_whois_domain(i['domain'])
                if whoisq.parser_output['expires'] is not None:
                    i['whois_expires'] = whoisq.parser_output['expires']
                    i['whois_updated'] = whoisq.parser_output['updated']
                    i['whois_created'] = whoisq.parser_output['created']
                    __.append(i)
            except Exception as e:
                pass

    tasks = []
    for _ in domains:
        semaphore = asyncio.Semaphore(num)
        task = asyncio.ensure_future(check(_, semaphore))
        tasks.append(task)
    # loop = asyncio.new_event_loop()
    # asyncio.set_event_loop(loop)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.gather(*tasks))
    loop.close()
    return __


def run(d):
    args = {
        'out': False,
        'domain': d,
        'option_lsh': 'ssdeep',
        'threads': 30,
        'num': 800,  # 协程数
        'dns_type': 1,
        'fuzzer_num': 5000,
        'threshold_value': (0.18, 1),
        'tld_all': True,
        'fuzzers': [
            'addition',
            'hyphenation',
            'insertion', 'omission', 'replacement',
            'subdomain', 'transposition'
        ],
        'useragent': USER_AGENT_STRING,
        'request_timeout_http': 1.5
    }
    # 1.生成混淆域名
    t1 = time.time()
    url = UrlParser(args['domain'])
    fuzz = fuzzer_plus.Fuzzer(domain=url.domain, tld_all=args['tld_all'], threshold_value=args['threshold_value'],
                              top=args['fuzzer_num'])
    fuzz.generate(args['fuzzers'])
    domains = list(fuzz.domains_tld)
    len_fuzz = len(domains)
    _ = min(args['fuzzer_num'], len(domains))
    domains = domains[:_].copy()

    # 2.域名探测
    domains = search_whois_async_plus(domains, args['num'])
    t6 = time.time()
    len_lsh = len(domains)

    sum_time = t6 - t1
    print("Total program time {:.2f}s".format(t6 - t1))
    save_domains(domains, "{} Similar domain name".format(url.domain))
    save_path = os.path.join(os.path.dirname(__file__), 'file')
    if not os.path.exists(save_path):
        os.makedirs(save_path)
    f_name = os.path.join(save_path, "{}-{}.csv".format(datetime.date.today().year, datetime.date.today().month))
    ___ = [i['domain'] for i in domains]
    dict_ = [d, min(len_fuzz, args['fuzzer_num']), len_lsh, sum_time, ___]
    print(">>", len(___))
    df = pd.DataFrame([dict_])
    df.to_csv(f_name, mode='a', index=False, header=False, encoding='utf-8')
    print("<<File: {} Written successfully".format(f_name))


if __name__ == '__main__':
    run(sys.argv[1])
