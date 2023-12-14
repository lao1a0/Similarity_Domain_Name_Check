# !/usr/bin/env python3
# -*- coding: utf-8 -*-
__author__ = 'laolao'
__version__ = '20230526'
__email__ = 'xxx@xxx.com'

import datetime
import whois
import re
import sys
import socket

import fuzzer_plus
from dependent_function import _debug, UrlParser, my_reshape, save_domains

socket.setdefaulttimeout(12.0)

import pandas as pd
import threading
import os
import queue

try:
    import idna
except ImportError as e:
    _debug(e)


    class idna:
        @staticmethod
        def decode(domain):
            return domain.encode().decode('idna')

        @staticmethod
        def encode(domain):
            return domain.encode('idna')

VALID_FQDN_REGEX = re.compile(r'(?=^.{4,253}$)(^((?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z0-9-]{2,63}$)',
                              re.IGNORECASE)  # 有效的FQDN正则表达式
USER_AGENT_STRING = 'Mozilla/5.0 ({} {}-bit) dnstwist/{}'.format(sys.platform, sys.maxsize.bit_length() + 1,
                                                                 __version__)
THREAD_COUNT_DEFAULT = min(32, os.cpu_count() + 4)


def search_whois_async_plus(domains, num=500):
    import asyncio
    import asyncwhois
    __ = []

    async def check(i, semaphore):
        async with semaphore:
            try:
                whoisq = await asyncwhois.aio_whois_domain(i['domain'])
                if whoisq.parser_output['expires'] is not None:
                    i['whois_expires'] = whoisq.parser_output['expires']
                    i['whois_updated'] = whoisq.parser_output['updated']
                    i['whois_created'] = whoisq.parser_output['created']

                    # print(">>", i)
                    __.append(i)
                    # return await i
            except Exception as e:
                pass

    tasks = []
    for _ in domains:
        semaphore = asyncio.Semaphore(num)  # 限制并发量为300
        task = asyncio.ensure_future(check(_, semaphore))
        tasks.append(task)
    # loop = asyncio.new_event_loop()
    # asyncio.set_event_loop(loop)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.gather(*tasks))
    loop.close()
    return __


def search_whois_thread(domains, out=False, tnum=4):
    def __job_whois(domains, q):
        try:
            for i in domains:
                whoisq = whois.whois(i['domain'])
                if whoisq.expiration_date is not None:
                    i['whois_domain_name'] = whoisq.expiration_date
                    q.put(i)
                    # print("<<", i)
        except Exception as e:
            # print(e)
            pass

    q = queue.Queue()
    threads = []  # 线程列表
    data = my_reshape(domains, tnum)
    for i in range(tnum):
        t = threading.Thread(target=__job_whois, args=(data[i], q))
        t.start()
        threads.append(t)
    for thread in threads:
        thread.join()
    new_domains = []
    for _ in range(q.qsize()):
        new_domains.append(q.get())
    if out:
        print("\nwhois过滤域名个数：{}->{}".format(len(domains), len(new_domains)))
    return new_domains


def run(d):
    args = {
        'out': False,
        'domain': d,
        'option_lsh': 'ssdeep',  # 使用LSH算法评估网页相似度: ssdeep
        'threads': 30,
        'num': 200,  # 并发数
        'dns_type': 1,
        'fuzzer_num': 5000,  # 0-np.inf，inf代表输出所有的生成结果
        'threshold_value': 0.7,
        'tld_all': True,
        'fuzzers': [
            #         'bitsquatting', 'vowel-swap', 'cyrillic', 'homoglyph', 'repetition','various', 'replacement'
            'addition',
            'hyphenation',
            'insertion', 'omission',
            'subdomain', 'transposition'
        ],
        'useragent': USER_AGENT_STRING,
        'request_timeout_http': 1.5
    }
    # 1.生成混淆域名
    import time
    t1 = time.time()
    url = UrlParser(args['domain'])
    fuzz = fuzzer_plus.Fuzzer(domain=url.domain, tld_all=args['tld_all'], threshold_value=args['threshold_value'],
                              top=args['fuzzer_num'])
    fuzz.generate(args['fuzzers'])
    domains = list(fuzz.domains_tld)
    print(domains)
    len_fuzz = len(domains)
    _ = min(args['fuzzer_num'], len(domains))
    domains = domains[:_].copy()
    t2 = time.time()
    print("Fuzzer耗时：{:.2f}s".format(t2 - t1))
    save_domains(domains, "{} 2 生成的混淆域名".format(url.domain))
    print(pd.DataFrame(domains))
    fuzz._make_fig(url.domain)

    # 2.域名探测
    t5 = time.time()
    domains = search_whois_async_plus(domains, args['num'])
    t6 = time.time()
    print("whois过滤过滤耗时：{:.2f}s".format(t6 - t5))
    len_lsh = len(domains)
    print(pd.DataFrame(domains))

    sum_time = t6 - t1
    print("程序共计耗时：{:.2f}s".format(t6 - t1))
    banner = '''
    1. 对域名{}进行探索，fuzzer生成{}条域名。
    2. 取前{}条进行whois过滤，得到{}条互联网中存活的域名
    3. 共计耗时：{}s ，超参数设置如下：\n\n{}
    '''.format(url.domain, len_fuzz, min(len_fuzz, args['fuzzer_num']), len_lsh, sum_time, args)
    # print(banner)
    save_domains(domains, "{} 相似域名".format(url.domain))
    save_path = os.path.join(os.path.dirname(__file__), 'file')
    if not os.path.exists(save_path):
        os.makedirs(save_path)
    f_name = os.path.join(save_path, "{}.csv".format(datetime.date.today()))
    dict_ = [d, min(len_fuzz, args['fuzzer_num']), len_lsh, sum_time]
    print(">>", dict_)
    df = pd.DataFrame([dict_])
    df.to_csv(f_name, mode='a', index=False, header=False)
    print("<<文件：{}写入成功".format(f_name))


if __name__ == '__main__':
    import sys

    run(sys.argv[1])
