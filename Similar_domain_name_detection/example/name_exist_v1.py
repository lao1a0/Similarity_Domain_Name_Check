# !/usr/bin/env python3
# -*- coding: utf-8 -*-
__author__ = 'laolao'
__version__ = '20230526'
__email__ = 'xxx@xxx.com'

import contextlib
import urllib

import requests
import whois
from setuptools.package_index import user_agent
import re
import sys
import socket

import fuzzer_plus
from dependent_function import _debug, UrlOpener, UrlParser, my_reshape, save_domains, domain_tld

socket.setdefaulttimeout(12.0)

import pandas as pd
import threading
import os
import queue

try:
    import tlsh

    MODULE_TLSH = True
except ImportError as e:
    _debug(e)
    MODULE_TLSH = False

try:
    import ssdeep

    MODULE_SSDEEP = True
except ImportError as e:
    _debug(e)
    try:
        import ppdeep as ssdeep

        MODULE_SSDEEP = True
    except ImportError as e:
        _debug(e)
        MODULE_SSDEEP = False

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


def search_status_code(domains, request_timeout, tnum=4):
    def __job_status_code(domains, q):
        for _ in domains:
            url = "http://{}".format(_['domain'])
            urls = "https://{}".format(_['domain'])
            try:
                r = requests.get(url, timeout=request_timeout)
                rs = requests.get(urls, timeout=request_timeout)
                print("> {} 状态码 {}".format(url, r.status_code), end='\t')
                print("{} 状态码 {}".format(urls, rs.status_code))
                if (r.status_code in {200, 301}) or (rs.status_code in {200, 301}):
                    q.put(_)
            except:
                pass

    q = queue.Queue()
    threads = []  # 线程列表
    data = my_reshape(domains, tnum)
    for i in range(tnum):
        t = threading.Thread(target=__job_status_code, args=(data[i], q))
        t.start()
        threads.append(t)
    for thread in threads:
        thread.join()
    new_domains = []
    for _ in range(q.qsize()):
        new_domains.append(q.get())
    print("\n状态码过滤域名个数：{}->{}".format(len(domains), len(new_domains)))
    return new_domains


def search_dns(domains, _type=1, tnum=4):
    ''':cvar
    _type：控制查询级别，默认查询A记录
        1：A
        2: NS
        3: MX
        4+: AAAA
    A记录，将主机名转换为IP地址；[默认]
    MX记录，邮件交换记录，定义邮件服务器的域名；
    NS记录，标记区域的域名服务器及授权子域；
    AAAA记录，ipv6
    '''
    print('Fuzzer后生成的域名：\n')
    print(pd.DataFrame(domains))
    domains = list(domains)
    from dns.resolver import Resolver
    import dns.rdatatype
    resolv = Resolver()
    if hasattr(resolv, 'resolve'):
        resolve = resolv.resolve
    else:
        resolve = resolv.query

    def __answer_to_list(_, _type):
        ''':cvar 输入域名，输出对应的dns记录'''
        try:
            if _type == 2:
                _re = resolve(idna.encode(_).decode(), rdtype=dns.rdatatype.NS)
            elif _type == 3:
                _re = resolve(idna.encode(_).decode(), rdtype=dns.rdatatype.MX)
            elif _type >= 4:
                _re = resolve(idna.encode(_).decode(), rdtype=dns.rdatatype.AAAA)
            else:
                _re = resolve(idna.encode(_).decode(), rdtype=dns.rdatatype.A)
            _ = []
            for i in _re:
                for j in str(i).split('\n'):
                    _.append(j.split(' ')[-1])
            return _
        except:
            print('>{} 解析结果：Check no record'.format(_))
            return []

    def __job_search_dns(domains, q):
        for _ in domains:
            ip_list = __answer_to_list(_['domain'], _type)
            if len(ip_list):  # 没有记录的直接过滤掉
                _['dns_record'] = ','.join(list(set(ip_list)))
                print('>{} 解析结果：{}'.format(_['domain'], _['dns_record']))
                q.put(_)

    q = queue.Queue()
    threads = []  # 线程列表
    data = my_reshape(domains, tnum)
    for i in range(tnum):
        t = threading.Thread(target=__job_search_dns, args=(data[i], q))
        t.start()
        threads.append(t)
    for thread in threads:
        thread.join()
    new_domains = []
    for _ in range(q.qsize()):
        new_domains.append(q.get())
    print("\nDNS查询过滤域名个数：{}->{}".format(len(domains), len(new_domains)))
    print(pd.DataFrame(new_domains))
    return new_domains


def __job_LSH_alg(domains, lsh_init, request_time_out, option_lsh, q):
    for _ in domains:
        try:
            r = UrlOpener(UrlParser(_['domain']).full_uri(),
                          timeout=request_time_out,
                          headers={'user-agent': user_agent},
                          verify=False)
            # print(r.url)
        except Exception as e:
            if "11001" not in str(e):
                print(">{}查询出错：{}".format(_['domain'], e))
                _['LSH_score'] = str(e)
                q.put(_)
        else:
            _['LSH_score'] = -1  # 默认值 -1
            if option_lsh == 'ssdeep':
                lsh_curr = ssdeep.hash(r.normalized_content)
                if lsh_curr not in (None, '3::'):
                    _['LSH_score'] = ssdeep.compare(lsh_init, lsh_curr)
            elif option_lsh == 'tlsh':
                lsh_curr = tlsh.hash(r.normalized_content)
                if lsh_curr not in (None, '', 'TNULL'):
                    _['LSH_score'] = int(100 - (min(tlsh.diff(lsh_init, lsh_curr), 300) / 3))
            print('>{}的LSH得分：{} {}'.format(_['domain'], _['LSH_score'], r.url))
            q.put(_)


def LSH_alg(url_raw, domains, request_timeout, user_agent, option_lsh='ssdeep', tnum=4):
    print('\n将要进行LSH检测的域名：\n')
    print(pd.DataFrame(domains))
    try:
        r = UrlOpener(UrlParser(url_raw).full_uri(),
                      timeout=request_timeout,
                      headers={'user-agent': user_agent},
                      verify=False)
    except Exception as e:
        print(e)
    else:
        if option_lsh == 'ssdeep':
            lsh_init = ssdeep.hash(r.normalized_content)
        else:
            lsh_init = tlsh.hash(r.normalized_content)

        q = queue.Queue()
        threads = []  # 线程列表
        data = my_reshape(domains, tnum)

        for i in range(tnum):
            t = threading.Thread(target=__job_LSH_alg, args=(data[i], lsh_init, request_timeout, option_lsh, q))
            t.start()
            threads.append(t)
        for thread in threads:
            thread.join()
        new_domains = []
        for _ in range(q.qsize()):
            new_domains.append(q.get())
        return new_domains


def main(args):
    url = UrlParser(args['domain'])
    fuzz = fuzzer_plus.Fuzzer(domain=url.domain, tld_all=args['tld_all'], threshold_value=args['threshold_value'],
                              top=args['fuzzer_num'], tnum=args['threads'])
    fuzz.generate(fuzzers=args['fuzzers'])
    domains = list(fuzz.domains)
    # print(domains)
    domains = search_status_code(domains, args['request_timeout_http'], args['threads'])
    save_domains(domains, "生成的混淆域名")
    fuzz._make_fig(url.domain)
    domains = search_dns(domains, _type=args['dns_type'], tnum=args['threads'])
    save_domains(domains, "DNS过滤后的混淆域名")
    domains = LSH_alg(args['domain'], domains, args['request_timeout_http'], args['useragent'], args['option_lsh'])
    save_domains(domains, "LSH过滤后的混淆域名")
    print(pd.DataFrame(domains))


def search_whois_async(domains):
    import asyncio
    async def check(i, semaphore):
        async with semaphore:
            try:
                whoisq = whois.whois(i['domain'])
                if whoisq.expiration_date is not None:
                    i['whois_domain_name'] = whoisq.expiration_date
                    print(i)
                    return await i
            except Exception as e:
                print(e)

    loop = asyncio.get_event_loop()
    tasks = []
    for _ in domains:
        semaphore = asyncio.Semaphore(500)  # 限制并发量为300
        task = asyncio.ensure_future(check(_, semaphore))
        tasks.append(task)
    result = loop.run_until_complete(asyncio.gather(*tasks))
    loop.close()
    return result


def search_whois_async_plus(domains, num=500):
    import asyncio
    import asyncwhois
    import nest_asyncio
    nest_asyncio.apply()
    __ = []

    async def check(i, semaphore):
        async with semaphore:
            try:
                whoisq = await asyncwhois.aio_whois_domain(i['domain'])
                if whoisq.parser_output['expires'] is not None:
                    i['whois_expires'] = whoisq.parser_output['expires']
                    print(">>", i)
                    __.append(i)
                    # return await i
            except Exception as e:
                print(e)

    tasks = []
    for _ in domains:
        semaphore = asyncio.Semaphore(num)  # 限制并发量为300
        task = asyncio.ensure_future(check(_, semaphore))
        tasks.append(task)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.gather(*tasks))
    # loop.close()
    return __


def search_whois_thread(domains, tnum=4):
    def __job_whois(domains, q):
        try:
            for i in domains:
                whoisq = whois.whois(i['domain'])
                if whoisq.expiration_date is not None:
                    i['whois_domain_name'] = whoisq.expiration_date
                    q.put(i)
                    print("<<", i)
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
    print("\nwhois过滤域名个数：{}->{}".format(len(domains), len(new_domains)))
    return new_domains


def run(d):
    args = {
        'domain': d,
        'option_lsh': 'ssdeep',  # 使用LSH算法评估网页相似度: ssdeep
        'threads': 30,
        'num': 200,  # 并发数
        'dns_type': 1,
        'fuzzer_num': 5000,  # 0-np.inf，inf代表输出所有的生成结果
        'threshold_value': 0.15,
        'tld_all': True,
        'fuzzers': [
            #         'bitsquatting', 'vowel-swap', 'cyrillic', 'homoglyph', 'repetition','various'
            'addition',
            'hyphenation',
            'insertion', 'omission', 'replacement',
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
    len_fuzz = len(domains)
    _ = min(args['fuzzer_num'], len(domains))
    domains = domains[:_].copy()
    t2 = time.time()
    print("Fuzzer耗时：{:.2f}s".format(t2 - t1))
    save_domains(domains, "{} 1 生成的混淆域名".format(url.domain))
    print(pd.DataFrame(domains))
    fuzz._make_fig(url.domain)

    # 2.域名探测
    t5 = time.time()
    domains = search_whois_async_plus(domains, args['num'])
    save_domains(domains, "{} 2 whois过滤后的混淆域名".format(url.domain))
    t6 = time.time()
    print("whois过滤过滤耗时：{:.2f}s".format(t6 - t5))
    len_lsh = len(domains)
    print(pd.DataFrame(domains))

    sum_time = t6 - t1
    print("程序共计耗时：{:.2f}s".format(t6 - t1))
    banner = '''
    1. 对域名{}进行探索，fuzzer生成{}条域名。
    2. 取前{}条进行whois过滤，得到{}条互联网中存活的域名
    3. 共计耗时：{}s /  数据库共计耗时：301.51s+【查询时间】，超参数设置如下：\n\n{}
    '''.format(url.domain, len_fuzz, min(args['fuzzer_num'], len_fuzz), len_lsh, sum_time, args)
    print(banner)


if __name__ == '__main__':
    run('ktea.com')