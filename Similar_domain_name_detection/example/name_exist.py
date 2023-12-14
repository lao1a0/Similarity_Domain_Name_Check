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


def url_survival(domains, lsh_init):
    ''':cvar
    备份：修改ssdeep的走的是并发
    本次扫描共探测289个url的存活情况，耗时146.52s
    '''
    import asyncio
    # def _normalize(req):
    #     content = b' '.join(req.content.split())  # 将content中的多个空格替换为一个空格
    #     mapping = dict({
    #         b'(action|src|href)="[^"]+"': lambda m: m.group(0).split(b'=')[0] + b'=""',
    #         b'url\([^)]+\)': b'url()',
    #     })
    #     for pattern, repl in mapping.items():
    #         content = re.sub(pattern, repl, content, flags=re.IGNORECASE)
    #     return content

    async def check(i, semaphore):
        # try:
        async with semaphore:
            try:
                whoisq = whois.whois(i['domain'])
                if whoisq.expiration_date is not None:
                    i['whois_domain_name'] = whoisq.expiration_date
                    print(i)
            except Exception as e:
                print(e)
            return await i
            # async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=50, ssl=False)) as session:
            #     # print("http://" + _['domain'].strip())
            #     async with session.get("http://" + _['domain'].strip()) as r:
            #         print("http://" + _['domain'].strip() + "    " + str(r.status) + str(type(r.status)))
            #         if int(r.status) in [200, 301, 203]:
            #             _['LSH_score'] = -1  # 默认值 -1
            #             if option_lsh == 'ssdeep':
            #                 lsh_curr = ssdeep.hash(_normalize(r))
            #                 if lsh_curr not in (None, '3::'):
            #                     _['LSH_score'] = ssdeep.compare(lsh_init, lsh_curr)
            #             elif option_lsh == 'tlsh':
            #                 lsh_curr = tlsh.hash(_normalize(r))
            #                 if lsh_curr not in (None, '', 'TNULL'):
            #                     _['LSH_score'] = int(100 - (min(tlsh.diff(lsh_init, lsh_curr), 300) / 3))
            #             print('>{}的LSH得分：{}'.format(_['domain'], _['LSH_score']))
            #             # url_success.append(domains['domain'])
            #             print(">>", _)
            #             return await _
        # except Exception as e:
        #     print(e)
        #     pass

    loop = asyncio.get_event_loop()
    tasks = []
    for _ in domains:
        semaphore = asyncio.Semaphore(500)  # 限制并发量为300
        task = asyncio.ensure_future(check(_, semaphore))
        tasks.append(task)
    result = loop.run_until_complete(asyncio.gather(*tasks))
    return result
    # run("url.txt")
    # loop.run_until_complete(asyncio.wait(tasks))
    # save_result()


def search_whois(domains, tnum=4):
    def __job_whois(domains, q):
        try:
            for i in domains:
                whoisq = whois.whois(i['domain'])
                if whoisq.expiration_date is not None:
                    i['whois_domain_name'] = whoisq.expiration_date
                    q.put(i)
                    print("<<",i)
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


if __name__ == '__main__':
    _ = [{'fuzzer': 'addition', 'domain': 'www.nttu.edu.tw', 'score': 1.5},
         {'fuzzer': 'addition', 'domain': 'www.ntut.edu.tw', 'score': 1.5},
         {'fuzzer': 'addition', 'domain': 'www.tntu.edu.tw', 'score': 1.5},
         {'fuzzer': 'addition', 'domain': 'www.untu.edu.tw', 'score': 1.5},
         {'fuzzer': 'addition', 'domain': 'www.nntu.edu.tw', 'score': 1.5},
         {'fuzzer': 'addition', 'domain': 'www.nutu.edu.tw', 'score': 1.5},
         {'fuzzer': 'addition', 'domain': 'www.ntnu.edu.tw', 'score': 1.5},
         {'fuzzer': 'addition', 'domain': 'www.ntun.edu.tw', 'score': 1.5},
         {'fuzzer': 'addition', 'domain': 'www.ntuu.edu.tw', 'score': 1.5},
         {'fuzzer': 'addition', 'domain': 'www.tun.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.6tu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nku.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ntz.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.xtu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nt1.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nti.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ndu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.3tu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ltu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.n7u.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nt0.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nbu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.n4u.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nta.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.dtu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ytu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.5tu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ntw.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.1tu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.qtu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ncu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nt8.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.btu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.npu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ntk.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.jtu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.unt.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ntq.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ztu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nju.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.mtu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.n2u.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ntv.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nqu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nts.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.etu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ntd.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nt9.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.0tu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nt2.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.atu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.n0u.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.9tu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nru.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.neu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nwu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.n9u.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ntx.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nfu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.htu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ktu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.otu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.tnu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ntj.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nhu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nth.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ntc.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ntb.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.n5u.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.2tu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.n3u.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.rtu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nto.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.itu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.n1u.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nt7.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ftu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.vtu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ntg.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nut.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ntf.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.gtu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.n6u.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.stu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.7tu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.n8u.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ntr.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nmu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.niu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ntl.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nau.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nte.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.n-u.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ctu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nlu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ntm.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nt5.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nxu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ntp.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.4tu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nou.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ngu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nzu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.8tu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nyu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ptu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nvu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nty.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nsu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.ntu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nt3.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.utn.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.wtu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nt6.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'addition', 'domain': 'www.nt4.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.btu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.htu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.jtu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.mtu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.btu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.htu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.jtu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.mtu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.btu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.htu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.jtu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.n6u.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nyu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.ngu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nfu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nru.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.n5u.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.n6u.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nzu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.ngu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nfu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nru.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.n5u.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.n6u.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nyu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.ngu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nfu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nru.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.n5u.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nt8.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nti.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.ntj.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nth.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nty.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nt7.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nt8.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nti.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.ntj.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nth.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.ntz.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nt7.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nt8.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nti.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.ntj.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nth.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nty.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'replacement', 'domain': 'www.nt7.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'transposition', 'domain': 'www.nut.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'transposition', 'domain': 'www.tnu.edu.tw', 'score': 1.584962500721156},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntw.com.tw', 'score': 2.495602923729013},
         {'fuzzer': 'tld-swap', 'domain': 'www.wtu.com.tw', 'score': 2.495602923729013},
         {'fuzzer': 'tld-swap', 'domain': 'www.nwu.edu.in', 'score': 2.610577243331642},
         {'fuzzer': 'tld-swap', 'domain': 'www.nwu.edu.cn', 'score': 2.610577243331642},
         {'fuzzer': 'tld-swap', 'domain': 'www.nwu.nhs.uk', 'score': 2.610577243331642},
         {'fuzzer': 'tld-swap', 'domain': 'www.mtu.com.tw', 'score': 2.610577243331642},
         {'fuzzer': 'tld-swap', 'domain': 'www.otu.com.tw', 'score': 2.610577243331642},
         {'fuzzer': 'tld-swap', 'domain': 'www.nto.com.tw', 'score': 2.610577243331642},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntc.com.tw', 'score': 2.610577243331643},
         {'fuzzer': 'tld-swap', 'domain': 'www.ctu.com.tw', 'score': 2.610577243331643},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntm.com.tw', 'score': 2.610577243331643},
         {'fuzzer': 'tld-swap', 'domain': 'www.nwu.com.tw', 'score': 2.6384600665861555},
         {'fuzzer': 'tld-swap', 'domain': 'www.ndu.edu.in', 'score': 2.699513850319966},
         {'fuzzer': 'tld-swap', 'domain': 'www.neu.edu.in', 'score': 2.699513850319966},
         {'fuzzer': 'tld-swap', 'domain': 'www.niu.edu.in', 'score': 2.699513850319966},
         {'fuzzer': 'tld-swap', 'domain': 'www.ndu.edu.cn', 'score': 2.699513850319966},
         {'fuzzer': 'tld-swap', 'domain': 'www.ncu.edu.cn', 'score': 2.699513850319966},
         {'fuzzer': 'tld-swap', 'domain': 'www.neu.edu.cn', 'score': 2.699513850319966},
         {'fuzzer': 'tld-swap', 'domain': 'www.nku.nhs.uk', 'score': 2.699513850319966},
         {'fuzzer': 'tld-swap', 'domain': 'www.nhu.nhs.uk', 'score': 2.699513850319966},
         {'fuzzer': 'tld-swap', 'domain': 'www.nsu.nhs.uk', 'score': 2.699513850319966},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntw.website', 'score': 2.7329145639793975},
         {'fuzzer': 'tld-swap', 'domain': 'www.wtu.website', 'score': 2.7329145639793975},
         {'fuzzer': 'tld-swap', 'domain': 'www.nwu.wedding', 'score': 2.732914563979398},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntw.wedding', 'score': 2.7329145639793984},
         {'fuzzer': 'tld-swap', 'domain': 'www.nttu.com.tw', 'score': 2.7395722619867224},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntut.com.tw', 'score': 2.7395722619867224},
         {'fuzzer': 'tld-swap', 'domain': 'www.tntu.com.tw', 'score': 2.7395722619867224},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntw.com.vn', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nwu.com.vn', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nwu.com.ua', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.wtu.com.ua', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntw.com.tr', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.wtu.com.tr', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nwu.org.uk', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.wtu.org.uk', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nwu.edu.pk', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.wtu.edu.pk', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntw.edu.in', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.wtu.edu.in', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nwu.gov.uk', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.wtu.gov.uk', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nwu.edu.my', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.wtu.edu.my', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntw.com.np', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nwu.com.np', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntw.org.nz', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nwu.org.nz', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nwu.com.au', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.wtu.com.au', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntw.edu.cn', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.wtu.edu.cn', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntw.nhs.uk', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.wtu.nhs.uk', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntw.org.in', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nwu.org.in', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.tun.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.6tu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntz.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.xtu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nt1.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nti.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.3tu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ltu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nt0.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nta.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.dtu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ytu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.5tu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.1tu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ncu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.qtu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nt8.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.btu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntk.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.jtu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.unt.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntq.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ztu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntv.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nts.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.etu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntd.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nt9.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.0tu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nt2.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.atu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.9tu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntx.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.htu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ktu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.tnu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntj.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nth.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntb.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.2tu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.rtu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.itu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nt7.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ftu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.vtu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntg.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nut.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntf.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.gtu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.stu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.7tu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntr.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nmu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntl.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nte.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nt5.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntp.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.4tu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nou.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.8tu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ptu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nty.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.ntu.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.utn.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nt3.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nt6.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nt4.com.tw', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.nwu.edu.ph', 'score': 2.7534343861887853},
         {'fuzzer': 'tld-swap', 'domain': 'www.wtu.edu.ph', 'score': 2.7534343861887853}]
    import time

    t1 = time.time()
    print(len(_))
    r = search_whois(_, tnum=30)
    print(len(r))
    print(r)
    # try:
    #     r = UrlOpener('https://www.baidu.com',
    #                   timeout=5,
    #                   headers={'user-agent': user_agent},
    #                   verify=False)
    #     lsh_init = ssdeep.hash(r.normalized_content)
    #     res = url_survival(_, lsh_init)
    #     print(res)
    # except Exception as e:
    #     print(e)
    t2 = time.time()
    print("{:.2f}".format(t2 - t1))
