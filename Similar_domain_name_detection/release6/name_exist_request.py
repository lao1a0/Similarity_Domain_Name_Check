# !/usr/bin/env python3
# -*- coding: utf-8 -*-
import asyncio
import aiohttp
import asyncwhois
import queue
import threading
from queue import Queue
import datetime
import re
import sys
import socket
import whois
import fuzzer_plus
from dependent_function import _debug, UrlParser, save_domains, my_reshape
import asyncio
import aiohttp
import asyncwhois

socket.setdefaulttimeout(12.0)
import pandas as pd
import os

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
                                                                 "")
THREAD_COUNT_DEFAULT = min(32, os.cpu_count() + 4)

error_set = set()

url_result_success = []

data_que = Queue()

_d_ = []


def search_status_code_async(domains, num=300):
    global _d_
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())  # 加上这一行
    policy = asyncio.WindowsSelectorEventLoopPolicy()
    asyncio.set_event_loop_policy(policy)

    async def check(data, semaphore):
        try:
            global _d_
            async with semaphore:
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=64, ssl=False)) as session:
                    async with session.get("http://" + data['domain'].strip()) as resp:
                        print("\t http://" + data['domain'].strip() + "    " + str(resp.status))
                        if resp.status in [100, 101, 200, 201, 202, 203, 204, 205, 206, 300, 301, 302, 303, 304, 305,
                                           306, 307, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412,
                                           415, 417, 500, 501, 504, 505]:
                            _d_.append(data)
                            return await resp.text()
        except Exception as e:
            if str(e) == '':
                print("\t>**>", i['domain'], e)
            elif '[getaddrinfo failed]' not in str(e):
                print("\t>>", i['domain'], e)

    tasks = []
    for i in domains:
        semaphore = asyncio.Semaphore(num)
        task = asyncio.ensure_future(check(i, semaphore))
        tasks.append(task)
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(asyncio.gather(*tasks))
    print(result)


def search_whois_async_plus(domains, num=500):
    __ = []
    import time
    async def check(i, semaphore):
        async with semaphore:
            try:
                whoisq = await asyncwhois.aio_whois_domain(i['domain'].strip('\n'))
                if whoisq.parser_output['expires'] is not None:
                    i['whois_expires'] = whoisq.parser_output['expires']
                    i['whois_updated'] = whoisq.parser_output['updated']
                    i['whois_created'] = whoisq.parser_output['created']
                    __.append(i)
                    print("<<<<<<<<<", i)
                    time.sleep(1)
            except Exception as e:
                if str(e) == '':
                    print(">**>", i['domain'], e)
                    # sys.exit()
                if str(e) not in ['', 'Domain not found!', '[Errno 104] Connection reset by peer',
                                  '[Errno 101] Network is unreachable',
                                  '[WinError 10054] 远程主机强迫关闭了一个现有的连接']:
                    print(">>", i['domain'], e)

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


def search_ping_async(domains, num=500):
    import ping3
    __ = []

    async def check(i, semaphore):
        ping3.EXCEPTIONS = True
        async with semaphore:
            try:
                mp = await ping3.verbose_ping(i["domain"], count=1, timeout=0.5)
                if mp != False:
                    __.append(i)
                    print("<<", i)
            except Exception as e:
                if 'Cannot resolve: Unknown host.' not in str(e):
                    print(">>Error>>", i['domain'], e)
                    __.append(i)
                    print("<<", i)

    tasks = []
    for _ in domains:
        semaphore = asyncio.Semaphore(num)
        task = asyncio.ensure_future(check(_, semaphore))
        tasks.append(task)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.gather(*tasks))
    loop.close()
    return __


def search_ping_thread(domains, num=500):
    import ping3
    ping3.EXCEPTIONS = False

    def __job(domains, q):
        for i in domains:
            try:
                mp = ping3.verbose_ping(i["domain"], count=1, timeout=0.5)
                # print(mp)
                if mp not in [False]:
                    # mp有三种返回值[None代表超时，False代表不存在，float代表正常]，这里不排除None的原意是timeout时间本来设置的就过于小
                    q.put(i)
                    print("<<", i)
            except Exception as e:
                if 'Cannot resolve: Unknown host.' not in str(e):
                    print(">>Error>>", i['domain'], e)
                    q.put(i)
                    print("<<", i)

    q = queue.Queue()
    threads = []  # 线程列表
    data = my_reshape(domains, num)
    for i in range(num):
        t = threading.Thread(target=__job, args=(data[i], q))
        t.start()
        threads.append(t)
    for thread in threads:
        thread.join()
    __ = []
    for _ in range(q.qsize()):
        __.append(q.get())
    print("\nping探测存活域名个数：{}->{}".format(len(domains), len(__)))
    return __


def search_whois_thread(domains, out=False, tnum=4):
    def __job_whois(domains, q):
        for i in domains:
            try:
                whoisq = whois.whois(i['domain'])
                if whoisq.expiration_date is not None:
                    i['whois_domain_name'] = whoisq.expiration_date
                    q.put(i)
                    print("<<", i)
            except Exception as e:
                if str(e) == '':
                    print(">**>", i['domain'], e)
                    # sys.exit()
                if str(e) not in ['', 'Domain not found!', '[Errno 104] Connection reset by peer',
                                  '[Errno 101] Network is unreachable',
                                  '[WinError 10054] 远程主机强迫关闭了一个现有的连接']:
                    print(">>", i['domain'], e)

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
        'fuzzer_num': 30000,  # 0-np.inf，inf代表输出所有的生成结果
        'threshold_value': 0.25,
        'step': 500,  # window最多509个 ulimit -n
        'tld_all': True,
        'fuzzers': [
            'addition',
            'hyphenation',
            'omission',
            'subdomain',
            'transposition'
        ],
        'useragent': USER_AGENT_STRING,
        'request_timeout_http': 1.5
    }
    # 1.生成混淆域名
    t1 = datetime.datetime.now()
    url = UrlParser(args['domain'])
    fuzz = fuzzer_plus.Fuzzer(domain=url.domain, tld_all=args['tld_all'], threshold_value=args['threshold_value'],
                              top=args['fuzzer_num'])
    fuzz.generate(args['fuzzers'])
    domains = list(fuzz.domains_tld)
    save_domains(domains, "fuzzer_{}".format(url.domain))

    # 2.域名过滤
    len_fuzz = len(domains)
    _ = min(args['fuzzer_num'], len(domains))
    print("fuzzer num:", _)

    # 3.域名探测
    print(t1)
    domains = search_whois_thread(domains[:_], args['step'])
    len_ = len(domains)
    print("live num：{}".format(len_))

    # 4.结果总结
    t2 = datetime.datetime.now()
    print("Total program time {}s".format(t2 - t1))
    save_domains(domains, "{}".format(url.domain))
    save_path = os.path.join(os.path.dirname(__file__), 'file')
    if not os.path.exists(save_path):
        os.makedirs(save_path)
    f_name = os.path.join(save_path, "{}-{}.csv".format(datetime.date.today().year, datetime.date.today().month))
    dict_ = [d, min(len_fuzz, args['fuzzer_num']), len_, t2 - t1]
    df = pd.DataFrame([dict_])
    print("<<", len_)
    df.to_csv(f_name, mode='a', index=False, header=False, encoding='utf-8')
    print("<<File: {} Written successfully".format(f_name))


if __name__ == '__main__':
    import sys

    run(sys.argv[1])
    # mp = ping3.verbose_ping('baidDDDDDDDDDDDDDDDDDDDDDDdu.com', count=1, timeout=0.5)
    # print(mp)
