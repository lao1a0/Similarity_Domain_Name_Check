# !/usr/bin/env python3
# -*- coding: utf-8 -*-
import gevent
from gevent import monkey

monkey.patch_all(thread=False)
import platform
import subprocess
from queue import Queue
import datetime
import re
import sys
import socket
import fuzzer_plus
from dependent_function import _debug, UrlParser, save_domains

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


def search_ping_async(_list):
    for d in _list:
        data_que.put(d)
    # 开启多协程
    cos = []
    for i in range(len(_list)):
        # 调用工作函数
        c = gevent.spawn(ping_func)
        cos.append(c)
    gevent.joinall(cos)


def ping_func():
    global _d_
    while True:
        if data_que.qsize() == 0:
            break
        domain_data = data_que.get()
        if (platform.system() == 'Windows'):
            # print('ping -n 1 {}'.format(ip))
            ping = subprocess.Popen(
                'ping -n 1 {}'.format(domain_data['domain']),
                shell=False,
                close_fds=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        else:
            ping = subprocess.Popen(
                'ping -c 1 {}'.format(domain_data['domain']),
                shell=False,
                close_fds=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        try:
            out, err = ping.communicate(timeout=20)
            if 'ttl' in out.decode('utf-8').lower():
                _d_.append(domain_data)
                print("\tSuccess : domain {} is alive".format(domain_data['domain']))
        except Exception as e:
            if 'timed out after' not in str(e):
                print("\tError : {}".format(e))
            pass
        ping.kill()


def list_of_groups(init_list, childern_list_len):
    list_of_groups = zip(*(iter(init_list),) * childern_list_len)  # 使用zip函数将列表按照网段长度分成多个列表
    end_list = [list(i) for i in list_of_groups]  # 转换成列表
    count = len(init_list) % childern_list_len
    end_list.append(init_list[-count:]) if count != 0 else end_list
    return end_list


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
    domains = domains[:_]
    len_ = len(domains)
    for i in range(0, len_, args["step"]):
        print("Step：", i)
        search_ping_async(domains[i:min(i + args["step"], len_ - 1)])
    domains = _d_
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
