#!/user/bin/python
# -*- coding: UTF-8 -*-
import gzip
import os
import queue
import re
import sys
import threading
import urllib
import numpy as np
import pandas as pd
from setuptools.package_index import user_agent
__version__ = '20230602'

import requests

import whois

VALID_FQDN_REGEX = re.compile(r'(?=^.{4,253}$)(^((?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z0-9-]{2,63}$)', re.IGNORECASE)
USER_AGENT_STRING = 'Mozilla/5.0 ({} {}-bit) dnstwist/{}'.format(sys.platform, sys.maxsize.bit_length() + 1,
                                                                 __version__)
REQUEST_TIMEOUT_SMTP = 5
REQUEST_TIMEOUT_DNS = 2.5
REQUEST_RETRIES_DNS = 2
# REQUEST_TIMEOUT_HTTP = 5
THREAD_COUNT_DEFAULT = min(32, os.cpu_count() + 4)


def my_reshape(data_set, row):
    ''':cvar 行号对应线程数量，不动，动的是列号'''
    column = len(data_set) // row  # 最后一个list的数量
    _ = np.array(data_set[:column * row]).reshape(row, column).tolist()
    __ = 0
    for i in data_set[column * row:]:
        _[__].append(i)
        __ += 1
    return _


def p_cli(text):
    if sys.stdout.isatty():
        print(text, end='', flush=True)


def _debug(msg):
    if 'DEBUG' in os.environ:
        if isinstance(msg, Exception):
            print('{}:{} {}'.format(__file__, msg.__traceback__.tb_lineno, str(msg)), file=sys.stderr, flush=True)
        else:
            print(str(msg), file=sys.stderr, flush=True)


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


def save_domains(domains, name):
    save_path = os.path.join(os.path.dirname(__file__), 'file')
    if not os.path.exists(save_path):
        os.makedirs(save_path)
    f_name = os.path.join(save_path, '{}.csv'.format(name))
    pd.DataFrame(domains).to_csv(f_name, index=False, encoding="utf-8")
    print("<<文件：{}保存成功".format(f_name))

def domain_tld(domain):
    try:
        from tld import parse_tld
    except ImportError:
        ctld = ['org', 'com', 'net', 'gov', 'edu', 'co', 'mil', 'nom', 'ac', 'info', 'biz']
        d = domain.rsplit('.', 3)
        if len(d) < 2:
            return '', d[0], ''
        if len(d) == 2:
            return '', d[0], d[1]
        if len(d) > 2:
            if d[-2] in ctld:
                return '.'.join(d[:-3]), d[-3], '.'.join(d[-2:])
            else:
                return '.'.join(d[:-2]), d[-2], d[-1]
    else:
        d = parse_tld(domain, fix_protocol=True)[::-1]
        if d[1:] == d[:-1] and None in d:
            d = tuple(domain.rsplit('.', 2))
            d = ('',) * (3 - len(d)) + d
        return d


class UrlOpener():
    def __init__(self, url, timeout=5, headers={}, verify=True):
        http_headers = {'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9',
                        'accept-encoding': 'gzip,identity',
                        'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8'}
        for h, v in headers.items():  # do not override accepted encoding - only gzip,identity is supported
            if h.lower() != 'accept-encoding':
                http_headers[h.lower()] = v
        if verify:  # 处理https，verify决定是否验证 SSL 证书
            ctx = urllib.request.ssl.create_default_context()
        else:
            ctx = urllib.request.ssl._create_unverified_context()
        request = urllib.request.Request(url, headers=http_headers)
        # urllib.request.urlopen用于打开一个远程的url连接,并且向这个连接发出请求,获取响应结果。
        # 返回的结果是一个http响应对象,这个响应对象中记录了本次http访问的响应头和响应体
        with urllib.request.urlopen(request, timeout=timeout, context=ctx) as r:
            self.headers = r.headers
            self.code = r.code
            self.reason = r.reason
            self.url = r.url
            self.content = r.read()
        if self.content[:3] == b'\x1f\x8b\x08':
            self.content = gzip.decompress(self.content)  # [0x1f, 0x8b, 0x08] 是 gzip 文件的 header
        if 64 < len(self.content) < 1024:
            try:
                # 用于从 HTML 的 meta 标签中提取 url。
                # 第一个参数用于匹配类似于 <meta name="xxx" content="xxx" url="xxx" ...> 这样的字符串。
                # 第二个参数是要查找的字符串。self.content.decode()，将 bytes 类型的内容转换为 str 类型。
                # 第三个参数是 re.IGNORECASE，表示忽略大小写。
                # 如果查找到了匹配的内容，则返回一个 Match 对象，否则返回 None。Match 对象有很多方法和属性，可以用于获取匹配到的内容、位置等信息。
                meta_url = re.search(r'<meta[^>]*?url=(https?://[\w.,?!:;/*#@$&+=[\]()%~-]*?)"', self.content.decode(),
                                     re.IGNORECASE)
            except Exception:
                pass
            else:
                if meta_url:
                    # 提取出meta_url中匹配到的第一个url
                    self.__init__(meta_url.group(1), timeout=timeout, headers=http_headers, verify=verify)
        self.normalized_content = self._normalize()

    def _normalize(self):
        # 第一个键值对：key匹配的action=“xxx”、src=“xxx”、href=“xxx”这样的字符串。 value 用于替换字符串中匹配到的内容，接受一个参数m，表示匹配到的内容，首先使用 split() 方法将匹配到的内容按照等号分割成两部分，将第一部分加上等号和两个双引号，最后返回这个字符串。因此其做的是将action=“xxx”、src=“xxx”、href=“xxx”的值清空
        # 第二个键值对： key匹配字符串中类似于 url(xxx) 的字符串，value用于将 url(xxx) 替换为 url()。
        content = b' '.join(self.content.split())  # 将content中的多个空格替换为一个空格
        mapping = dict({
            b'(action|src|href)="[^"]+"': lambda m: m.group(0).split(b'=')[0] + b'=""',
            b'url\([^)]+\)': b'url()',
        })
        for pattern, repl in mapping.items():
            content = re.sub(pattern, repl, content, flags=re.IGNORECASE)
        return content


class UrlParser():
    def __init__(self, url):
        u = urllib.parse.urlparse(url if '://' in url else 'http://{}'.format(url))
        self.domain = u.hostname.lower()
        self.domain = idna.encode(self.domain).decode()
        if not self._validate_domain(self.domain):
            raise ValueError('Invalid domain name') from None
        self.scheme = u.scheme
        if self.scheme not in ('http', 'https'):
            raise ValueError('Invalid scheme') from None
        self.username = u.username
        self.password = u.password
        self.port = u.port
        self.path = u.path
        self.query = u.query
        self.fragment = u.fragment

    def _validate_domain(self, domain):
        if len(domain) > 253:
            return False
        if VALID_FQDN_REGEX.match(domain):
            try:
                _ = idna.decode(domain)
            except Exception:
                return False
            else:
                return True
        return False

    def full_uri(self, domain=None):
        uri = '{}://'.format(self.scheme)
        if self.username:
            uri += self.username
            if self.password:
                uri += ':{}'.format(self.password)
            uri += '@'
        uri += self.domain if not domain else domain
        if self.port:
            uri += ':{}'.format(self.port)
        if self.path:
            uri += self.path
        if self.query:
            uri += '?{}'.format(self.query)
        if self.fragment:
            uri += '#{}'.format(self.fragment)
        return uri


class Permutation(dict):
    def __getattr__(self, item):
        if item in self:
            return self[item]
        raise AttributeError("object has no attribute '{}'".format(item)) from None

    __setattr__ = dict.__setitem__

    def __init__(self, fuzzer='', domain='', score=np.inf):
        super(dict, self).__init__()
        self['fuzzer'] = fuzzer
        self['domain'] = domain
        self['score'] = score

    def __hash__(self):
        return hash(self['domain'])

    def __eq__(self, other):
        return self['domain'] == other['domain']

    def __lt__(self, other):
        return self['fuzzer'] + ''.join(self.get('dns_a', [])[:1]) + self['domain'] < other['fuzzer'] + ''.join(
            other.get('dns_a', [])[:1]) + other['domain']

    def is_registered(self):
        return len(self) > 2

def search_dns(domains, _type=1, out=False, tnum=4):
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
    if out:
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
    import tlsh

    MODULE_TLSH = True
except ImportError as e:
    _debug(e)
    MODULE_TLSH = False

def __job_LSH_alg(domains, lsh_init, request_time_out, option_lsh,q):
    for _ in domains:
        try:
            r = UrlOpener(UrlParser(_['domain']).full_uri(),
                          timeout=request_time_out,
                          headers={'user-agent': user_agent},
                          verify=False)
        except Exception as e:
            if "11001" not in str(e):
                # print(">{}查询出错：{}".format(_['domain'], e))
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
            # print('>{}的LSH得分：{} {}'.format(_['domain'], _['LSH_score'], r.url))
            q.put(_)


def LSH_alg(url_raw, domains, request_timeout, user_agent, option_lsh='ssdeep', out=False, tnum=4):
    if out:
        print('\n将要进行LSH检测的域名：\n')
        print(pd.DataFrame(domains))
    try:
        r = UrlOpener(UrlParser(url_raw).full_uri(),
                      timeout=request_timeout,
                      headers={'user-agent': user_agent},
                      verify=False)
    except Exception as e:
        # print(e)
        pass
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

def search_whois_async(domains):
    import asyncio
    async def check(i, semaphore):
        async with semaphore:
            try:
                whoisq = whois.whois(i['domain'])
                if whoisq.expiration_date is not None:
                    i['whois_domain_name'] = whoisq.expiration_date
                    # print(i)
                    return await i
            except Exception as e:
                pass
                # print(e)

    loop = asyncio.get_event_loop()
    tasks = []
    for _ in domains:
        semaphore = asyncio.Semaphore(500)  # 限制并发量为300
        task = asyncio.ensure_future(check(_, semaphore))
        tasks.append(task)
    result = loop.run_until_complete(asyncio.gather(*tasks))
    loop.close()
    return result

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

def search_whois_thread(domains, out=False, tnum=4):
    def __job_whois(domains, q):
        try:
            for i in domains:
                whoisq = whois.whois(i['domain'])
                if whoisq.expiration_date is not None:
                    i['whois_domain_name'] = whoisq.expiration_date
                    q.put(i)
        except Exception as e:
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