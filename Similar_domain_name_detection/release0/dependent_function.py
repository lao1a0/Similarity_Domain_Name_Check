'''
@Time : 2023-06-02 14:24
@Author : laolao
@FileName: dependent_function.py
'''
import gzip
import os
import re
import sys
import urllib
import numpy as np
import pandas as pd

__version__ = '20230602'

VALID_FQDN_REGEX = re.compile(r'(?=^.{4,253}$)(^((?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z0-9-]{2,63}$)', re.IGNORECASE)
USER_AGENT_STRING = 'Mozilla/5.0 ({} {}-bit) dnstwist/{}'.format(sys.platform, sys.maxsize.bit_length() + 1,
                                                                 __version__)
REQUEST_TIMEOUT_SMTP = 5
REQUEST_TIMEOUT_DNS = 2.5
REQUEST_RETRIES_DNS = 2
REQUEST_TIMEOUT_HTTP = 5
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
    f_name = os.path.join(os.path.dirname(__file__), '{}.csv'.format(name))
    pd.DataFrame(domains).to_csv(f_name, index=False, encoding="utf-8")
    print("文件：{}保存成功".format(f_name))


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
    def __init__(self, url, timeout=REQUEST_TIMEOUT_HTTP, headers={}, verify=True):
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

    def __init__(self, fuzzer='', domain=''):
        super(dict, self).__init__()
        self['fuzzer'] = fuzzer
        self['domain'] = domain

    def __hash__(self):
        return hash(self['domain'])

    def __eq__(self, other):
        return self['domain'] == other['domain']

    def __lt__(self, other):
        return self['fuzzer'] + ''.join(self.get('dns_a', [])[:1]) + self['domain'] < other['fuzzer'] + ''.join(
            other.get('dns_a', [])[:1]) + other['domain']

    def is_registered(self):
        return len(self) > 2
