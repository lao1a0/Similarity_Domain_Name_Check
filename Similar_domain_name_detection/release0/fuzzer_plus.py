#!/usr/bin/env python
# coding: utf-8

# In[2]:


import itertools
import math
import threading
from queue import Queue
import matplotlib.pyplot as plt
from pylab import mpl
import numpy as np
from dependent_function import Permutation, idna, VALID_FQDN_REGEX, UrlParser, domain_tld, my_reshape


class Fuzzer():
    glyphs_idn_by_tld = {
        **dict.fromkeys(['cz', 'sk', 'uk', 'co.uk', 'nl', 'edu'], {
            # IDN not suported by the corresponding registry
        }),
        **dict.fromkeys(['br'], {
            'a': ('à', 'á', 'â', 'ã'),
            'c': ('ç',),
            'e': ('é', 'ê'),
            'i': ('í',),
            'o': ('ó', 'ô', 'õ'),
            'u': ('ú', 'ü'),
            'y': ('ý', 'ÿ'),
        }),
        **dict.fromkeys(['dk'], {
            'a': ('ä', 'å'),
            'e': ('é',),
            'o': ('ö', 'ø'),
            'u': ('ü',),
            'ae': ('æ',),
        }),
        **dict.fromkeys(['eu', 'de', 'pl'], {
            'a': ('á', 'à', 'ă', 'â', 'å', 'ä', 'ã', 'ą', 'ā'),
            'c': ('ć', 'ĉ', 'č', 'ċ', 'ç'),
            'd': ('ď', 'đ'),
            'e': ('é', 'è', 'ĕ', 'ê', 'ě', 'ë', 'ė', 'ę', 'ē'),
            'g': ('ğ', 'ĝ', 'ġ', 'ģ'),
            'h': ('ĥ', 'ħ'),
            'i': ('í', 'ì', 'ĭ', 'î', 'ï', 'ĩ', 'į', 'ī'),
            'j': ('ĵ',),
            'k': ('ķ', 'ĸ'),
            'l': ('ĺ', 'ľ', 'ļ', 'ł'),
            'n': ('ń', 'ň', 'ñ', 'ņ'),
            'o': ('ó', 'ò', 'ŏ', 'ô', 'ö', 'ő', 'õ', 'ø', 'ō'),
            'r': ('ŕ', 'ř', 'ŗ'),
            's': ('ś', 'ŝ', 'š', 'ş'),
            't': ('ť', 'ţ', 'ŧ'),
            'u': ('ú', 'ù', 'ŭ', 'û', 'ů', 'ü', 'ű', 'ũ', 'ų', 'ū'),
            'w': ('ŵ',),
            'y': ('ý', 'ŷ', 'ÿ'),
            'z': ('ź', 'ž', 'ż'),
            'ae': ('æ',),
            'oe': ('œ',),
        }),
        **dict.fromkeys(['fi'], {
            '3': ('ʒ',),
            'a': ('á', 'ä', 'å', 'â'),
            'c': ('č',),
            'd': ('đ',),
            'g': ('ǧ', 'ǥ'),
            'k': ('ǩ',),
            'n': ('ŋ',),
            'o': ('õ', 'ö'),
            's': ('š',),
            't': ('ŧ',),
            'z': ('ž',),
        }),
        **dict.fromkeys(['no'], {
            'a': ('á', 'à', 'ä', 'å'),
            'c': ('č', 'ç'),
            'e': ('é', 'è', 'ê'),
            'i': ('ï',),
            'n': ('ŋ', 'ń', 'ñ'),
            'o': ('ó', 'ò', 'ô', 'ö', 'ø'),
            's': ('š',),
            't': ('ŧ',),
            'u': ('ü',),
            'z': ('ž',),
            'ae': ('æ',),
        }),
        **dict.fromkeys(['be', 'fr', 're', 'yt', 'pm', 'wf', 'tf', 'ch', 'li'], {
            'a': ('à', 'á', 'â', 'ã', 'ä', 'å'),
            'c': ('ç',),
            'e': ('è', 'é', 'ê', 'ë'),
            'i': ('ì', 'í', 'î', 'ï'),
            'n': ('ñ',),
            'o': ('ò', 'ó', 'ô', 'õ', 'ö'),
            'u': ('ù', 'ú', 'û', 'ü'),
            'y': ('ý', 'ÿ'),
            'ae': ('æ',),
            'oe': ('œ',),
        }),
        **dict.fromkeys(['ca'], {
            'a': ('à', 'â'),
            'c': ('ç',),
            'e': ('è', 'é', 'ê', 'ë'),
            'i': ('î', 'ï'),
            'o': ('ô',),
            'u': ('ù', 'û', 'ü'),
            'y': ('ÿ',),
            'ae': ('æ',),
            'oe': ('œ',),
        }),
    }
    glyphs_unicode = {
        '2': ('ƻ',),
        '3': ('ʒ',),
        '5': ('ƽ',),
        'a': ('ạ', 'ă', 'ȧ', 'ɑ', 'å', 'ą', 'â', 'ǎ', 'á', 'ə', 'ä', 'ã', 'ā', 'à'),
        'b': ('ḃ', 'ḅ', 'ƅ', 'ʙ', 'ḇ', 'ɓ'),
        'c': ('č', 'ᴄ', 'ċ', 'ç', 'ć', 'ĉ', 'ƈ'),
        'd': ('ď', 'ḍ', 'ḋ', 'ɖ', 'ḏ', 'ɗ', 'ḓ', 'ḑ', 'đ'),
        'e': ('ê', 'ẹ', 'ę', 'è', 'ḛ', 'ě', 'ɇ', 'ė', 'ĕ', 'é', 'ë', 'ē', 'ȩ'),
        'f': ('ḟ', 'ƒ'),
        'g': ('ǧ', 'ġ', 'ǵ', 'ğ', 'ɡ', 'ǥ', 'ĝ', 'ģ', 'ɢ'),
        'h': ('ȟ', 'ḫ', 'ḩ', 'ḣ', 'ɦ', 'ḥ', 'ḧ', 'ħ', 'ẖ', 'ⱨ', 'ĥ'),
        'i': ('ɩ', 'ǐ', 'í', 'ɪ', 'ỉ', 'ȋ', 'ɨ', 'ï', 'ī', 'ĩ', 'ị', 'î', 'ı', 'ĭ', 'į', 'ì'),
        'j': ('ǰ', 'ĵ', 'ʝ', 'ɉ'),
        'k': ('ĸ', 'ǩ', 'ⱪ', 'ḵ', 'ķ', 'ᴋ', 'ḳ'),
        'l': ('ĺ', 'ł', 'ɫ', 'ļ', 'ľ'),
        'm': ('ᴍ', 'ṁ', 'ḿ', 'ṃ', 'ɱ'),
        'n': ('ņ', 'ǹ', 'ń', 'ň', 'ṅ', 'ṉ', 'ṇ', 'ꞑ', 'ñ', 'ŋ'),
        'o': ('ö', 'ó', 'ȯ', 'ỏ', 'ô', 'ᴏ', 'ō', 'ò', 'ŏ', 'ơ', 'ő', 'õ', 'ọ', 'ø'),
        'p': ('ṗ', 'ƿ', 'ƥ', 'ṕ'),
        'q': ('ʠ',),
        'r': ('ʀ', 'ȓ', 'ɍ', 'ɾ', 'ř', 'ṛ', 'ɽ', 'ȑ', 'ṙ', 'ŗ', 'ŕ', 'ɼ', 'ṟ'),
        's': ('ṡ', 'ș', 'ŝ', 'ꜱ', 'ʂ', 'š', 'ś', 'ṣ', 'ş'),
        't': ('ť', 'ƫ', 'ţ', 'ṭ', 'ṫ', 'ț', 'ŧ'),
        'u': ('ᴜ', 'ų', 'ŭ', 'ū', 'ű', 'ǔ', 'ȕ', 'ư', 'ù', 'ů', 'ʉ', 'ú', 'ȗ', 'ü', 'û', 'ũ', 'ụ'),
        'v': ('ᶌ', 'ṿ', 'ᴠ', 'ⱴ', 'ⱱ', 'ṽ'),
        'w': ('ᴡ', 'ẇ', 'ẅ', 'ẃ', 'ẘ', 'ẉ', 'ⱳ', 'ŵ', 'ẁ'),
        'x': ('ẋ', 'ẍ'),
        'y': ('ŷ', 'ÿ', 'ʏ', 'ẏ', 'ɏ', 'ƴ', 'ȳ', 'ý', 'ỿ', 'ỵ'),
        'z': ('ž', 'ƶ', 'ẓ', 'ẕ', 'ⱬ', 'ᴢ', 'ż', 'ź', 'ʐ'),
        'ae': ('æ',),
        'oe': ('œ',),
    }
    glyphs_ascii = {
        '0': ('o',),
        '1': ('l', 'i'),
        '3': ('8',),
        '6': ('9',),
        '8': ('3',),
        '9': ('6',),
        'b': ('d', 'lb'),
        'c': ('e',),
        'd': ('b', 'cl', 'dl'),
        'e': ('c',),
        'g': ('q',),
        'h': ('lh'),
        'i': ('1', 'l'),
        'k': ('lc'),
        'l': ('1', 'i'),
        'm': ('n', 'nn', 'rn', 'rr'),
        'n': ('m', 'r'),
        'o': ('0',),
        'q': ('g',),
        'w': ('vv',),
    }
    latin_to_cyrillic = {
        'a': 'а', 'b': 'ь', 'c': 'с', 'd': 'ԁ', 'e': 'е', 'g': 'ԍ', 'h': 'һ',
        'i': 'і', 'j': 'ј', 'k': 'к', 'l': 'ӏ', 'm': 'м', 'o': 'о', 'p': 'р',
        'q': 'ԛ', 's': 'ѕ', 't': 'т', 'v': 'ѵ', 'w': 'ԝ', 'x': 'х', 'y': 'у',
    }
    qwerty = {
        '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7',
        '9': '0oi8', '0': 'po9',
        'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7',
        'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
        'a': 'qwsz', 's': 'edxzaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'ikmnhu',
        'k': 'olmji', 'l': 'kop',
        'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
    }
    qwertz = {
        '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7zt5', '7': '8uz6', '8': '9iu7',
        '9': '0oi8', '0': 'po9',
        'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6zgfr5', 'z': '7uhgt6', 'u': '8ijhz7',
        'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
        'a': 'qwsy', 's': 'edxyaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'zhbvft', 'h': 'ujnbgz', 'j': 'ikmnhu',
        'k': 'olmji', 'l': 'kop',
        'y': 'asx', 'x': 'ysdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
    }
    azerty = {
        '1': '2a', '2': '3za1', '3': '4ez2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7',
        '9': '0oi8', '0': 'po9',
        'a': '2zq1', 'z': '3esqa2', 'e': '4rdsz3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7',
        'i': '9okju8', 'o': '0plki9', 'p': 'lo0m',
        'q': 'zswa', 's': 'edxwqz', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'iknhu',
        'k': 'olji', 'l': 'kopm', 'm': 'lp',
        'w': 'sxq', 'x': 'wsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhj'
    }
    keyboards = [qwerty, qwertz, azerty]
    _tld_dictionary = ['AERO', 'AI', 'Ai', 'BE', 'Biz', 'CA', 'CL', 'CO.IN', 'CO.UK', 'COM', 'COM.MX', 'DK', 'ES', 'FR',
                       'GOV.UK', 'GR', 'Global', 'ID', 'IN', 'IT', 'Jobs', 'LIVE', 'MT', 'MX', 'NET', 'NO', 'Net',
                       'ORG', 'Org', 'PL', 'PT', 'Pk', 'RO', 'TV', 'UA', 'US', 'ac', 'ac.at', 'ac.il', 'ac.in', 'ac.uk',
                       'ae', 'aero', 'africa', 'ag', 'agency', 'ai', 'am', 'app', 'ar', 'art', 'asia', 'asn.au', 'at',
                       'au', 'az', 'band', 'bc.ca', 'be', 'beer', 'bg', 'biz', 'bj.cn', 'blog', 'blue', 'br', 'by',
                       'bz', 'ca', 'canon', 'cat', 'cc', 'center', 'cfd', 'ch', 'city', 'cl', 'cloud', 'club', 'cm',
                       'cn', 'co', 'co.id', 'co.il', 'co.in', 'co.jp', 'co.ke', 'co.kr', 'co.nz', 'co.th', 'co.uk',
                       'co.za', 'co.zw', 'com', 'com.ar', 'com.au', 'com.bd', 'com.bh', 'com.br', 'com.cn', 'com.gh',
                       'com.hk', 'com.my', 'com.np', 'com.ph', 'com.pk', 'com.pl', 'com.sg', 'com.tr', 'com.tw',
                       'com.ua', 'com.vn', 'community', 'coop', 'cx', 'cy', 'cyou', 'cz', 'de', 'design', 'dev',
                       'digital', 'directory', 'dk', 'dog', 'edu', 'edu.au', 'edu.cn', 'edu.in', 'edu.my', 'edu.ph',
                       'edu.pk', 'ee', 'eg', 'es', 'eu', 'fi', 'fit', 'fm', 'fr', 'fr.it', 'fun', 'ge', 'gg', 'gh',
                       'global', 'go.jp', 'go.kr', 'golf', 'gov', 'gov.my', 'gov.uk', 'gov.za', 'gq', 'gr', 'group',
                       'gs', 'guru', 'hk', 'host', 'hr', 'hu', 'icu', 'id', 'ie', 'il', 'im', 'in', 'info', 'ink',
                       'insure', 'int', 'investments', 'io', 'ir', 'is', 'it', 'jo', 'jobs', 'jp', 'ke', 'kg', 'kim',
                       'kr', 'kz', 'la', 'law', 'lc', 'li', 'life', 'link', 'live', 'lk', 'lol', 'love', 'lt', 'ltd',
                       'lu', 'lv', 'ly', 'md', 'me', 'me.uk', 'media', 'mil', 'mn', 'mobi', 'ms', 'mt', 'mx', 'my',
                       'name', 'net', 'news', 'ng', 'nhs.uk', 'nl', 'no', 'np', 'nu', 'nz', 'on.ca', 'one', 'ong',
                       'online', 'ooo', 'org', 'org.br', 'org.in', 'org.my', 'org.nz', 'org.sg', 'org.uk', 'org.za',
                       'pe', 'ph', 'pk', 'pl', 'plus', 'porn', 'press', 'pro', 'pt', 'pub', 'qa', 'red', 'ro', 'rocks',
                       'roma.it', 'rs', 'ru', 'run', 'sa', 'scot', 'se', 'sg', 'shop', 'show', 'si', 'site', 'sk', 'so',
                       'space', 'store', 'studio', 'su', 'team', 'tech', 'tm', 'to', 'today', 'tokyo', 'tools', 'top',
                       'tr', 'travel', 'tt', 'tv', 'tw', 'tz', 'ua', 'uk', 'us', 'va', 'vc', 've', 'vicenza.it',
                       'video', 'vip', 'vn', 'wang', 'waw.pl', 'website', 'wedding', 'win', 'work', 'world', 'ws',
                       'xin', 'xyz', 'za', 'zone', 'zw', '商城']  # 域名存在性清洗后的，百度搜索能大于10w条结果的，304条

    def __init__(self, domain, dictionary=[], tld_dictionary=[], tld_all=True, threshold_value=0.5, top=50, tnum=10):
        self.subdomain, self.domain, self.tld = domain_tld(domain)
        self.domain = idna.decode(self.domain)
        self.dictionary = list(dictionary)
        self.tld_dictionary = list(tld_dictionary) if len(list(tld_dictionary)) else self._tld_dictionary
        self.domains = set()
        self.tld_all = tld_all  # 控制tld与域是否交叉组合
        self.threshold_value = threshold_value  # 相似度的阈值，控制生成域名的数量
        self.top = top  # 保留生成的相似度最高的域名数量，默认50个
        self.tnum = tnum  # tld_all时候的多线程

    def _bitsquatting(self):
        masks = [1, 2, 4, 8, 16, 32, 64, 128]
        chars = set('abcdefghijklmnopqrstuvwxyz0123456789-')
        for i, c in enumerate(self.domain):
            for mask in masks:
                b = chr(ord(c) ^ mask)
                if b in chars:
                    yield self.domain[:i] + b + self.domain[i + 1:]

    def _cyrillic(self):
        cdomain = self.domain
        for l, c in self.latin_to_cyrillic.items():
            cdomain = cdomain.replace(l, c)
        for c, l in zip(cdomain, self.domain):
            if c == l:
                return []
        return [cdomain]

    def _homoglyph(self):
        md = lambda a, b: {k: set(a.get(k, [])) | set(b.get(k, [])) for k in set(a.keys()) | set(b.keys())}
        glyphs = md(self.glyphs_ascii, self.glyphs_idn_by_tld.get(self.tld, self.glyphs_unicode))

        def mix(domain):
            for w in range(1, len(domain)):
                for i in range(len(domain) - w + 1):
                    pre = domain[:i]
                    win = domain[i:i + w]
                    suf = domain[i + w:]
                    for c in (set(win) | {win[:2]}):
                        for g in glyphs.get(c, []):
                            yield pre + win.replace(c, g) + suf

        result1 = set(mix(self.domain))
        result2 = set()
        for r in result1:
            result2.update(set(mix(r)))
        return result1 | result2

    def _hyphenation(self):
        return {self.domain[:i] + '-' + self.domain[i:] for i in range(1, len(self.domain))}

    def _insertion(self):
        result = set()
        for i in range(1, len(self.domain) - 1):
            prefix, orig_c, suffix = self.domain[:i], self.domain[i], self.domain[i + 1:]
            for c in (c for keys in self.keyboards for c in keys.get(orig_c, [])):
                result.update({
                    prefix + c + orig_c + suffix,
                    prefix + orig_c + c + suffix
                })
        return result

    def _omission(self):
        return {self.domain[:i] + self.domain[i + 1:] for i in range(len(self.domain))}

    def _repetition(self):
        return {self.domain[:i] + c + self.domain[i:] for i, c in enumerate(self.domain)}

    def _replacement(self):
        for i, c in enumerate(self.domain):
            pre = self.domain[:i]
            suf = self.domain[i + 1:]
            for layout in self.keyboards:
                for r in layout.get(c, ''):
                    yield pre + r + suf

    def _subdomain(self):
        for i in range(1, len(self.domain) - 1):
            if self.domain[i] not in ['-', '.'] and self.domain[i - 1] not in ['-', '.']:
                yield self.domain[:i] + '.' + self.domain[i:]

    def _transposition(self):
        return {self.domain[:i] + self.domain[i + 1] + self.domain[i] + self.domain[i + 2:] for i in
                range(len(self.domain) - 1)}

    def _vowel_swap(self):
        vowels = 'aeiou'
        for i in range(0, len(self.domain)):
            for vowel in vowels:
                if self.domain[i] in vowels:
                    yield self.domain[:i] + vowel + self.domain[i + 1:]

    def _addition(self):
        t = set()
        for i in self.domain:
            for j in (32, 45, *range(48, 58), *range(97, 123)):
                t.add(self.domain.replace(i, chr(j)))  # 字符替代插入
                l_d = list(self.domain)
                l_d.insert(self.domain.find(i), chr(j))
                t.add(''.join(l_d))  # 字符直接插入
                t.add(self.domain + chr(j))  # 字符直接插入
        for i in list(itertools.permutations(self.domain, len(self.domain))):  # 字符串本身排列组合
            t.add("".join(i))
        return t

    def _dictionary(self):
        result = set()
        for word in self.dictionary:
            if not (self.domain.startswith(word) and self.domain.endswith(word)):
                result.update({
                    self.domain + '-' + word,
                    self.domain + word,
                    word + '-' + self.domain,
                    word + self.domain
                })
        if '-' in self.domain:
            parts = self.domain.split('-')
            for word in self.dictionary:
                result.update({
                    '-'.join(parts[:-1]) + '-' + word,
                    word + '-' + '-'.join(parts[1:])
                })
        return result

    def _tld(self):
        if self.tld in self.tld_dictionary:
            self.tld_dictionary.remove(self.tld)
        return set(self.tld_dictionary)

    def _job_tld(self, data, q):
        for tld in data:
            for j in self.domains.copy():
                q.put('.'.join(
                    filter(None, [self.subdomain, j['domain'].split('.')[0], tld])))

    # def _multithreading(self):
    #     q = Queue()
    #     threads = []  # 线程列表
    #     data = my_reshape(list(self._tld()), self.tnum)
    #     for i in range(self.tnum):
    #         t = threading.Thread(target=self._job_tld, args=(data[i], q))
    #         threads.append(t)
    #         t.start()
    #     for thread in threads:
    #         thread.join()
    #     for _ in range(self.tnum):
    #         self.domains.add(Permutation(fuzzer='tld-swap', domain=q.get()))

    def generate(self, fuzzers=[]):
        if not fuzzers or '*original' in fuzzers:
            self.domains.add(
                Permutation(fuzzer='*original', domain='.'.join(filter(None, [self.subdomain, self.domain, self.tld]))))
        for f_name in fuzzers or [
            'addition', 'bitsquatting',
            'cyrillic', 'homoglyph',
            'hyphenation',
            'insertion', 'omission', 'repetition', 'replacement',
            'subdomain', 'transposition', 'vowel-swap', 'dictionary',
        ]:
            try:
                f = getattr(self, '_' + f_name.replace('-', '_'))
            except AttributeError:
                pass
            else:
                # 添加代码
                original_domain_score = self._similar_alg_entropy(self.domain)
                #########################
                for domain in f():  # 添加代码
                    if math.fabs(self._similar_alg_entropy(domain) - original_domain_score) < self.threshold_value:
                        self.domains.add(
                            Permutation(fuzzer=f_name,
                                        domain='.'.join(filter(None, [self.subdomain, domain, self.tld]))))
                    #############################################

        if self.tld_all:
            # self._multithreading()
            q = Queue()
            threads = []  # 线程列表
            data = my_reshape(list(self._tld()), self.tnum)
            for i in range(self.tnum):
                t = threading.Thread(target=self._job_tld, args=(data[i], q))
                threads.append(t)
                t.start()
            for thread in threads:
                thread.join()
            for _ in range(self.tnum):
                self.domains.add(Permutation(fuzzer='tld-swap', domain=q.get()))
            # for tld in self._tld():
            #     for j in self.domains.copy():
            #         self.domains.add(Permutation(fuzzer='tld-swap', domain='.'.join(
            #             filter(None, [self.subdomain, j['domain'].split('.')[0], tld]))))
            # pass
        else:
            for tld in self._tld():
                self.domains.add(Permutation(fuzzer='tld-swap',
                                             domain='.'.join(filter(None, [self.subdomain, self.domain, tld]))))
        if not fuzzers or 'various' in fuzzers:
            if '.' in self.tld:
                self.domains.add(Permutation(fuzzer='various', domain='.'.join(
                    filter(None, [self.subdomain, self.domain, self.tld.split('.')[-1]]))))
                self.domains.add(Permutation(fuzzer='various',
                                             domain='.'.join(filter(None, [self.subdomain, self.domain + self.tld]))))
            if '.' not in self.tld:
                self.domains.add(Permutation(fuzzer='various', domain='.'.join(
                    filter(None, [self.subdomain, self.domain + self.tld, self.tld]))))
            if self.tld != 'com' and '.' not in self.tld:
                self.domains.add(Permutation(fuzzer='various', domain='.'.join(
                    filter(None, [self.subdomain, self.domain + '-' + self.tld, 'com']))))
            if self.subdomain:
                self.domains.add(
                    Permutation(fuzzer='various', domain='.'.join([self.subdomain + self.domain, self.tld])))
                self.domains.add(Permutation(fuzzer='various', domain='.'.join(
                    [self.subdomain.replace('.', '') + self.domain, self.tld])))
                self.domains.add(
                    Permutation(fuzzer='various', domain='.'.join([self.subdomain + '-' + self.domain, self.tld])))
                self.domains.add(Permutation(fuzzer='various', domain='.'.join(
                    [self.subdomain.replace('.', '-') + '-' + self.domain, self.tld])))

        def _punycode(domain):
            try:
                return idna.encode(domain['domain']).decode()
            except Exception:
                return ''

        # 删除不合格的域名
        original_domain_score = self._similar_alg_entropy(
            '.'.join(filter(None, [self.subdomain, self.domain, self.tld])))
        tmp_domain = self.domains.copy()
        self.domains.clear()
        for domain in tmp_domain:
            if math.fabs(
                    self._similar_alg_entropy(domain.get('domain')) - original_domain_score) < self.threshold_value:
                domain['score'] = math.fabs(self._similar_alg_entropy(domain.get('domain')) - original_domain_score)
                if VALID_FQDN_REGEX.match(_punycode(domain)):
                    self.domains.add(domain)

        # 保留最相似的前top个
        tmp_domain = list(self.domains.copy())
        import operator
        tmp_domain.sort(key=operator.itemgetter('score'), reverse=False)
        _ = min(self.top, len(tmp_domain))
        self.domains = set(tmp_domain[:_]).copy()

    def permutations(self, registered=False, unregistered=False, dns_all=False):
        if (registered == False and unregistered == False) or (registered == True and unregistered == True):
            domains = self.domains.copy()
        elif registered == True:
            domains = set({x for x in self.domains.copy() if x.is_registered()})
        elif unregistered == True:
            domains = set({x for x in self.domains.copy() if not x.is_registered()})
        if not dns_all:
            for domain in domains:
                for k in ('dns_ns', 'dns_a', 'dns_aaaa', 'dns_mx'):
                    if k in domain:
                        domain[k] = domain[k][:1]
        return sorted(domains)

    def _similar_alg_entropy(self, data, choise='info_entropy'):
        # 用于删除低质量的域名
        if not data:
            return 0
        if choise == 'info_entropy':
            valid_chars = set(data)
            entropy = 0
            for x in valid_chars:
                p_x = float(data.count(x)) / len(data)
                if p_x > 0:
                    entropy += - p_x * math.log(p_x, 2)
            return entropy

    def _make_fig(self,domain,db=False):
        ''':cvar
        domains:生成的域名列表
        db:对比mongdb
        '''
        a = []
        b = []
        for x in self.domains:
            b.append(self._similar_alg_entropy(x['domain']))
            a.append(self._similar_alg_entropy(domain))
        mpl.rcParams["font.sans-serif"] = ["SimHei"]
        x = np.arange(0, len(b))
        if db:
            cc = []
            import pymongo
            client = pymongo.MongoClient("mongodb://ybkjadmin:Root123!@27.124.46.123:27017")
            collection = client['yuanbaotech_admin_v3']['similar_domain_info']
            for i in collection.find({'task_url': domain}, {}):
                db_t = i['similar_domain_list']
            for x in db_t:
                cc.append(math.fabs(self._similar_alg_entropy(x)))
            cc.sort(reverse=True)
            plt.plot(x, cc[:len(b)], c='blue', linestyle='-.', label="数据库", alpha=0.75)

        plt.plot(x, b, c='green', linestyle='-.', label="相似域名", alpha=0.75)
        plt.plot(x, a, c='red', label="原始域名")
        plt.scatter(x, b, c='yellow')
        plt.legend(loc='best')
        plt.ylabel("信息熵")
        plt.grid(True, alpha=0.5)
        plt.show()

def tld_filtering(set_dir, se="https://www.baidu.com/", save_name='4', filter=100000):
    ''':cvar
    域名过滤器，根据输入的域名集合，在百度上筛选，选出网站数量大于10w的后缀
    目前的数据来源：https://seo.juziseo.com/doc/tld/top500 + mongodb
    '''
    import re
    import time
    from selenium import webdriver
    import pandas as pd

    dir_ = {}
    d_ = set()
    driver = webdriver.Chrome()
    driver.get(se)
    p_input = driver.find_element_by_id('kw')
    for tld_ in set_dir:
        p_input.send_keys('site:{}'.format(tld_))
        p_btn = driver.find_element_by_id('su')
        p_btn.click()
        time.sleep(1)
        try:
            text = driver.find_element_by_xpath('//*[@id="content_left"]/div[1]/div/p[1]/b').text
            number = re.findall("\d+", text)  # 输出结果为列表
            if int(''.join(number)) > filter:
                d_.add(tld_)
            dir_[tld_] = int(''.join(number))
        except:
            dir_[tld_] = 0
        p_input.clear()
    pd.DataFrame.from_dict(dir_, orient='index').to_excel(save_name + '.xlsx')
    driver.close()
    print('保存：' + save_name + '.xlsx')
    return d_



def main():
    domain = 'ktea.com'
    fuzzers = ['addition', 'bitsquatting']
    url = UrlParser(domain)
    import time
    t1 = time.time()
    fuzz = Fuzzer(url.domain, tld_all=False, threshold_value=0.15, top=1000, tnum=20)
    fuzz.generate(fuzzers=fuzzers)
    t2 = time.time()
    print("fuzzer耗时：{} min".format((t2 - t1) / 60))
    domains = fuzz.domains
    fuzz._make_fig(url.domain)
    print(domains)


if __name__ == '__main__':
    main()
    # pass
