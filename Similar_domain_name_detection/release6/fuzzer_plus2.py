#!/user/bin/python
# -*- coding: UTF-8 -*-
# !/usr/bin/env python
# coding: utf-8

import itertools
import math
import threading
from queue import Queue
import matplotlib.pyplot as plt
from pylab import mpl
import numpy as np
from simhash import Simhash

from dependent_function import Permutation, idna, VALID_FQDN_REGEX, UrlParser, domain_tld, my_reshape, save_domains


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
    _tld_dictionary = ['tt', 'group', 'canon', 'ir', 'uk', 'pl', 'co.ke', 'space', 'co.uk', 'com.pl', 'ws', 'ly', 'ms',
                       'news', 'pub', 'io', 'online', 'roma.it', 'com.tw', 'travel', 'pe', 'ar', 'global', 'website',
                       'us', 'co.zw', 'wang', 'waw.pl', 'by', 'hr', 'asn.au', 'com.ar', 'lt', 'cloud', 'asia', 'design',
                       'gs', 'su', 'com', 'com.br', 'xyz', 'dk', 'kg', 'live', 'cn', 'tools', 'co.kr', 'insure', 'vn',
                       'edu.ph', 'gov.uk', 'net', 'cfd', 'run', 'com.ph', 'directory', 'fm', 'lk', 'lol', 'aero',
                       'com.np', 'guru', 'ca', 'org.za', 'br', 'co.id', 'digital', 'top', 'com.bh', 'com.my', 'jp',
                       'studio', 'tm', 'fi', 'ag', 'blue', 'ooo', 'la', 'ru', 'media', 'org', 'one', 'ph', 'com.mx',
                       'xin', 'center', 'edu.pk', 'love', 'gov.my', 'ke', 'com.pk', 'com.tr', 'work', 'app', 'info',
                       'biz', 'jo', 'md', 'si', 'cx', 'law', 'so', 'vicenza.it', 'mobi', 'wedding', 'world',
                       'ac.uk', 'agency', 'bj.cn', 'cyou', 'se', 'edu', 'hk', 'pro', 'gov.za', 'red', 'ee', 'gg',
                       'plus', 'bg', 'cat', 'np', 'com.hk', 'qa', 'kim', 'edu.my', 'go.jp', 'porn', 'co.nz', 'org.sg',
                       'tv', 'mil', 'in', 'com.ua', 'cz', 'is', 'ie', 'ac', 'vc', 'fit', 'zone', 'ae', 'icu', 'win',
                       'za', 'va', 'az', 'sk', 'blog', 'today', 'il', 'mn', 'on.ca', 'co.jp', 'sg', 'cy', 'co.in', 'ch',
                       'link', 'pk', 'art', 'life', 'me', 'nhs.uk', 'press', 'es', 'tech', 'co.za', 'kz', 've', 'lc',
                       'tr', 'co.th', 'edu.in', 'rs', 'gq', 'africa', 'co.il', 'pt', 'mt', 'scot', 'lu', 'li', 'cm',
                       'club', 'nz', 'org.in', 'name', 'band', 'go.kr', 'gr', 'gh', 'golf', 'edu.cn', 'de', 'ong',
                       'org.nz', 'city', 'me.uk', 'ge', 'au', 'ltd', 'fun', 'gov', 'nl', 'to', 'ro', 'no', 'ua', 'beer',
                       'ink', 'cl', 'com.au', 'ac.il', 'show', 'ng', 'com.gh', 'coop', 'edu.au', 'eu', 'mx', 'ac.at',
                       'video', 'host', 'bc.ca', 'dog', 'ac.in', 'im', 'kr', 'org.br', 'site', 'com.vn', 'be', 'lv',
                       'zw', 'team', 'dev', 'fr', 'com.sg', 'investments', 'am', 'hu', 'tokyo', 'store', 'vip', 'id',
                       'bz', 'co', 'at', 'tz', 'jobs', 'int', 'my', 'tw', 'cc', 'com.cn', 'shop', 'ai', 'sa', 'it',
                       'nu', 'org.my', 'org.uk', 'rocks', 'eg', 'fr.it', 'community',
                       'com.bd']  # 域名存在性清洗后的，百度搜索能大于10w条结果的，269条

    def __init__(self, domain, dictionary=[], tld_dictionary=[], tld_all=True, threshold_value=(0.2, 1), top=50,
                 tnum=10):
        self.subdomain, self.domain, self.tld = domain_tld(domain)
        self.domain = self.domain
        self.dictionary = list(dictionary)
        self.tld_dictionary = tld_dictionary if len(tld_dictionary) > 0 else self._tld_dictionary
        self.domains = set()
        self.tld_all = tld_all
        self.threshold_value = threshold_value
        self.top = top
        self.tnum = tnum
        self.domains_tld = list()

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
        glyphs = md(self.glyphs_ascii)

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
        if len(self.domain) < 7:
            '''域名小于6位直接上全排列'''
            for i in list(itertools.permutations(self.domain, len(self.domain))):  # 字符串本身排列组合
                t.add("".join(i))
        for i in range(len(self.domain)):
            for j in (45, *range(48, 58), *range(97, 123)):
                if chr(j) == '-' and (i == 0 or i == len(self.domain) - 1):
                    continue
                t.add(self.domain[:i] + chr(j) + self.domain[i + 1:])  # 字符替代插入
                l_d = list(self.domain)
                l_d.insert(i, chr(j))
                t.add(''.join(l_d))  # 字符直接插入
                t.add(self.domain + chr(j))  # 字符直接插入
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

    def simhash_similarity(self, text1, text2):
        aa_simhash = Simhash(text1)
        bb_simhash = Simhash(text2)
        max_hashbit = max(len(bin(aa_simhash.value)), (len(bin(bb_simhash.value))))
        # 汉明距离
        distince = aa_simhash.distance(bb_simhash)
        similar = 1 - distince / max_hashbit
        return similar

    def _tld(self):
        '''
        过滤一下tld，删除信息熵偏差过大的域名
        :return:
        '''
        if self.tld in self._tld_dictionary:
            self._tld_dictionary.remove(self.tld)
        _ = []
        for i in self._tld_dictionary:
            score = self.simhash_similarity(self.tld, i)
            if self.threshold_value[0] < score < self.threshold_value[1]:
                _.append(i)
        return set(_)

    def _job_tld(self, data, q):
        for tld in data:
            for j in self.domains:
                __ = '.'.join(filter(None, [self.subdomain, j, tld]))  # 替换tld后的新域名
                if VALID_FQDN_REGEX.match(self._punycode(__)):
                    score = self.simhash_similarity('.'.join(filter(None, [self.subdomain, self.domain, self.tld])), __)
                    if self.threshold_value[0] < score < self.threshold_value[1]:
                        q.put({'fuzzer': 'tld-swap', 'domain': __, 'score': score})

    def _punycode(self, domain):
        try:
            return idna.encode(domain).decode()
        except Exception:
            return ''

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

    def generate(self, fuzzers=[]):
        for f_name in fuzzers:
            try:
                f = getattr(self, '_' + f_name.replace('-', '_'))
            except AttributeError:
                pass
            else:
                for domain in f():
                    score = self.simhash_similarity(self.domain, domain)
                    if self.threshold_value[0] < score < self.threshold_value[1]:
                        self.domains_tld.append(Permutation(fuzzer=f_name,
                                                            domain='.'.join(
                                                                filter(None, [self.subdomain, domain, self.tld])),
                                                            score=score))
                        self.domains.add(domain)
                self.domains_tld = list(set(self.domains_tld))
                self.domains = set(self.domains)
        # fuzzer后的域名与tld字典进行交叉生成
        q = Queue()
        threads = []  # 线程列表
        data = my_reshape(list(self._tld()), self.tnum)
        for i in range(self.tnum):
            t = threading.Thread(target=self._job_tld, args=(data[i], q))
            threads.append(t)
            t.start()
        for thread in threads:
            thread.join()
        for _ in range(q.qsize()):
            self.domains_tld.append(q.get())
        self.domains_tld = sorted(self.domains_tld, key=lambda _: _['score'], reverse=False)


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


if __name__ == '__main__':
    args = {
        'out': False,
        'domain': 'revved-industries.com',
        'option_lsh': 'ssdeep',  # 使用LSH算法评估网页相似度: ssdeep
        'threads': 30,
        'num': 500,  # 并发数
        'dns_type': 1,
        'fuzzer_num': 300000,  # 0-np.inf，inf代表输出所有的生成结果
        'threshold_value': (0.2, 1),
        'tld_all': True,
        'fuzzers': [
            'addition',
            'hyphenation',
            'omission',
            'subdomain',
            'transposition'
        ],
        'useragent': "",
        'request_timeout_http': 1.5
    }
    # 1.生成混淆域名
    import time
    t1 = time.time()
    url = UrlParser(args['domain'])
    fuzz = Fuzzer(domain=url.domain, tld_all=args['tld_all'], threshold_value=args['threshold_value'],
                  top=args['fuzzer_num'])
    fuzz.generate(args['fuzzers'])
    t2 = time.time()
    domains = list(fuzz.domains_tld)
    print("耗时：{}".format(t2-t1)) # 耗时：37.75210523605347
    save_domains(domains, "{} 3.2 相似域名".format(url.domain))

