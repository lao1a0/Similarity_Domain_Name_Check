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
    _tld_dictionary = [('cc', 0.0), ('ee', 0.0), ('gg', 0.0), ('ooo', 0.0), ('tt', 0.0), ('app', 0.9182958340544896),
                       ('lol', 0.9182958340544896), ('AI', 1.0), ('Ai', 1.0), ('BE', 1.0), ('CA', 1.0), ('CL', 1.0),
                       ('DK', 1.0), ('ES', 1.0), ('FR', 1.0), ('GR', 1.0), ('ID', 1.0), ('IN', 1.0), ('IT', 1.0),
                       ('MT', 1.0), ('MX', 1.0), ('NO', 1.0), ('PL', 1.0), ('PT', 1.0), ('Pk', 1.0), ('RO', 1.0),
                       ('TV', 1.0), ('UA', 1.0), ('US', 1.0), ('ac', 1.0), ('ae', 1.0), ('ag', 1.0), ('ai', 1.0),
                       ('am', 1.0), ('ar', 1.0), ('at', 1.0), ('au', 1.0), ('az', 1.0), ('be', 1.0), ('bg', 1.0),
                       ('br', 1.0), ('by', 1.0), ('bz', 1.0), ('ca', 1.0), ('ch', 1.0), ('cl', 1.0), ('cm', 1.0),
                       ('cn', 1.0), ('co', 1.0), ('cx', 1.0), ('cy', 1.0), ('cz', 1.0), ('de', 1.0), ('dk', 1.0),
                       ('eg', 1.0), ('es', 1.0), ('eu', 1.0), ('fi', 1.0), ('fm', 1.0), ('fr', 1.0), ('ge', 1.0),
                       ('gh', 1.0), ('gq', 1.0), ('gr', 1.0), ('gs', 1.0), ('hk', 1.0), ('hr', 1.0), ('hu', 1.0),
                       ('id', 1.0), ('ie', 1.0), ('il', 1.0), ('im', 1.0), ('in', 1.0), ('io', 1.0), ('ir', 1.0),
                       ('is', 1.0), ('it', 1.0), ('jo', 1.0), ('jp', 1.0), ('ke', 1.0), ('kg', 1.0), ('kr', 1.0),
                       ('kz', 1.0), ('la', 1.0), ('lc', 1.0), ('li', 1.0), ('lk', 1.0), ('lt', 1.0), ('lu', 1.0),
                       ('lv', 1.0), ('ly', 1.0), ('md', 1.0), ('me', 1.0), ('mn', 1.0), ('ms', 1.0), ('mt', 1.0),
                       ('mx', 1.0), ('my', 1.0), ('ng', 1.0), ('nl', 1.0), ('no', 1.0), ('np', 1.0), ('nu', 1.0),
                       ('nz', 1.0), ('pe', 1.0), ('ph', 1.0), ('pk', 1.0), ('pl', 1.0), ('pt', 1.0), ('qa', 1.0),
                       ('ro', 1.0), ('rs', 1.0), ('ru', 1.0), ('sa', 1.0), ('se', 1.0), ('sg', 1.0), ('si', 1.0),
                       ('sk', 1.0), ('so', 1.0), ('su', 1.0), ('tm', 1.0), ('to', 1.0), ('tr', 1.0), ('tv', 1.0),
                       ('tw', 1.0), ('tz', 1.0), ('ua', 1.0), ('uk', 1.0), ('us', 1.0), ('va', 1.0), ('vc', 1.0),
                       ('ve', 1.0), ('vn', 1.0), ('ws', 1.0), ('za', 1.0), ('zw', 1.0), ('商城', 1.0), ('asia', 1.5),
                       ('beer', 1.5), ('coop', 1.5), ('guru', 1.5), ('Biz', 1.584962500721156),
                       ('COM', 1.584962500721156), ('NET', 1.584962500721156), ('Net', 1.584962500721156),
                       ('ORG', 1.584962500721156), ('Org', 1.584962500721156), ('art', 1.584962500721156),
                       ('biz', 1.584962500721156), ('cat', 1.584962500721156), ('cfd', 1.584962500721156),
                       ('com', 1.584962500721156), ('dev', 1.584962500721156), ('dog', 1.584962500721156),
                       ('edu', 1.584962500721156), ('fit', 1.584962500721156), ('fun', 1.584962500721156),
                       ('gov', 1.584962500721156), ('icu', 1.584962500721156), ('ink', 1.584962500721156),
                       ('int', 1.584962500721156), ('kim', 1.584962500721156), ('law', 1.584962500721156),
                       ('ltd', 1.584962500721156), ('mil', 1.584962500721156), ('net', 1.584962500721156),
                       ('one', 1.584962500721156), ('ong', 1.584962500721156), ('org', 1.584962500721156),
                       ('pro', 1.584962500721156), ('pub', 1.584962500721156), ('red', 1.584962500721156),
                       ('run', 1.584962500721156), ('top', 1.584962500721156), ('vip', 1.584962500721156),
                       ('win', 1.584962500721156), ('xin', 1.584962500721156), ('xyz', 1.584962500721156),
                       ('ac.at', 1.9219280948873623), ('bc.ca', 1.9219280948873623), ('canon', 1.9219280948873623),
                       ('press', 1.9219280948873623), ('tokyo', 1.9219280948873623), ('tools', 1.9219280948873623),
                       ('AERO', 2.0), ('Jobs', 2.0), ('LIVE', 2.0), ('aero', 2.0), ('band', 2.0), ('blog', 2.0),
                       ('blue', 2.0), ('city', 2.0), ('club', 2.0), ('cyou', 2.0), ('golf', 2.0), ('host', 2.0),
                       ('info', 2.0), ('jobs', 2.0), ('life', 2.0), ('link', 2.0), ('live', 2.0), ('love', 2.0),
                       ('mobi', 2.0), ('name', 2.0), ('news', 2.0), ('plus', 2.0), ('porn', 2.0), ('scot', 2.0),
                       ('shop', 2.0), ('show', 2.0), ('site', 2.0), ('team', 2.0), ('tech', 2.0), ('wang', 2.0),
                       ('work', 2.0), ('zone', 2.0), ('COM.MX', 2.2516291673878226), ('Global', 2.2516291673878226),
                       ('africa', 2.2516291673878226), ('asn.au', 2.2516291673878226), ('center', 2.2516291673878226),
                       ('com.cn', 2.2516291673878226), ('com.my', 2.2516291673878226), ('edu.au', 2.2516291673878226),
                       ('global', 2.2516291673878226), ('org.br', 2.2516291673878226), ('org.sg', 2.2516291673878226),
                       ('waw.pl', 2.2516291673878226), ('online', 2.251629167387823), ('CO.IN', 2.321928094887362),
                       ('CO.UK', 2.321928094887362), ('ac.il', 2.321928094887362), ('ac.in', 2.321928094887362),
                       ('ac.uk', 2.321928094887362), ('bj.cn', 2.321928094887362), ('cloud', 2.321928094887362),
                       ('co.id', 2.321928094887362), ('co.il', 2.321928094887362), ('co.in', 2.321928094887362),
                       ('co.jp', 2.321928094887362), ('co.ke', 2.321928094887362), ('co.kr', 2.321928094887362),
                       ('co.nz', 2.321928094887362), ('co.th', 2.321928094887362), ('co.uk', 2.321928094887362),
                       ('co.za', 2.321928094887362), ('co.zw', 2.321928094887362), ('fr.it', 2.321928094887362),
                       ('go.jp', 2.321928094887362), ('go.kr', 2.321928094887362), ('group', 2.321928094887362),
                       ('me.uk', 2.321928094887362), ('media', 2.321928094887362), ('on.ca', 2.321928094887362),
                       ('rocks', 2.321928094887362), ('space', 2.321928094887362), ('store', 2.321928094887362),
                       ('today', 2.321928094887362), ('video', 2.321928094887362), ('world', 2.321928094887362),
                       ('digital', 2.5216406363433186), ('website', 2.5216406363433186),
                       ('wedding', 2.5216406363433186), ('GOV.UK', 2.584962500721156), ('agency', 2.584962500721156),
                       ('com.ar', 2.584962500721156), ('com.au', 2.584962500721156), ('com.bd', 2.584962500721156),
                       ('com.bh', 2.584962500721156), ('com.br', 2.584962500721156), ('com.gh', 2.584962500721156),
                       ('com.hk', 2.584962500721156), ('com.np', 2.584962500721156), ('com.ph', 2.584962500721156),
                       ('com.pk', 2.584962500721156), ('com.pl', 2.584962500721156), ('com.sg', 2.584962500721156),
                       ('com.tr', 2.584962500721156), ('com.tw', 2.584962500721156), ('com.ua', 2.584962500721156),
                       ('com.vn', 2.584962500721156), ('design', 2.584962500721156), ('edu.cn', 2.584962500721156),
                       ('edu.in', 2.584962500721156), ('edu.my', 2.584962500721156), ('edu.ph', 2.584962500721156),
                       ('edu.pk', 2.584962500721156), ('gov.my', 2.584962500721156), ('gov.uk', 2.584962500721156),
                       ('gov.za', 2.584962500721156), ('insure', 2.584962500721156), ('nhs.uk', 2.584962500721156),
                       ('org.in', 2.584962500721156), ('org.my', 2.584962500721156), ('org.nz', 2.584962500721156),
                       ('org.uk', 2.584962500721156), ('org.za', 2.584962500721156), ('studio', 2.584962500721156),
                       ('travel', 2.584962500721156), ('investments', 2.7321588913645702),
                       ('roma.it', 2.8073549220576046), ('community', 2.94770277922009),
                       ('directory', 2.94770277922009), ('vicenza.it', 3.1219280948873624)]

    # _tld_dictionary = ['AERO', 'AI', 'Ai', 'BE', 'Biz', 'CA', 'CL', 'CO.IN', 'CO.UK', 'COM', 'COM.MX', 'DK', 'ES', 'FR',
    #                    'GOV.UK', 'GR', 'Global', 'ID', 'IN', 'IT', 'Jobs', 'LIVE', 'MT', 'MX', 'NET', 'NO', 'Net',
    #                    'ORG', 'Org', 'PL', 'PT', 'Pk', 'RO', 'TV', 'UA', 'US', 'ac', 'ac.at', 'ac.il', 'ac.in', 'ac.uk',
    #                    'ae', 'aero', 'africa', 'ag', 'agency', 'ai', 'am', 'app', 'ar', 'art', 'asia', 'asn.au', 'at',
    #                    'au', 'az', 'band', 'bc.ca', 'be', 'beer', 'bg', 'biz', 'bj.cn', 'blog', 'blue', 'br', 'by',
    #                    'bz', 'ca', 'canon', 'cat', 'cc', 'center', 'cfd', 'ch', 'city', 'cl', 'cloud', 'club', 'cm',
    #                    'cn', 'co', 'co.id', 'co.il', 'co.in', 'co.jp', 'co.ke', 'co.kr', 'co.nz', 'co.th', 'co.uk',
    #                    'co.za', 'co.zw', 'com', 'com.ar', 'com.au', 'com.bd', 'com.bh', 'com.br', 'com.cn', 'com.gh',
    #                    'com.hk', 'com.my', 'com.np', 'com.ph', 'com.pk', 'com.pl', 'com.sg', 'com.tr', 'com.tw',
    #                    'com.ua', 'com.vn', 'community', 'coop', 'cx', 'cy', 'cyou', 'cz', 'de', 'design', 'dev',
    #                    'digital', 'directory', 'dk', 'dog', 'edu', 'edu.au', 'edu.cn', 'edu.in', 'edu.my', 'edu.ph',
    #                    'edu.pk', 'ee', 'eg', 'es', 'eu', 'fi', 'fit', 'fm', 'fr', 'fr.it', 'fun', 'ge', 'gg', 'gh',
    #                    'global', 'go.jp', 'go.kr', 'golf', 'gov', 'gov.my', 'gov.uk', 'gov.za', 'gq', 'gr', 'group',
    #                    'gs', 'guru', 'hk', 'host', 'hr', 'hu', 'icu', 'id', 'ie', 'il', 'im', 'in', 'info', 'ink',
    #                    'insure', 'int', 'investments', 'io', 'ir', 'is', 'it', 'jo', 'jobs', 'jp', 'ke', 'kg', 'kim',
    #                    'kr', 'kz', 'la', 'law', 'lc', 'li', 'life', 'link', 'live', 'lk', 'lol', 'love', 'lt', 'ltd',
    #                    'lu', 'lv', 'ly', 'md', 'me', 'me.uk', 'media', 'mil', 'mn', 'mobi', 'ms', 'mt', 'mx', 'my',
    #                    'name', 'net', 'news', 'ng', 'nhs.uk', 'nl', 'no', 'np', 'nu', 'nz', 'on.ca', 'one', 'ong',
    #                    'online', 'ooo', 'org', 'org.br', 'org.in', 'org.my', 'org.nz', 'org.sg', 'org.uk', 'org.za',
    #                    'pe', 'ph', 'pk', 'pl', 'plus', 'porn', 'press', 'pro', 'pt', 'pub', 'qa', 'red', 'ro', 'rocks',
    #                    'roma.it', 'rs', 'ru', 'run', 'sa', 'scot', 'se', 'sg', 'shop', 'show', 'si', 'site', 'sk', 'so',
    #                    'space', 'store', 'studio', 'su', 'team', 'tech', 'tm', 'to', 'today', 'tokyo', 'tools', 'top',
    #                    'tr', 'travel', 'tt', 'tv', 'tw', 'tz', 'ua', 'uk', 'us', 'va', 'vc', 've', 'vicenza.it',
    #                    'video', 'vip', 'vn', 'wang', 'waw.pl', 'website', 'wedding', 'win', 'work', 'world', 'ws',
    #                    'xin', 'xyz', 'za', 'zone', 'zw', '商城']  # 域名存在性清洗后的，百度搜索能大于10w条结果的，304条
    # _tld_dictionary_score = [2.0, 1.0, 1.0, 1.0, 1.584962500721156, 1.0, 1.0, 2.321928094887362, 2.321928094887362,
    #                          1.584962500721156, 2.2516291673878226, 1.0, 1.0, 1.0, 2.584962500721156, 1.0,
    #                          2.2516291673878226, 1.0, 1.0, 1.0, 2.0, 2.0, 1.0, 1.0, 1.584962500721156, 1.0,
    #                          1.584962500721156, 1.584962500721156, 1.584962500721156, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0,
    #                          1.0, 1.9219280948873623, 2.321928094887362, 2.321928094887362, 2.321928094887362, 1.0, 2.0,
    #                          2.2516291673878226, 1.0, 2.584962500721156, 1.0, 1.0, 0.9182958340544896, 1.0,
    #                          1.584962500721156, 1.5, 2.2516291673878226, 1.0, 1.0, 1.0, 2.0, 1.9219280948873623, 1.0,
    #                          1.5, 1.0, 1.584962500721156, 2.321928094887362, 2.0, 2.0, 1.0, 1.0, 1.0, 1.0,
    #                          1.9219280948873623, 1.584962500721156, 0.0, 2.2516291673878226, 1.584962500721156, 1.0,
    #                          2.0, 1.0, 2.321928094887362, 2.0, 1.0, 1.0, 1.0, 2.321928094887362, 2.321928094887362,
    #                          2.321928094887362, 2.321928094887362, 2.321928094887362, 2.321928094887362,
    #                          2.321928094887362, 2.321928094887362, 2.321928094887362, 2.321928094887362,
    #                          2.321928094887362, 1.584962500721156, 2.584962500721156, 2.584962500721156,
    #                          2.584962500721156, 2.584962500721156, 2.584962500721156, 2.2516291673878226,
    #                          2.584962500721156, 2.584962500721156, 2.2516291673878226, 2.584962500721156,
    #                          2.584962500721156, 2.584962500721156, 2.584962500721156, 2.584962500721156,
    #                          2.584962500721156, 2.584962500721156, 2.584962500721156, 2.584962500721156,
    #                          2.94770277922009, 1.5, 1.0, 1.0, 2.0, 1.0, 1.0, 2.584962500721156, 1.584962500721156,
    #                          2.5216406363433186, 2.94770277922009, 1.0, 1.584962500721156, 1.584962500721156,
    #                          2.2516291673878226, 2.584962500721156, 2.584962500721156, 2.584962500721156,
    #                          2.584962500721156, 2.584962500721156, 0.0, 1.0, 1.0, 1.0, 1.0, 1.584962500721156, 1.0, 1.0,
    #                          2.321928094887362, 1.584962500721156, 1.0, 0.0, 1.0, 2.2516291673878226, 2.321928094887362,
    #                          2.321928094887362, 2.0, 1.584962500721156, 2.584962500721156, 2.584962500721156,
    #                          2.584962500721156, 1.0, 1.0, 2.321928094887362, 1.0, 1.5, 1.0, 2.0, 1.0, 1.0,
    #                          1.584962500721156, 1.0, 1.0, 1.0, 1.0, 1.0, 2.0, 1.584962500721156, 2.584962500721156,
    #                          1.584962500721156, 2.7321588913645702, 1.0, 1.0, 1.0, 1.0, 1.0, 2.0, 1.0, 1.0, 1.0,
    #                          1.584962500721156, 1.0, 1.0, 1.0, 1.584962500721156, 1.0, 1.0, 2.0, 2.0, 2.0, 1.0,
    #                          0.9182958340544896, 2.0, 1.0, 1.584962500721156, 1.0, 1.0, 1.0, 1.0, 1.0,
    #                          2.321928094887362, 2.321928094887362, 1.584962500721156, 1.0, 2.0, 1.0, 1.0, 1.0, 1.0, 2.0,
    #                          1.584962500721156, 2.0, 1.0, 2.584962500721156, 1.0, 1.0, 1.0, 1.0, 1.0, 2.321928094887362,
    #                          1.584962500721156, 1.584962500721156, 2.251629167387823, 0.0, 1.584962500721156,
    #                          2.2516291673878226, 2.584962500721156, 2.584962500721156, 2.584962500721156,
    #                          2.2516291673878226, 2.584962500721156, 2.584962500721156, 1.0, 1.0, 1.0, 1.0, 2.0, 2.0,
    #                          1.9219280948873623, 1.584962500721156, 1.0, 1.584962500721156, 1.0, 1.584962500721156, 1.0,
    #                          2.321928094887362, 2.8073549220576046, 1.0, 1.0, 1.584962500721156, 1.0, 2.0, 1.0, 1.0,
    #                          2.0, 2.0, 1.0, 2.0, 1.0, 1.0, 2.321928094887362, 2.321928094887362, 2.584962500721156, 1.0,
    #                          2.0, 2.0, 1.0, 1.0, 2.321928094887362, 1.9219280948873623, 1.9219280948873623,
    #                          1.584962500721156, 1.0, 2.584962500721156, 0.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0,
    #                          1.0, 3.1219280948873624, 2.321928094887362, 1.584962500721156, 1.0, 2.0,
    #                          2.2516291673878226, 2.5216406363433186, 2.5216406363433186, 1.584962500721156, 2.0,
    #                          2.321928094887362, 1.0, 1.584962500721156, 1.584962500721156, 1.0, 2.0, 1.0, 1.0]

    def __init__(self, domain, dictionary=[], tld_dictionary=[], tld_all=True, threshold_value=0.5, top=50, tnum=10):
        self.subdomain, self.domain, self.tld = domain_tld(domain)
        self.domain = self.domain
        self.dictionary = list(dictionary)
        self.tld_dictionary = tld_dictionary if len(tld_dictionary) > 0 else self._tld_dictionary
        self.domains = set()
        self.tld_all = tld_all  # 控制tld与域是否交叉组合
        self.threshold_value = threshold_value  # 相似度的阈值，控制生成域名的数量
        self.top = top  # 保留生成的相似度最高的域名数量，默认50个
        self.tnum = tnum  # tld_all时候的多线程
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
        # glyphs = md(self.glyphs_ascii, self.glyphs_idn_by_tld.get(self.tld, self.glyphs_unicode))
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
            for i in self.domain:
                for j in (45, *range(48, 58), *range(97, 123)):
                    if chr(j) == '-' and (self.domain.find(i) == 0 or self.domain.find(i) == len(self.domain) - 1):
                        continue
                    t.add(self.domain.replace(i, chr(j)))  # 字符替代插入
                    l_d = list(self.domain)
                    l_d.insert(self.domain.find(i), chr(j))
                    t.add(''.join(l_d))  # 字符直接插入
                    t.add(self.domain + chr(j))  # 字符直接插入
            for i in list(itertools.permutations(self.domain, len(self.domain))):  # 字符串本身排列组合
                t.add("".join(i))
        else:
            '''域名长度大于6，取前2后2'''
            for i in self.domain[:3]:
                for j in (*range(48, 58), *range(97, 123)):
                    if chr(j) == '-' and self.domain.find(i) == 0:
                        continue
                    t.add(self.domain.replace(i, chr(j)))  # 字符替代插入
                    l_d = list(self.domain)
                    l_d.insert(self.domain.find(i), chr(j))
                    t.add(''.join(l_d))  # 字符直接插入
                    t.add(self.domain + chr(j))  # 字符直接插入
            for i in self.domain[-3:]:
                for j in (45, *range(48, 58), *range(97, 123)):
                    if chr(j) == '-' and self.domain.find(i) == len(self.domain) - 1:
                        continue
                    t.add(self.domain.replace(i, chr(j)))  # 字符替代插入
                    l_d = list(self.domain)
                    l_d.insert(self.domain.find(i), chr(j))
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

    def _tld(self):
        '''
        过滤一下tld，删除信息熵偏差过大的域名
        :return:
        '''
        tld_init = self._similar_alg_entropy(self.tld)
        # print(tld_init, self.tld)
        _ = []
        for i, j in self._tld_dictionary:
            if math.fabs(j - tld_init) < self.threshold_value:
                _.append(i)
        if self.tld in _:
            _.remove(self.tld)
        return set(_)

    def _job_tld(self, data, q):
        original_domain_score = self._similar_alg_entropy(
            '.'.join(filter(None, [self.subdomain, self.domain, self.tld])))
        for tld in data:
            for j in self.domains:
                # __, _, ___ = domain_tld(j['domain'])
                __ = '.'.join(filter(None, [self.subdomain, j, tld]))  # 替换tld后的新域名
                # print(">_job_tld：",__)
                if VALID_FQDN_REGEX.match(self._punycode(__)):
                    if math.fabs(self._similar_alg_entropy(__) - original_domain_score) < self.threshold_value:
                        # j['domain'] = __
                        # j['score'] = self._similar_alg_entropy(__)
                        q.put({'fuzzer': 'tld-swap', 'domain': __, 'score': self._similar_alg_entropy(__)})

    def generate(self, fuzzers=[]):
        for f_name in fuzzers:
            try:
                f = getattr(self, '_' + f_name.replace('-', '_'))
            except AttributeError:
                pass
            else:
                original_domain_score = self._similar_alg_entropy(self.domain)
                for domain in f():  # 添加代码
                    if math.fabs(self._similar_alg_entropy(domain) - original_domain_score) < self.threshold_value:
                        # print('.'.join(filter(None, [self.subdomain, domain, self.tld])))
                        self.domains_tld.append(Permutation(fuzzer=f_name,
                                                            domain='.'.join(
                                                                filter(None, [self.subdomain, domain, self.tld])),
                                                            score=self._similar_alg_entropy(domain)))  # 保存的是最终的结果
                        self.domains.add(domain)  # 保存的是fuzzer后的域名
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
        # print(self.domains)
        # print(self.domains_tld)
        for _ in range(q.qsize()):
            self.domains_tld.append(q.get())
        # _ = []
        # for i in self.domains_tld:
        #     if i in _:
        #         continue
        #     else:
        #         _.append(i)
        # self.domains_tld = _
        self.domains_tld = sorted(self.domains_tld, key=lambda _: _['score'], reverse=False)

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

    def _make_fig(self, domain, db=False):
        ''':cvar
        domains:生成的域名列表
        db:对比mongdb
        '''
        a = []
        b = []
        for x in self.domains_tld:
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
    # domains=[{"fuzzer":"additon",'domain':"baidu.com",'score':7},{"fuzzer":"additon",'domain':"baidu.com",'score':7},
    #          {"fuzzer":"additon",'domain':"baidu.com",'score':7},{"fuzzer":"additon",'domain':"baidu.com",'score':7},
    #          {"fuzzer":"additon",'domain':"baidu.cdom",'score':7},{"fuzzer":"additon",'domain':"baidu.com",'score':7},
    #          {"fuzzer":"additon",'domain':"ba1idu.com",'score':7},{"fuzzer":"additon",'domain':"baidu.com",'score':7}
    #          ,{"fuzzer":"additon",'domain':"bairdu.com",'score':7},{"fuzzer":"additon",'domain':"baidu.com",'score':7}]
    # _ = []
    # for i in domains:
    #     if i in _:
    #         continue
    #     else:
    #         _.append(i)
    # domains = _
    # print(domains)
    pass
