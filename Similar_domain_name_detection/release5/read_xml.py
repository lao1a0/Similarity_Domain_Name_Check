import re

try:
    import idna
except ImportError as e:
    class idna:
        @staticmethod
        def decode(domain):
            return domain.encode().decode('idna')

        @staticmethod
        def encode(domain):
            return domain.encode('idna')


def read_whois_server_xml(name='whois-server-list.xml'):
    import xml.etree.ElementTree as ET
    xml_data = open(name, 'r', encoding='utf-8').read()  # Read file
    root = ET.XML(xml_data)  # Parse XML
    data = dict()
    for i, child in enumerate(root):
        if (child.tag == 'domain') and (child.find('whoisServer') is not None):
            # print(child.attrib)
            # print(child.find('whoisServer').attrib)
            data[idna.encode(child.attrib['name']).decode().upper()] = child.find('whoisServer').attrib['host']
    # print(data)
    return data


from tew import *

cy = GenericTLD() # SponsoredTLD() # CountryCodeTLD()
ipA = IPv4Allocations()
re_data = read_whois_server_xml(name='whois-server-list.xml')
# print(re_data)
new_para = dict()

for i in dir(cy):  # 源文件
    if not (re.findall(r'^[\_\_]\w*', i)):
        _ = []
        if i in re_data:  # 补充文件
            # print(re_data[i.lower()])
            _.append(re_data[i])
        # print(getattr(cy, i))
        _.append(getattr(cy, i))
        new_para[i] = list(set(_))
for i, j in new_para.items():
    if len(j) == 1 and j[0] == None:
        print("{} = {}".format(i, j[0]))
    elif len(j) == 1 and j[0] is not None:
        print("{} = '{}'".format(i, j[0]))
    else:
        print("{} = random.choice({})".format(i, j))

# print(dir(cy))
# print(new_para.keys())
