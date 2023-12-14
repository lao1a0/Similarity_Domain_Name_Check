'''
@Time : 2023-06-16 17:58
@Author : laolao
@FileName: 1.py
'''
import asyncio
from pprint import pprint
import asyncwhois

# pick a domain
try:
    domain = ' nisuscorw.ink'
    # standard call
    result = asyncwhois.whois_domain(domain)
    print(">>", result.parser_output["admin_email"])
except Exception as e:
    print(e)
