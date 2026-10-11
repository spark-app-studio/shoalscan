import ssl

import aiohttp
import httpx
import requests
import urllib3

# ruleid: python-tls-verification-disabled
requests.get("https://example.com/api", verify=False)

# ruleid: python-tls-verification-disabled
requests.post(url, json=body, verify=False, timeout=5)

session = requests.Session()
# ruleid: python-tls-verification-disabled
session.verify = False

# ruleid: python-tls-verification-disabled
session.get(url, verify=False)

# ruleid: python-tls-verification-disabled
client = httpx.Client(verify=False)

# ruleid: python-tls-verification-disabled
ctx = ssl._create_unverified_context()

context = ssl.create_default_context()
# ruleid: python-tls-verification-disabled
context.verify_mode = ssl.CERT_NONE

# ruleid: python-tls-verification-disabled
conn = aiohttp.TCPConnector(ssl=False)

# ruleid: python-tls-verification-disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ok: python-tls-verification-disabled
requests.get("https://example.com/api", verify="/etc/ssl/private-ca.pem")

# ok: python-tls-verification-disabled
requests.get("https://example.com/api", verify=True)

# ok: python-tls-verification-disabled
requests.get("https://example.com/api")

# ok: python-tls-verification-disabled
context.verify_mode = ssl.CERT_REQUIRED

# ok: python-tls-verification-disabled
client = httpx.Client(verify=ctx_with_ca)
