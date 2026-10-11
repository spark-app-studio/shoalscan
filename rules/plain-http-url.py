import requests

# ruleid: plain-http-url
API = "http://api.vendor.io/v1/items"

# ruleid: plain-http-url
requests.get("http://payments.internal:8080/charge")

# ok: plain-http-url
LOCAL = "http://localhost:8080/health"

# ok: plain-http-url
LOOPBACK = "http://127.0.0.1:9000"

# ok: plain-http-url
LOOPBACK_TEMPLATE = "http://127.0.0.1:{port}/"

# ok: plain-http-url
DOCS_PLACEHOLDER = "http://idp.example.com/token"

# ok: plain-http-url
RESERVED = "http://registry.test.invalid/v2"

# ok: plain-http-url
METADATA = "http://169.254.169.254/latest/meta-data/"

# ok: plain-http-url
SECURE = "https://api.vendor.io/v1/items"

# ok: plain-http-url
SVG_NS = "http://www.w3.org/2000/svg"

# ok: plain-http-url
if url.startswith("http://"):
    pass

# ruleid: plain-http-url
TRICK = "http://localhost@attacker.vendor.io/collect"

# ruleid: plain-http-url
BASE = "http://reg.vendor.io/v2"


def use_base():
    # ok: plain-http-url
    connect(BASE)
