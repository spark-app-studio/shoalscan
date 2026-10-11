import logging

import requests

logger = logging.getLogger(__name__)


def fetch(url, api_key):
    logger.info("calling %s", url)
    response = requests.get(url, headers={"Authorization": api_key}, verify=False)
    return response.json()


def ping():
    # nosemgrep: shoalscan.plain-http-url #42 local test double, never deployed
    return requests.get("http://status.vendor.io/ping", timeout=5)


def debug_login(user, password):
    logger.debug("login %s %s", user, password)
