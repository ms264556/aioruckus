
"""Utility functions shared by all APIs"""

import datetime
import random
import aiohttp
import re
import ssl
from yarl import URL

from .const import ERROR_CONNECT_NOPARSE, ERROR_INVALID_MAC, ERROR_PASSPHRASE_JS, ERROR_PASSPHRASE_LEN

def get_host_url(host_str: str) -> URL:
    """Normalize the host input to a URL."""
    if "://" not in host_str:
        host_str = f"https://{host_str}"
    parsed_url = URL(host_str)
    if not parsed_url.host:
        raise ConnectionError(ERROR_CONNECT_NOPARSE)
    return parsed_url

def cast_timeout(timeout: aiohttp.ClientTimeout | int | None) -> aiohttp.ClientTimeout | None:
    return aiohttp.ClientTimeout(total=timeout) if isinstance(timeout, int) else timeout

def create_legacy_client_session() -> aiohttp.ClientSession:
    # create SSLContext which ignores certificate errors and allows old ciphers
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    ssl_context.set_ciphers("DEFAULT")
    # create ClientSession using our SSLContext, allowing cookies on IP address URLs,
    # with a short keepalive for compatibility with old Unleashed versions
    return aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=10),
        cookie_jar=aiohttp.CookieJar(unsafe=True),
        connector=aiohttp.TCPConnector(keepalive_timeout=5, ssl=ssl_context),
    )

def remove_nones(data: dict) -> dict:
    """Remove keys with values of None"""
    return {key: value for key, value in data.items() if value is not None}

def __normalize_mac_nocase(mac: str) -> str:
    """Normalize MAC address format"""
    if mac and re.fullmatch(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", mac):
        return mac.replace('-', ':')
    elif mac and re.fullmatch(r"[0-9a-fA-F]{12}", mac):
        return ':'.join(mac[i:i+2] for i in range(0, 12, 2))
    raise ValueError(ERROR_INVALID_MAC)

def normalize_mac_lower(mac: str) -> str:
    """Normalize MAC address format and casing"""
    return __normalize_mac_nocase(mac).lower()

def normalize_mac_upper(mac: str) -> str:
    """Normalize MAC address format and casing"""
    return __normalize_mac_nocase(mac).upper()

def ruckus_timestamp(time_part: bool = True, random_part: bool = True) -> str:
    return f"{int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000) if time_part else ''}{('.' if time_part and random_part else '')}{int(9000 * random.random()) + 1000 if random_part else ''}"

def validate_passphrase(passphrase: str) -> str:
    """Validate passphrase against ZoneDirector/Unleashed rules"""
    if passphrase and re.search(r"<.*>", string=passphrase):
        raise ValueError(ERROR_PASSPHRASE_JS)
    if passphrase and re.fullmatch(r"[!-~][ -~]{6,61}[!-~]|[0-9a-fA-F]{64}", passphrase):
        return passphrase
    raise ValueError(ERROR_PASSPHRASE_LEN)