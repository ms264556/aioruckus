
"""Utility functions shared by all APIs"""

import base64
import binascii
import xmltodict
import datetime
import random
import aiohttp
import re
import ssl
import xmltodict

from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from yarl import URL

from .const import ERROR_CONNECT_NOPARSE, ERROR_INVALID_MAC, ERROR_PASSPHRASE_JS, ERROR_PASSPHRASE_LEN, ERROR_POST_BADRESULT
from .exceptions import SchemaError

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

def unwrap_xml(xml: str, collection_elements: list[str] | None = None, aggressive_unwrap: bool = True) -> dict | list[dict]:
    # convert xml and unwrap collection
    force_list = None if not collection_elements else {ce: True for ce in collection_elements}
    result = xmltodict.parse(
        xml,
        encoding="utf-8",
        attr_prefix='',
        postprocessor=_process_ruckus_xml,
        force_list=force_list
    )
    collection_list = ([] if not collection_elements else [f"{ce}-list" for ce in collection_elements] + collection_elements)
    try:
        result = result["ajax-response"]["response"]
    except KeyError as kerr:
        raise SchemaError(ERROR_POST_BADRESULT) from kerr

    for key in (["apstamgr-stat"] if aggressive_unwrap else []) + collection_list:
        if result and key and key in result:
            result = result[key]
    return result or []

def _process_ruckus_xml(path, key, value):
    if key.startswith("x-"):
        # passphrases are obfuscated and stored with an x- prefix; decrypt these
        return key[2:], _decrypt_value(key, value) if value else value
    if key == "apstamgr-stat" and not value:
        # return an empty array rather than None, for ease of use
        return key, []
    if (
        (key == "accept" or key == "deny") and not value and
        path and len(path) > 0 and path[-1][0] == "acl"
    ):
        return key, []
    if (
        key == "status" and
        value and value.isnumeric() and
        path and len(path) > 0 and path[-1][0] == "client"
    ):
        # client status is numeric code for active, and name for inactive.
        # show name for everything
        description = (
            "Authorized" if value == "1" else
            "Authenticating" if value == "2" else
            "PSK Expired" if value == "3" else
            "Authorized(Deny)" if value == "4" else
            "Authorized(Permit)" if value == "5" else
            "Unauthorized"
        )
        return key, description
    return key, value

def _decrypt_value(key: str, encrypted_string: str) -> str:
    if key == "x-password" and len(encrypted_string) >= 16 and len(encrypted_string) % 4 == 0 and all(c.isalnum() or c in '/+=' for c in encrypted_string):
        try:
            encrypted_bytes = base64.b64decode(encrypted_string, validate=True)
            if len(encrypted_bytes) in (16, 32, 48):
                decryptor = Cipher(algorithms.AES(b'Svdlvt`Jefoujgz`QXE`ALFZ'), modes.ECB()).decryptor()
                padded_bytes = decryptor.update(encrypted_bytes) + decryptor.finalize()
                unpadder = PKCS7(128).unpadder()
                decrypted_bytes = unpadder.update(padded_bytes) + unpadder.finalize()
                return decrypted_bytes.decode('utf-8')
        except binascii.Error:
            pass
    return ''.join(chr(ord(letter) - 1) for letter in encrypted_string)