"""Constants used in aioruckus."""
from enum import Enum

# Error strings
ERROR_CONNECT_EOF = "Could not establish connection to host"
ERROR_CONNECT_TIMEOUT = "Timed out while waiting for client"
ERROR_CONNECT_TEMPORARY = "Temporarily unable to handle the request"
ERROR_POST_REDIRECTED = "Insufficient permission to run this command"
ERROR_POST_BADRESULT = "Unable to parse the response"
ERROR_POST_NORESULT = "The command was not understood"
ERROR_LOGIN_INCORRECT = "Login incorrect"
ERROR_INVALID_AP = "Invalid AP"
ERROR_ALLOCATED_AP = "AP already in another AP Group"
ERROR_INVALID_MAC = "Invalid MAC"
ERROR_INVALID_WLAN = "Invalid WLAN"
ERROR_PASSPHRASE_LEN = "Passphrase can only contain between 8 and 63 characters or 64 " \
     "HEX characters, space is not allowed"
ERROR_PASSPHRASE_JS = "Embedding html or javascript code, e.g. < />, is not allowed"
ERROR_PASSPHRASE_MISSING = "WPA2 and Mixed WPA2/3 WLANs require a passphrase"
ERROR_SAEPASSPHRASE_MISSING = "WPA3 and Mixed WPA2/3 WLANs require an SAE passphrase"
ERROR_PASSPHRASE_NAME = "You must also provide a name if you wish to override the passphrase"

class SystemStat(Enum):
    """Ruckus System Info section keys"""
    ALL = []
    ADMIN = ["admin"]
    CLUSTER = ["cluster"]
    DEFAULT = ["identity", "sysinfo", "port", "unleashed-network"]
    IDENTITY = ["identity"]
    MESH_POLICY = ["mesh-policy"]
    MGMT_IP = ["mgmt-ip"]
    MGMT_VLAN = ["mgmt-vlan"]
    PORT = ["port"]
    SYSINFO = ["sysinfo"]
    TIME = ["time"]
    UNLEASHED_NETWORK = ["unleashed-network"]

class WlanEncryption(Enum):
    """WLAN encryption types"""
    NONE = "none"
    OWE = "owe"
    WPA2 = "wpa2"
    WPA23_MIXED = "wpa23-mixed"
    WPA3 = "wpa3"
