"""Constants used in aioruckus."""
from enum import Enum

# Error strings
CONNECT_ERROR_EOF = "Could not establish connection to host"
CONNECT_ERROR_TIMEOUT = "Timed out while waiting for client"
CONNECT_ERROR_TEMPORARY = "Temporarily unable to handle the request"
AJAX_POST_REDIRECTED_ERROR = "Insufficient permission to run this command"
AJAX_POST_NORESULT_ERROR = "The command was not understood"
LOGIN_ERROR_LOGIN_INCORRECT = "Login incorrect"
VALUE_ERROR_INVALID_MAC = "Invalid MAC"
VALUE_ERROR_INVALID_PASSPHRASE_LEN = "Passphrase can only contain between 8 and 63 characters or 64 HEX characters, space is not allowed"
VALUE_ERROR_INVALID_PASSPHRASE_JS = "Embedding html or javascript code, e.g. < />, is not allowed"

class SystemStat(Enum):
    ALL = ""
    DEFAULT = "<identity/><sysinfo/><port/>"
    IDENTITY = "<identity/>"
    SYSINFO = "<sysinfo/>"
    PORT = "<port/>"
    ADMIN = "<admin/>"
    MESH_POLICY = "<mesh-policy/>"
