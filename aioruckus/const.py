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
ERROR_PASSPHRASE_LEN = "Passphrase can only contain between 8 and 63 characters or 64 HEX characters, space is not allowed"
ERROR_PASSPHRASE_JS = "Embedding html or javascript code, e.g. < />, is not allowed"
ERROR_PASSPHRASE_MISSING = "WPA2 and Mixed WPA2/3 WLANs require a passphrase"
ERROR_SAEPASSPHRASE_MISSING = "WPA3 and Mixed WPA2/3 WLANs require an SAE passphrase"
ERROR_PASSPHRASE_NAME = "You must also provide a name if you wish to override the passphrase"
ERROR_ACL_NOT_FOUND = "ACL not found"
ERROR_ACL_TOO_BIG = "ACLs may only contain 128 stations"
ERROR_ACL_SYSTEM = "Please use do_block_client() and do_unblock_client() to modify the System ACL"

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

class PatchNewAttributeMode(Enum):
    """Treatment of patch attributes which are missing from existing XML"""
    ERROR = "error"
    IGNORE = "ignore"
    ADD = "add"

URL_FILTERING_CATEGORIES = {
    "1": "Real Estate",
    "2": "Computer and Internet Security",
    "3": "Financial Services",
    "4": "Business and Economy",
    "5": "Computer and Internet Info",
    "6": "Auctions",
    "7": "Shopping",
    "8": "Cult and Occult",
    "9": "Travel",
    "10": "Abused Drugs",
    "11": "Adult and Pornography",
    "12": "Home and Garden",
    "13": "Military",
    "14": "Social Networking",
    "15": "Dead Sites",
    "16": "Stock and Advice Tools",
    "17": "Training and Tools",
    "18": "Dating",
    "19": "Sex Education",
    "20": "Religion",
    "21": "Entertainment and Arts",
    "22": "Personal sites and Blogs",
    "23": "Legal",
    "24": "Local Information",
    "25": "Streaming Media",
    "26": "Job Search",
    "27": "Gambling",
    "28": "Translation",
    "29": "Reference and Research",
    "30": "Shareware and Freeware",
    "31": "Peer to Peer",
    "32": "Marijuana",
    "33": "Hacking",
    "34": "Games",
    "35": "Philosophy and Political Advocacy",
    "36": "Weapons",
    "37": "Pay to Surf",
    "38": "Hunting and Fishing",
    "39": "Society",
    "40": "Educational Institutions",
    "41": "Online Greeting cards",
    "42": "Sports",
    "43": "Swimsuits & Intimate Apparel",
    "44": "Questionable",
    "45": "Kids",
    "46": "Hate and Racism",
    "47": "Personal Storage",
    "48": "Violence",
    "49": "Keyloggers and Monitoring",
    "50": "Search Engines",
    "51": "Internet Portals",
    "52": "Web Advertisements",
    "53": "Cheating",
    "54": "Gross",
    "55": "Web based Email",
    "56": "Malware Sites",
    "57": "Phishing and Other Frauds",
    "58": "Proxy Avoidance and Anonymizers",
    "59": "Spyware and Adware",
    "60": "Music",
    "61": "Government",
    "62": "Nudity",
    "63": "News and Media",
    "64": "Illegal",
    "65": "Content Delivery Networks",
    "66": "Internet Communications",
    "67": "Bot Nets",
    "68": "Abortion",
    "69": "Health and Medicine",
    "70": "Confirmed SPAM Sources",
    "71": "SPAM URLs",
    "72": "Unconfirmed SPAM Sources",
    "73": "Open HTTP Proxies",
    "74": "Dynamic Comment",
    "75": "Parked Domains",
    "76": "Alcohol and Tobacco",
    "77": "Private IP Addresses",
    "78": "Image and Video Search",
    "79": "Fashion and Beauty",
    "80": "Recreation and Hobbies",
    "81": "Motor Vehicles",
    "82": "Web Hosting",
    "83": "Food and Dining",
}

class UrlFilteringGroups(Enum):
    """URL Filtering groups"""
    NO_ADULT = [{'id': category, 'name': URL_FILTERING_CATEGORIES[category]} for category in ['68', '11', '70', '8', '18', '15', '46', '64', '49', '56', '32', '62', '37', '57', '71', '59', '72', '48', '36']]
    CLEAN_AND_SAFE = [{'id': category, 'name': URL_FILTERING_CATEGORIES[category]} for category in ['68', '10', '11', '67', '70', '8', '18', '15', '27', '54', '33', '46', '64', '49', '56', '32', '62', '37', '57', '58', '71', '59', '72', '48', '36']]
    CHILD_AND_STUDENT_FRIENDLY = [{'id': category, 'name': URL_FILTERING_CATEGORIES[category]} for category in ['68', '10', '11', '76', '67', '53', '70', '8', '18', '15', '27', '54', '33', '46', '64', '49', '56', '32', '62', '75', '37', '31', '57', '58', '44', '71', '59', '43', '72', '48', '36']]
    STRICT = [{'id': category, 'name': URL_FILTERING_CATEGORIES[category]} for category in ['68', '10', '11', '76', '6', '67', '53', '70', '8', '18', '15', '74', '27', '34', '54', '33', '46', '38', '64', '78', '49', '56', '32', '60', '62', '73', '75', '37', '31', '47', '57', '58', '44', '71', '19', '30', '7', '14', '39', '59', '25', '43', '72', '48', '36']]
