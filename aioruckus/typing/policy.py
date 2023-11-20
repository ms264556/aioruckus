"""Type Hints for Application Policies"""

from typing import Literal, TypedDict


AvpRule = TypedDict('AvpRule', {
    'rule-id': str, 'application-type': Literal['System Defined', 'Port base User Defined Application', 'IP base User Defined Application'],
    'rule-type': Literal['Denial Rules', 'QoS', 'Rate Limiting'], 'category-id': str, 'category': str, 'application-id': str, 'application': str,
    'action': Literal['accept', 'deny'], 'marking': str, 'uplink': str, 'downlink': str
    }, total=False)

AvpPolicy = TypedDict('AvpPolicy', {
    'id': str, 'name': str, 'description': str, 'default-mode': Literal['accept', 'deny'], 'avprule': list[AvpRule]
    }, total=False)

AvpApplication = TypedDict('AvpApplication', {
    'id': str, 'name': str, 'protocol': Literal['tcp', 'udp'] , 'src-ip': str, 'src-port': str, 'dst-ip': str, 'dst-port': str, 'netmask': str
    }, total=False)

AvpPort = TypedDict('AvpPort', {
    'id': str, 'name': str, 'port': str, 'protocol': Literal['tcp', 'udp']
    }, total=False)

IpRule = TypedDict('IpRule', {
    'action': Literal['accept', 'deny', 'restrict', 'auth'], 'type': Literal['layer 2', 'layer 3'],
    'ether-type': str,
    'app': Literal['HTTP', 'HTTPS', 'FTP', 'SSH', 'TELNET', 'SMTP', 'DNS', 'DHCP', 'SNMP'],
    'protocol': str, 'src-addr': str, 'src-port': str, 'dst-addr': str, 'dst-port': str, 'icmp-type': str
    }, total=False)

Ip4Policy = TypedDict('IpPolicy', {
    'id': str, 'name': str, 'default-mode': Literal['accept', 'deny'], 'internal-id': str, 'guestservice-id': str, 'type': str,
    'EDITABLE': str, 'rule': list[IpRule]
    }, total=False)

Ip6Policy = TypedDict('IpPolicy', {
    'id': str, 'name': str, 'default-mode': Literal['accept', 'deny'], 'internal-id': str, 'guestservice-id': str, 'type': str,
    'EDITABLE': str, 'rule6': list[IpRule]
    }, total=False)

UrlBlockCategory = TypedDict('UrlBlockCategory', {
    'id': str, 'name': str
    }, total=False)

UrlSafeSearchDns = TypedDict('UrlSafeSearchDns', {
    'enabled': Literal['true', 'false'], 'dns': str
    }, total=False)

UrlFilter = TypedDict('UrlFilter', {
    'id': str, 'name': str, 'description': str,
    'filtering-level': Literal['CUSTOM', 'NO_ADULT', 'CLEAN_AND_SAFE', 'CHILD_AND_STUDENT_FRIENDLY', 'STRICT'], 'blockcategories': list[UrlBlockCategory],
    'blacklist': list[str], 'whitelist': list[str],
    'safesearchgoogle': UrlSafeSearchDns, 'safesearchyoutube': UrlSafeSearchDns, 'safesearchbing': UrlSafeSearchDns
    }, total=False)

PreRule = TypedDict('PreRule', {
    'description': str, 'attr': str, 'order': list[Literal['AAA', 'Device Policy', 'WLAN']], 'EDITABLE': Literal['true', 'false']
    }, total=False)

PrecedencePolicy = TypedDict('PrecedencePolicy', {
    'id': str, 'name': str, 'EDITABLE': Literal['true', 'false'], 'prerule': list[PreRule]
    }, total=False)
