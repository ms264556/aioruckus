"""Type Hints for Application Policies"""

from typing import Literal, TypedDict


AvpRule = TypedDict('AvpRule', {
    'rule-id': str, 'application-type': Literal['System Defined', 'Port base User Defined Application', 'IP base User Defined Application'],
    'rule-type': Literal['Denial Rules', 'QoS', 'Rate Limiting'], 'category-id': str, 'category': str, 'application-id': str, 'application': str,
    'action': Literal['accept', 'deny'], 'marking': str, 'uplink': str, 'downlink': str
    }, total=False)

ArcPolicy = TypedDict('ArcPolicy', {
    'id': str, 'name': str, 'description': str, 'default-mode': Literal['accept', 'deny'], 'avprule': list[AvpRule]
    }, total=False)

ArcApplication = TypedDict('ArcApplication', {
    'id': str, 'name': str, 'protocol': Literal['tcp', 'udp'] , 'src-ip': str, 'src-port': str, 'dst-ip': str, 'dst-port': str, 'netmask': str
    }, total=False)

ArcPort = TypedDict('ArcPort', {
    'id': str, 'name': str, 'port': str, 'protocol': Literal['tcp', 'udp']
    }, total=False)

IpRule = TypedDict('IpRule', {
    'action': Literal['accept', 'deny', 'restrict', 'auth'], 'type': Literal['layer 2', 'layer 3'],
    'ether-type': str,
    'app': Literal['HTTP', 'HTTPS', 'FTP', 'SSH', 'TELNET', 'SMTP', 'DNS', 'DHCP', 'SNMP'],
    'protocol': str, 'src-addr': str, 'src-port': str, 'dst-addr': str, 'dst-port': str, 'icmp-type': str
    }, total=False)

Ip4Policy = TypedDict('Ip4Policy', {
    'id': str, 'name': str, 'default-mode': Literal['accept', 'deny'], 'internal-id': str, 'guestservice-id': str, 'type': str,
    'EDITABLE': str, 'rule': list[IpRule]
    }, total=False)

Ip6Policy = TypedDict('Ip6Policy', {
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

DevRule = TypedDict('DevRule', {
    'description': str, 'osvendor': Literal['Windows', 'Android', 'Apple iOS', 'BlackBerry', 'Mac OS', 'Chrome OS', 'Linux', 'VoIP', 'Gaming', 'Printers'], 'action': Literal['accept', 'deny'],
    'uplink-preset': str, 'downlink-preset': str, 'vlan': str, 'osvendor-id': Literal['1', '2', '3', '4', '5', '6', '7', '8', '9', '10'], 'dvctype-id': str, 'dvctype': str
    }, total=False)

DevicePolicy = TypedDict('DevicePolicy', {
    'id': str, 'name': str, 'description': str, 'default-mode': Literal['accept', 'deny'], 'EDITABLE': Literal['true', 'false'], 'is-gateway-mode': Literal['undefined'] , 'devrule': list[DevRule]
    }, total=False)

Role = TypedDict('Role', {
    'id': str, 'name': str, 'description': str, 'radius-group-attr': str, 'can-generate-pass': Literal['true', 'false'], 'allow-all-wlansvc': Literal['true', 'false'],
    'allow-admin-priv': Literal['true', 'false'], 'admin-priv': Literal['rw', 'op', 'ro'],
    'enable-access-ctrl': Literal['true', 'false'], 'allow-all-dvc-types': Literal['true', 'false'],
    'vlan': str, 'uplink-preset': str, 'downlink-preset': str, 'time-range-type': str,
    'allow-wlansvc': list[dict], 'time-range': dict, 'url-filtering': UrlFilter, 'dvc-pcy': DevicePolicy,
    'arc-pcy': ArcPolicy, 'policy': Ip4Policy, 'policy6': Ip6Policy
    }, total=False)

Dpsk = TypedDict('Dpsk', {
    'id': str, 'mac': str, 'user': str, 'passphrase': str, 'last-rekey': str, 'next-rekey': str,
    'start-point': str, 'expire': str, 'dvlan-id': str, 'creation': str, 'wlansvc': dict, 'role': Role
    }, total=False)

L2Rule = TypedDict('L2Rule', {
    'mac': str, 'type': Literal['single'], 'hostname': str
    }, total=False)

L2Policy = TypedDict('L2Policy', {
    'id': str, 'name': str, 'description': str, 'EDITABLE': Literal['true', 'false'],
    'default-mode': Literal['allow', 'deny'], 'deny': list[L2Rule], 'accept': list[L2Rule]
    }, total=False)
