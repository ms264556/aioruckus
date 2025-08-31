"""Type Hints for Application Policies"""

from typing import Literal, Required, TypedDict

Radio = TypedDict('Radio', {
    "radio-type": str,
    "ieee80211-radio-type": str,
    "radio-id": str,
    "channel": str,
    "channel_seg2": str,
    "tx-power": str,
    "wmm-ac": str,
    "prot-mode": str,
    "vap-enabled": str,
    "wlangroup-id": str,
    "channel-select": str,
    "enabled": str,
    "channelization": str
}, total=False)

AdvMesh = TypedDict('AdvMesh', {
    "apply-acl": str
}, total=False)

PortDetail = TypedDict('PortDetail', {
    "id": str,
    "enabled": str,
    "tunnel": str,
    "opt82": str,
    "uplink": str,
    "untag": str,
    "members": str,
    "guestvlan": str,
    "dvlan": str,
    "dot1x": str
}, total=False)

Ports = TypedDict('Ports', {
    "port-num": str,
    "acctsvr-id": str,
    "authsvr-id": str,
    "mac-auth": str,
    "supplicant": str,
    "port": list[PortDetail]
}, total=False)

BonjourFencing = TypedDict('BonjourFencing', {
    "enable": str,
    "policy": str
}, total=False)

Ap = TypedDict('Ap', {
    "id": Required[str],
    "mac": Required[str],
    "last-seen": str,
    "ip": str,
    "netmask": str,
    "gateway": str,
    "dns1": str,
    "dns2": str,
    "ipv6-addr": str,
    "ipv6-plen": str,
    "ipv6-gateway": str,
    "ipv6-dns1": str,
    "ipv6-dns2": str,
    "application-reboot": str,
    "user-reboot": str,
    "push-reset-reboot": str,
    "kernel-panic-reboot": str,
    "watchdog-reboot": str,
    "powercycle-reboot": str,
    "reboot-reason": str,
    "reboot-detail": str,
    "rejoin-reason": str,
    "mesh-last-good-ssid": str,
    "mesh-last-good-psk": str,
    "ext-ip": str,
    "ext-port": str,
    "ext-ipv6": str,
    "ext-family": str,
    "tunnel-mode": str,
    "poe-mode": str,
    "name": str,
    "devname": Required[str],
    "model": Required[str],
    "description": str,
    "location": str,
    "coordinate_source": str,
    "gps": str,
    "group-id": str,
    "ipmode": str,
    "as-is": str,
    "as-is-ipv6": str,
    "bonjour-check": str,
    "psk": str,
    "mesh-enabled": str,
    "mesh-mode": str,
    "max-hops": str,
    "led-off": str,
    "usb-installed": str,
    "usb-port": str,
    "working-radio": str,
    "approved": str,
    "poe-mode-setting": str,
    "port-setting": str,
    "support-11ac": str,
    "version": Required[str],
    "build-version": str,
    "strong-cert": str,
    "config-state": str,
    "serial": Required[str],
    "udp-port": str,
    "support-11ax": str,
    "auth-mode": str,
    "blocked": str,
    "radio": list[Radio],
    "adv-mesh": AdvMesh,
    "ports": Ports,
    "venue-names": str | None,
    "bonjourfencing": BonjourFencing,
    "lacp-state": str,
    "cband-chann": str
}, total=False)

ApStatsIf = TypedDict('ApStatsIf', {
    "if-descr": str,
    "if-type": str,
    "if-name": str,
    "if-namedefined": str,
    "if-physAddress": str,
    "if-speed": str,
    "if-adminStatus": str,
    "if-operStatus": str,
    "if-inDiscards": str,
    "if-inErrors": str,
    "if-inNUcastPkts": str,
    "if-inOctets": str,
    "if-inUcastPkts": str,
    "if-inUnknownProtos": str,
    "if-outDiscards": str,
    "if-outErrors": str,
    "if-outNUcastPkts": str,
    "if-outOctets": str,
    "if-outUcastPkts": str,
    "if-mtu": str,
}, total=False)

ApStatsPort = TypedDict('ApStatsPort', {
    "name": str,
    "state": str,
    "tunnel": str,
    "opt82": str,
    "dvlan": str,
    "guestvlan": str,
    "mld-snooping": str,
    "igmp-snooping": str,
    "type": str,
    "vlan": str,
}, total=False)

ApStatsLanPort = TypedDict('ApStatsLanPort', {
    "Port": str,
    "Interface": str,
    "Dot1x": str,
    "Logical": str,
    "Physical": str,
    "Label": str,
    "name": str,
}, total=False)

ApStatsSpectrumCapability = TypedDict('ApStatsSpectrumCapability', {
    "gn": str,
    "an": str,
    "sniffer": str,
}, total=False)

ApStatsSpectrumStatus = TypedDict('ApStatsSpectrumStatus', {
    "running": str,
    "radio-id": str,
    "ip-addr": str,
    "port": str,
}, total=False)

ApStatsRadio = TypedDict('ApStatsRadio', {
    "ieee80211-radio-type": str,
    "tx-power": str,
    "wlangrp-wlan-num": str,
    "ap-max-wlan-num": str,
    "ap-current-wlan-num": str,
    "radio-id": str,
    "wmm-ac": str,
    "channel-select": str,
    "enabled": str,
    "vap-enabled": str,
    "bgscan": str,
    "tx-pkts-bcast": str,
    "tx-pkts-mcast": str,
    "rx-pkts-bcast": str,
    "rx-pkts-mcast": str,
    "tx-pkts-ucast": str,
    "rx-pkts-ucast": str,
    "radio-total-rx-pkts": str,
    "radio-total-rx-mcast": str,
    "radio-total-tx-pkts": str,
    "radio-total-tx-mcast": str,
    "radio-total-tx-fail": str,
    "radio-total-retries": str,
    "radio-total-rx-decrypt-error": str,
    "mgmt-rx-mgmt": str,
    "mgmt-tx-mgmt": str,
    "mgmt-auth-req": str,
    "mgmt-auth-resp": str,
    "mgmt-auth-success": str,
    "mgmt-auth-fail": str,
    "mgmt-assoc-req": str,
    "mgmt-assoc-resp": str,
    "mgmt-reassoc-req": str,
    "mgmt-reassoc-resp": str,
    "mgmt-assoc-success": str,
    "mgmt-assoc-fail": str,
    "mgmt-assoc-deny": str,
    "mgmt-disassoc-abnormal": str,
    "mgmt-disassoc-capacity": str,
    "mgmt-disassoc-leave": str,
    "mgmt-disassoc-misc": str,
    "antenna-gain": str,
    "beacon-period": str,
    "rts-threshold": str,
    "frag-threshold": str,
    "rf-samples": str,
    "noisefloor": str,
    "phyerr": str,
    "airtime-total": str,
    "airtime-busy": str,
    "airtime-rx": str,
    "airtime-tx": str,
    "avail-chan": str,
    "block-chan": str,
    "radio-type": str,
    "channel": str,
    "channel_seg2": str,
    "cfg-channel": str,
    "wlangroup_id": str,
    "prot-mode": str,
    "dfs-channel-11na": str,
    "channelization": str,
    "total-rx-pkts": str,
    "total-rx-bytes": str,
    "total-tx-pkts": str,
    "total-tx-bytes": str,
    "radio-total-rx-bytes": str,
    "radio-total-tx-bytes": str,
    "total-fcs-err": str,
    "num-sta": str,
    "assoc-stas": str,
    "avg-rssi": str,
}, total=False)

ApStats = TypedDict('ApStats', {
    "mac": Required[str],
    "id": str,
    "state": str,
    "ap-name": str,
    "devname": Required[str],
    "model": str,
    "ip": str,
    "ip-type": str,
    "netmask": str,
    "gateway": str,
    "dns1": str,
    "dns2": str,
    "by-dhcp": str,
    "external-ip": str,
    "external-port": str,
    "group-id": str,
    "approved": str,
    "support-11ac": str,
    "support-11ax": str,
    "psk": str,
    "max-client": str,
    "usb-installed": str,
    "usb-port": str,
    "poe-mode": str,
    "poe-mode-setting": str,
    "poe-tx-chain": str,
    "vid-pid": str,
    "usb-version": str,
    "hardware-version": str,
    "lacp-state": str,
    "strong-cert": str,
    "preSharedKey": str,
    "cpuArch": str,
    "tpmFlag": str,
    "rpkiCertStatus": str,
    "map-id": str,
    "x": str,
    "y": str,
    "as-is": str,
    "as-is-ipv6": str,
    "build-version": str,
    "bonjour-check": str,
    "bonjour-policy-name": str,
    "by-autoconfig": str,
    "ipv6-type": str,
    "ipv6-plen": str,
    "ipv6-gateway": str,
    "ipmode": str,
    "l3_conn_type": str,
    "ext-family": str,
    "ext-ipv6": str,
    "mgmt-vlan-id": str,
    "sys-pmtu": str,
    "ap-crashfile-flag": str,
    "current-temperature": str,
    "current-temperature-time": str,
    "lifetime-max-temperature": str,
    "lifetime-max-temperature-time": str,
    "lifetime-min-temperature": str,
    "lifetime-min-temperature-time": str,
    "application-reboot-counter": str,
    "user-reboot-counter": str,
    "reset-button-reboot-counter": str,
    "kernel-panic-reboot-counter": str,
    "watchdog-reboot-counter": str,
    "powercycle-reboot-counter": str,
    "last-reboot-reason": str,
    "last-rejoin-reason": str,
    "last-reboot-details": str,
    "config-state": str,
    "coordinate_source": str,
    "name": str,
    "udp-port": str,
    "auth-mode": str,
    "tunnel-mode": str,
    "serial-number": Required[str],
    "gps": str,
    "firmware-version": Required[str],
    "bonjour-fence-en": str,
    "bonjour-fence-id": str,
    "fence-policy-name": str,
    "ipv6": str,
    "num-vap": str,
    "num-neighbors": str,
    "uptime-updatetime": str,
    "last-seen-by-mesh": str,
    "last-config": str,
    "registered": str,
    "mem_avail": str,
    "mem_total": str,
    "cpu_util": str,
    "fw_size": str,
    "fw_part_size": str,
    "lan_stats_rx_byte": str,
    "lan_stats_rx_pkt_err": str,
    "lan_stats_rx_pkt_succ": str,
    "lan_stats_rx_pkt_mcast": str,
    "lan_stats_dropped": str,
    "lan_stats_tx_byte": str,
    "lan_stats_tx_pkt": str,
    "lan_stats_rx_pkt_bcast": str,
    "lan_stats_rx_pkt_mcast2": str,
    "lan_stats_tx_pkt_bcast": str,
    "lan_stats_tx_pkt_mcast": str,
    "wlan_tx_drop_frame": str,
    "wlan_tx_error_frame": str,
    "sta_tx_byte": str,
    "sta_rx_byte": str,
    "last-oclock-serviceup-time": str,
    "num-interval-stats": str,
    "total-boot-counter": str,
    "ap-join-counter": str,
    "stay-sole-run-counter": str,
    "nonrun-reboot-counter": str,
    "num-sta": str,
    "assoc-stas": str,
    "num-rogue": str,
    "uptime": str,
    "last-seen": str,
    "firstAssoc": str,
    "amount-connected-time": str,
    "mesh-enabled": str,
    "mesh-depth": str,
    "mesh-num-uplink-acquired": str,
    "num-uplink": str,
    "num-downlinks": str,
    "mesh-activated": str,
    "mesh-uplink-type": str,
    "mesh-mode": str,
    "num-uplink-history": str,
    "num-scan-history": str,
    "mesh-state": str,
    "location": str,
    "description": str,
    "cm-mac": str,
    "cm-wanip": str,
    "cm-uptime": str,
    "cm-fwver": str,
    "cm-status": str,
    "cm-ds-snr1": str,
    "cm-ds-snr2": str,
    "cm-ds-snr3": str,
    "cm-ds-snr4": str,
    "cm-ds-snr5": str,
    "cm-ds-snr6": str,
    "cm-ds-snr7": str,
    "cm-ds-snr8": str,
    "cm-us-txpow1": str,
    "cm-us-txpow2": str,
    "cm-us-txpow3": str,
    "cm-us-txpow4": str,
    "channel-11ng": str,
    "tx-power-11ng": str,
    "channelization-11ng": str,
    "channel-11na": str,
    "tx-power-11na": str,
    "channelization-11na": str,
    "if": list[ApStatsIf],
    "port": list[ApStatsPort],
    "lan-port": list[ApStatsLanPort],
    "spectrum-capability": ApStatsSpectrumCapability,
    "spectrum-status": ApStatsSpectrumStatus,
    "radio": list[ApStatsRadio],
}, total=False)

WlanRrm = TypedDict('WlanRrm', {
    "neighbor-report": str,
}, total=False)

WlanSmartcast = TypedDict('WlanSmartcast', {
    "mcast-filter": str,
    "directed-mcast": str,
}, total=False)

WlanAvpPolicy = TypedDict('WlanAvpPolicy', {
    "avp-enabled": str,
    "avpdeny-id": str,
}, total=False)

WlanQos = TypedDict('WlanQos', {
    "uplink-preset": str,
    "downlink-preset": str,
    "perssid-uplink-preset": str,
    "perssid-downlink-preset": str,
}, total=False)

WlanWpa = TypedDict('WlanWpa', {
    "cipher": str,
    "sae-passphrase": str,
    "passphrase": str,
    "dynamic-psk": str,
    "dynamic-psk-len": str,
    "dpsk-type": str,
    "expire": str,
    "start-point": str,
    "shared-dpsk": str,
    "shared-dpsk-num": str,
}, total=False)

WlanQueuePriority = TypedDict('WlanQueuePriority', {
    "voice": str,
    "video": str,
    "data": str,
    "background": str,
}, total=False)

WlanSchedule = TypedDict('WlanSchedule', {
    "value": str,
}, total=False)

WlanPrecedencePrerule = TypedDict('WlanPrecedencePrerule', {
    "description": str,
    "attr": str,
    "order": list[str],
    "EDITABLE": str,
    "moved": str,
}, total=False)

WlanPrecedence = TypedDict('WlanPrecedence', {
    "id": str,
    "name": str,
    "EDITABLE": str,
    "description": str,
    "prerule": list[WlanPrecedencePrerule],
}, total=False)

WlanAclAccept = TypedDict('WlanAclAccept', {
    "mac": str,
}, total=False)

WlanAcl = TypedDict('WlanAcl', {
    "id": str,
    "name": str,
    "description": str,
    "default-mode": str,
    "EDITABLE": str,
    "accept": list[WlanAclAccept],
}, total=False)

WlanUrlFilteringBlockCategory = TypedDict('WlanUrlFilteringBlockCategory', {
    "id": str,
    "name": str,
}, total=False)

WlanUrlFilteringSafeSearch = TypedDict('WlanUrlFilteringSafeSearch', {
    "enabled": str,
    "dns": str,
}, total=False)

WlanUrlFilteringPolicy = TypedDict('WlanUrlFilteringPolicy', {
    "name": str,
    "description": str,
    "filtering-level": str,
    "blockcategories": list[WlanUrlFilteringBlockCategory],
    "id": str,
    "blacklist": list[str],
    "whitelist": list[str],
    "safesearchgoogle": WlanUrlFilteringSafeSearch,
    "safesearchyoutube": WlanUrlFilteringSafeSearch,
    "safesearchbing": WlanUrlFilteringSafeSearch,
}, total=False)

WlanDevicePolicyDevRule = TypedDict('WlanDevicePolicyDevRule', {
    "description": str,
    "osvendor": str,
    "action": str,
    "uplink-preset": str,
    "downlink-preset": str,
    "vlan": str,
    "osvendor-id": str,
    "dvctype-id": str,
    "dvctype": str,
}, total=False)

WlanDevicePolicy = TypedDict('WlanDevicePolicy', {
    "EDITABLE": str,
    "name": str,
    "description": str,
    "default-mode": str,
    "is-gateway-mode": str,
    "id": str,
    "devrule": list[WlanDevicePolicyDevRule],
}, total=False)

WlanPolicyRule = TypedDict('WlanPolicyRule', {
    "action": str,
    "type": str,
    "ether-type": str,
    "app": str,
    "protocol": str,
    "dst-port": str,
    "description": str,
    "src-addr": str,
    "dst-addr": str,
    "src-port": str,
}, total=False)

WlanPolicy = TypedDict('WlanPolicy', {
    "EDITABLE": str,
    "name": str,
    "description": str,
    "default-mode": str,
    "internal-id": str,
    "id": str,
    "rule": list[WlanPolicyRule],
}, total=False)

Wlan = TypedDict('Wlan', {
    "id": Required[str],
    "name": Required[str],
    "ssid": Required[str],
    "description": str,
    "ofdm-rate-only": str,
    "bss-minrate": str,
    "tx-rate-config": str,
    "authentication": str,
    "encryption": str,
    "do-802-11w": str,
    "is-guest": str,
    "max-clients-per-radio": str,
    "usage": str,
    "acctsvr-id": str,
    "acct-upd-interval": str,
    "do-802-11d": str,
    "do-wmm-ac": str,
    "option82": str,
    "option82-opt1": str,
    "option82-opt2": str,
    "option82-opt150": str,
    "option82-opt151": str,
    "option82-areaName": str,
    "force-dhcp": str,
    "force-dhcp-timeout": str,
    "dis-dgaf": str,
    "parp": str,
    "authstats": str,
    "sta-info-extraction": str,
    "enable-type": str,
    "idle-timeout": str,
    "max-idle-timeout": str,
    "called-station-id-type": str,
    "ci-whitelist-id": str,
    "client-isolation": str,
    "pool-id": str,
    "vlan-id": str,
    "dvlan": str,
    "https-redirection": str,
    "local-bridge": str,
    "dhcpsvr-id": str,
    "bgscan": str,
    "balance": str,
    "band-balance": str,
    "fast-bss": str,
    "pmk-cache-for-reconnect": str,
    "pmk-cache-time": str,
    "role-based-access-ctrl": str,
    "client-flow-log": str,
    "export-client-log": str,
    "wifi6": str,
    "dtim-period": str,
    "directed-mbc": str,
    "transient-client-mgnt": str,
    "close-system": str,
    "rrm": WlanRrm,
    "smartcast": WlanSmartcast,
    "avp-policy": WlanAvpPolicy,
    "urlfiltering-policy": WlanUrlFilteringPolicy,
    "qos": WlanQos,
    "wpa": WlanWpa,
    "queue-priority": WlanQueuePriority,
    "wlan-schedule": WlanSchedule,
    "precedence": WlanPrecedence,
    "devicepolicy": WlanDevicePolicy,
    "acl": WlanAcl,
    "policy": WlanPolicy,
}, total=False)

VapIntervalStats = TypedDict('VapIntervalStats', {
    'time': str,
    'bin-start-time': str,
    'tx-pkts': str,
    'rx-pkts': str,
    'tx-bytes': str,
    'rx-bytes': str,
    'tx-mgmt-bytes': str,
    'tx-mgmt-pkts': str,
    'rx-mgmt-bytes': str,
    'rx-mgmt-pkts': str,
    'tx-data-bytes': str,
    'tx-data-pkts': str,
    'rx-data-bytes': str,
    'rx-data-pkts': str,
    'tx-mcast-pkts': str,
    'tx-bcast-pkts': str,
    'rx-mcast-pkts': str,
    'rx-bcast-pkts': str,
    'tx-ucast-pkts': str,
    'rx-ucast-pkts': str,
    'tx-mgmt-drop-pkts': str,
    'tx-data-drop-pkts': str,
    'peak-tx-bytes': str,
    'peak-rx-bytes': str,
    'multicast': str,
    'rx-errors': str,
    'tx-errors': str,
    'authorized-connection': str,
    'bssid': str,
    'ssid': str,
    'ap': str,
    'radio-type': str,
    'ieee80211-radio-type': str,
    'channel': str,
    'previous-bin-data-flag': str
}, total=False)

Vap = TypedDict('Vap', {
    'bssid': str,
    'wlan': str,
    'ssid': str,
    'ap': str,
    'radio-type': str,
    'ieee80211-radio-type': str,
    'vap-up': str,
    'tx-ucast-pkts': str,
    'rx-ucast-pkts': str,
    'rx-drop-pkt': str,
    'tx-drop-pkt': str,
    'tx-errors': str,
    'tx-pkts': str,
    'rx-pkts': str,
    'multicast': str,
    'rx-errors': str,
    'num-interval-stats': str,
    'tx-bcast-pkts': str,
    'tx-mcast-pkts': str,
    'rx-bcast-pkts': str,
    'rx-mcast-pkts': str,
    'tx-mgmt-pkts': str,
    'rx-mgmt-pkts': str,
    'tx-mgmt-drop-pkts': str,
    'tx-data-drop-pkts': str,
    'radio-type-alias': str,
    'channel': str,
    'num-sta': str,
    'assoc-stas': str,
    'tx-bytes': str,
    'rx-bytes': str,
    'tx-data-pkts': str,
    'rx-data-pkts': str,
    'interval-stats': VapIntervalStats
}, total=False)

RogueDetection = TypedDict('RogueDetection', {
    'ap': str,
    'sys-name': str,
    'location': str,
    'rssi': str,
    'last-seen': str
}, total=False)

Rogue = TypedDict('Rogue', {
    'mac': Required[str],
    'id': Required[str],
    'recognized': str,
    'name': str,
    'ieee80211-radio-type': str,
    'num-detection': str,
    'rogue-type': str,
    'radio-type': str,
    'channel': str,
    'ssid': str,
    'is-open': str,
    'last-seen': str,
    'detection': RogueDetection
}, total=False)

Event = TypedDict('Event', {
    'msg': Required[str],
    'severity': Required[str],
    'time': Required[str],
    'c': Required[str],
    'ap': Required[str],
    'ap-name': Required[str],
    'lmsg': Required[str],
    'ap-desc': str,
    'uptime': str,
    'reason': str,
    'rogue': str,
    'ssid': str,
    'channel': str,
    'radioindex': str,
    'occur_time': str,
    'model': str,
    'mac': str,
    'wlan': str,
    'block': str,
    'ip': str,
}, total=False)

Alarm = TypedDict('Alarm', {
    'msg': Required[str],
    'severity': Required[str],
    'time': Required[str],
    'c': Required[str],
    'ap': Required[str],
    'ap-name': Required[str],
    'lmsg': Required[str],
    'ap-desc': str,
    'uptime': str,
    'reason': str,
    'rogue': str,
    'ssid': str,
    'channel': str,
    'radioindex': str,
    'occur_time': str,
    'model': str,
    'mac': str,
    'wlan': str,
    'block': str,
    'ip': str,
    'id': Required[str],
    'alarmdef-id': Required[str],
    'name': Required[str],
    'always-send-mail': Required[str],
    'occurs': Required[str],
}, total=False)

WlanGroup = TypedDict('WlanGroup', {
    'id': Required[str],
    'name': Required[str],
    'description': str,
    'wlansvc': list[Wlan]
}, total=False)

ApGroup = TypedDict('ApGroup', {
    'id': Required[str],
    'name': Required[str],
    'description': str,
    'ap': list[Ap]
}, total=False)

Client = TypedDict('Client', {
    'mac': Required[str],
    'ap': Required[str],
    'ap-name': str,
    'apMac': str,
    'auth-method': str,
    'blocked': str,
    'called-station-id-type': str,
    'channel': str,
    'channelization': str,
    'clientMac': str,
    'description': str,
    'dvcinfo': str,
    'dvcinfo-group': str,
    'dvctype': str,
    'dpsk-id': str,
    'encryption': str,
    'ext-status': str,
    'favourite': str,
    'first-assoc': str,
    'hostname': str,
    'ieee80211-radio-type': str,
    'ip': Required[str],
    'ipAddress': str,
    'ipv6': str,
    'location': str,
    'model': str,
    'noise-floor': str,
    'num-interval-stats': str,
    'oldname': str,
    'radio-type': str,
    'radio-type-text': str,
    'received-signal-strength': str,
    'role-id': str,
    'rssi': str,
    'rssi-level': str,
    'ssid': str,
    'status': str,
    'user': str,
    'vap-mac': str,
    'vap-nasid': str,
    'vlan': str,
    'wlan': str,
    'wlan-id': str,
    'acct-multi-session-id': str,
    'acct-session-id': str,
}, total=False)

AvpRule = TypedDict('AvpRule', {
    'rule-id': str,
    'application-type': Literal['System Defined', 'Port base User Defined Application', 'IP base User Defined Application'],
    'rule-type': Literal['Denial Rules', 'QoS', 'Rate Limiting'],
    'category-id': str,
    'category': str,
    'application-id': str,
    'application': str,
    'action': Literal['accept', 'deny'],
    'marking': str,
    'uplink': str,
    'downlink': str
}, total=False)

ArcPolicy = TypedDict('ArcPolicy', {
    'id': Required[str],
    'name': str,
    'description': str,
    'default-mode': Literal['accept', 'deny'],
    'avprule': list[AvpRule]
}, total=False)

ArcApplication = TypedDict('ArcApplication', {
    'id': Required[str],
    'name': str,
    'protocol': Literal['tcp', 'udp'],
    'src-ip': str,
    'src-port': str,
    'dst-ip': str,
    'dst-port': str,
    'netmask': str
}, total=False)

ArcPort = TypedDict('ArcPort', {
    'id': Required[str],
    'name': str,
    'port': str,
    'protocol': Literal['tcp', 'udp']
}, total=False)

IpRule = TypedDict('IpRule', {
    'action': Literal['accept', 'deny', 'restrict', 'auth'],
    'type': Literal['layer 2', 'layer 3'],
    'ether-type': str,
    'app': Literal['HTTP', 'HTTPS', 'FTP', 'SSH', 'TELNET', 'SMTP', 'DNS', 'DHCP', 'SNMP'],
    'protocol': str,
    'src-addr': str,
    'src-port': str,
    'dst-addr': str,
    'dst-port': str,
    'icmp-type': str
}, total=False)

Ip4Policy = TypedDict('Ip4Policy', {
    'id': Required[str],
    'name': str,
    'default-mode': Literal['accept', 'deny'],
    'internal-id': str,
    'guestservice-id': str,
    'type': str,
    'EDITABLE': str,
    'rule': list[IpRule]
}, total=False)

Ip6Policy = TypedDict('Ip6Policy', {
    'id': Required[str],
    'name': str,
    'default-mode': Literal['accept', 'deny'],
    'internal-id': str,
    'guestservice-id': str,
    'type': str,
    'EDITABLE': str,
    'rule6': list[IpRule]
}, total=False)

UrlBlockCategory = TypedDict('UrlBlockCategory', {
    'id': Required[str],
    'name': str
}, total=False)

UrlSafeSearchDns = TypedDict('UrlSafeSearchDns', {
    'enabled': Literal['true', 'false'],
    'dns': str
}, total=False)

UrlFilter = TypedDict('UrlFilter', {
    'id': Required[str],
    'name': str,
    'description': str,
    'filtering-level': Literal['CUSTOM', 'NO_ADULT', 'CLEAN_AND_SAFE', 'CHILD_AND_STUDENT_FRIENDLY', 'STRICT'],
    'blockcategories': list[UrlBlockCategory],
    'blacklist': list[str],
    'whitelist': list[str],
    'safesearchgoogle': UrlSafeSearchDns,
    'safesearchyoutube': UrlSafeSearchDns,
    'safesearchbing': UrlSafeSearchDns
}, total=False)

PreRule = TypedDict('PreRule', {
    'order': Required[list[Literal['AAA', 'Device Policy', 'WLAN']]],
    'description': str,
    'attr': str,
    'EDITABLE': Literal['true', 'false']
}, total=False)

PrecedencePolicy = TypedDict('PrecedencePolicy', {
    'id': Required[str],
    'name': str,
    'EDITABLE': Literal['true', 'false'],
    'prerule': list[PreRule]
}, total=False)

DevRule = TypedDict('DevRule', {
    'description': str,
    'osvendor': Literal['Windows', 'Android', 'Apple iOS', 'BlackBerry', 'Mac OS', 'Chrome OS', 'Linux', 'VoIP', 'Gaming', 'Printers'],
    'action': Literal['accept', 'deny'],
    'uplink-preset': str,
    'downlink-preset': str,
    'vlan': str,
    'osvendor-id': Literal['1', '2', '3', '4', '5', '6', '7', '8', '9', '10'],
    'dvctype-id': str,
    'dvctype': str
}, total=False)

DevicePolicy = TypedDict('DevicePolicy', {
    'id': Required[str],
    'name': str,
    'description': str,
    'default-mode': Literal['accept', 'deny'],
    'EDITABLE': Literal['true', 'false'],
    'is-gateway-mode': Literal['undefined'],
    'devrule': list[DevRule]
}, total=False)

Role = TypedDict('Role', {
    'id': Required[str],
    'name': str,
    'description': str,
    'radius-group-attr': str,
    'can-generate-pass': Literal['true', 'false'],
    'allow-all-wlansvc': Literal['true', 'false'],
    'allow-admin-priv': Literal['true', 'false'],
    'admin-priv': Literal['rw', 'op', 'ro'],
    'enable-access-ctrl': Literal['true', 'false'],
    'allow-all-dvc-types': Literal['true', 'false'],
    'vlan': str,
    'uplink-preset': str,
    'downlink-preset': str,
    'time-range-type': str,
    'allow-wlansvc': list[dict],
    'time-range': dict,
    'url-filtering': UrlFilter,
    'dvc-pcy': DevicePolicy,
    'arc-pcy': ArcPolicy,
    'policy': Ip4Policy,
    'policy6': Ip6Policy
}, total=False)

Dpsk = TypedDict('Dpsk', {
    'id': Required[str],
    'mac': str,
    'user': str,
    'passphrase': str,
    'last-rekey': str,
    'next-rekey': str,
    'start-point': str,
    'expire': str,
    'dvlan-id': str,
    'creation': str,
    'wlansvc': dict,
    'role': Role
}, total=False)

L2Rule = TypedDict('L2Rule', {
    'mac': Required[str],
    'type': Literal['single'],
    'hostname': str
}, total=False)

L2Policy = TypedDict('L2Policy', {
    'id': Required[str],
    'name': Required[str],
    'description': Required[str],
    'default-mode': Required[Literal['allow', 'deny']],
    'EDITABLE': Literal['true', 'false'],
    'deny': list[L2Rule],
    'accept': list[L2Rule]
}, total=False)

Mesh = TypedDict('Mesh', {
    'id': str,
    'name': Required[str],
    'psk': str
}, total=False)

class SzPermissionResourceItem(TypedDict, total=False):
    resource: str
    access: Literal["NA", "READ", "MODIFY", "FULL_ACCESS"]
    display: str

class SzPermissionCategory(TypedDict, total=False):
    resource: Required[str]
    access: Required[Literal["READ", "MODIFY", "FULL_ACCESS"]]
    display: str
    items: list[SzPermissionResourceItem]
    itemsDescription: list[str]
    ids: list[str]

class SzPermissionExtra(TypedDict, total=False):
    isSuperAdmin: bool
    isSuperAdminOfDomain: bool

class SzPermissionCategories(TypedDict, total=False):
    totalCount: int
    hasMore: bool
    firstIndex: int
    list: Required[list[SzPermissionCategory]]
    extra: SzPermissionExtra

class SzSession(TypedDict, total=False):
    cpId: Required[str]
    domainId: Required[str]
    adminId: Required[str]
    controllerVersion: Required[str]
    permissionCategories: Required[SzPermissionCategories]
    partnerDomain: str
    cpName: str
    cpSerialNumber: str

class NodeStateItem(TypedDict):
    nodeId: str
    nodeName: str
    nodeState: Literal["Out_Of_Service", "In_Service"]

class ManagementServiceStateItem(TypedDict):
    nodeId: str
    nodeName: str
    managementServiceState: Literal["Out_Of_Service", "In_Service"]

class SzClusterState(TypedDict, total=False):
    clusterName: Required[str]
    clusterState: Literal["In_Service", "Out_Of_Service", "Maintenance", "Read_Only", "NetworkPartitionSuspected"]
    clusterRole: Literal["Leader", "Follower"]
    currentNodeId: str
    currentNodeName: str
    nodeStateList: list[NodeStateItem]
    managementServiceStateList: list[ManagementServiceStateItem]