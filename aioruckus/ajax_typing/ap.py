"""Type Hints for AJAX AP Payloads"""

# pylint: disable=duplicate-bases

from __future__ import annotations
import sys

from .stats import Level1, Level2, Level3


if sys.version_info >= (3, 11):
    from typing import Required, TypedDict, TypeVar
else:
    from typing_extensions import Required, TypedDict, TypeVar

ApIf = TypedDict(
    "ApIf",
    {
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
    },
    total=False,
)

ApPort = TypedDict(
    "ApPort",
    {
        # --- Base ZD 9.10 Fields ---
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
        # --- Unleashed 200.15 Additions ---
        "rate-downlink": str,
        "rate-uplink": str,
    },
    total=False,
)

ApLanPort = TypedDict(
    "ApLanPort",
    {
        # --- Base ZD 9.10 Fields ---
        "Port": str,
        "Interface": str,
        "Dot1x": str,
        "Logical": str,
        "Physical": str,
        "Label": str,
        # --- Unleashed 200.15 Additions ---
        "name": str,
    },
    total=False,
)

ApSpectrumCapability = TypedDict(
    "ApSpectrumCapability",
    {
        "gn": str,
        "an": str,
        "sniffer": str,
    },
    total=False,
)

ApSpectrumStatus = TypedDict(
    "ApSpectrumStatus",
    {
        "running": str,
        "radio-id": str,
        "ip-addr": str,
        "port": str,
    },
    total=False,
)

ApRadioL1 = TypedDict(
    "ApRadioL1",
    {
        # --- Base ZD 9.10 Fields ---
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
        "cfg-channel": str,
        "wlangroup_id": str,
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
        "spectralink-comp": str,
        # --- ZD 10.1 Additions ---
        "channel_seg2": str,
        "prot-mode": str,
        "dfs-channel-11na": str,
        # --- Unleashed 200.15 Additions ---
        "radio-band": str,
        "vap-enabled-setting": str,
        "tx-power-setting": str,
        "channelization-setting": str,
        "channel-select-setting": str,
        "channel-setting": str,
    },
    total=False,
)


ApRadioL3 = TypedDict(
    "ApRadioL3",
    {
        # --- Base ZD 9.10 Fields ---
        "radio-type": str,
        "ieee80211-radio-type": str,
        "airtime-util": str,
        "authorized-connection": str,
        "peak-tx-bytes": str,
        "peak-rx-bytes": str,
        "delta-chanchange": str,
        # --- Unleashed 200.15 Additions ---
        "radio-band": str,
    },
    total=False,
)

ApInterval = TypedDict(
    "ApInterval",
    {
        "time": str,
        "uptime": str,
        "rx-pkts": str,
        "tx-pkts": str,
        "rx-bytes": str,
        "peak-rx-bytes": str,
        "tx-bytes": str,
        "peak-tx-bytes": str,
        "mesh-depth": str,
        "max-num-clients": str,
        "mesh-uplink-rssi": str,
        "max-mesh-downlinks": str,
        "authorized-connection": str,
        "radio-stats": list[ApRadioL3],
    },
    total=False,
)

ApHistory = TypedDict(
    "ApHistory",
    {
        "rx-bytes-2.4g": str,
        "tx-bytes-2.4g": str,
        "rx-bytes-5g": str,
        "tx-bytes-5g": str,
        "rssi": str,
    },
)


RogueDetection = TypedDict(
    "RogueDetection",
    {"ap": str, "sys-name": str, "location": str, "rssi": str, "last-seen": str},
    total=False,
)

Rogue = TypedDict(
    "Rogue",
    {
        "mac": Required[str],
        "id": Required[str],
        "recognized": str,
        "name": str,
        "ieee80211-radio-type": str,
        "num-detection": str,
        "rogue-type": str,
        "radio-type": str,
        "channel": str,
        "ssid": str,
        "is-open": str,
        "last-seen": str,
        "detection": RogueDetection,
    },
    total=False,
)


_ApL1 = TypedDict(
    "_ApL1",
    {
        # --- Base ZD 9.10 Fields ---
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
        "psk": str,
        "max-client": str,
        "usb-installed": str,
        "poe-mode": str,
        "poe-mode-setting": str,
        "vid-pid": str,
        "usb-version": str,
        "hardware-version": str,
        "strong-cert": str,
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
        "num-interval-stats": str,
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
        "if": list[ApIf],
        "port": list[ApPort],
        "lan-port": list[ApLanPort],
        "spectrum-capability": ApSpectrumCapability,
        "spectrum-status": ApSpectrumStatus,
        "radio": list[ApRadioL1],
        "history": ApHistory,
        # --- ZD 10.1 Additions ---
        "support-11ac": str,
        "support-11ax": str,
        "poe-tx-chain": str,
        "lacp-state": str,
        "preSharedKey": str,
        "cpuArch": str,
        "tpmFlag": str,
        "rpkiCertStatus": str,
        "bonjour-fence-en": str,
        "bonjour-fence-id": str,
        "fence-policy-name": str,
        "ap-crashfile-flag": str,
        # --- ZD 10.5 Additions ---
        "mesh-state": str,
        # --- Unleashed 200.7 Additions ---
        "role": str,
        "fixed": str,
        # --- Unleashed 200.15 Additions ---
        "oem-model": str,
        "display-model": str,
        "poe-mode-str": str,
        "poe-mode-caps": str,
        "support-dedicated-master": str,
        "led-off": str,
        "priority": str,
        "allow-chan144": str,
        "usb-port": str,
    },
)

ApVapInterval = TypedDict(
    "ApVapInterval",
    {
        "time": str,
        "bin-start-time": str,
        "tx-pkts": str,
        "rx-pkts": str,
        "tx-bytes": str,
        "rx-bytes": str,
        "tx-mgmt-bytes": str,
        "tx-mgmt-pkts": str,
        "rx-mgmt-bytes": str,
        "rx-mgmt-pkts": str,
        "tx-data-bytes": str,
        "tx-data-pkts": str,
        "rx-data-bytes": str,
        "rx-data-pkts": str,
        "tx-mcast-pkts": str,
        "tx-bcast-pkts": str,
        "rx-mcast-pkts": str,
        "rx-bcast-pkts": str,
        "tx-ucast-pkts": str,
        "rx-ucast-pkts": str,
        "tx-mgmt-drop-pkts": str,
        "tx-data-drop-pkts": str,
        "peak-tx-bytes": str,
        "peak-rx-bytes": str,
        "multicast": str,
        "rx-errors": str,
        "tx-errors": str,
        "authorized-connection": str,
        "bssid": str,
        "ssid": str,
        "ap": str,
        "radio-type": str,
        "ieee80211-radio-type": str,
        "channel": str,
    },
    total=False,
)

ApVapL2 = TypedDict(
    "ApVapL2",
    {
        # --- Base ZD 9.10 Fields ---
        "bssid": str,
        "wlan": str,
        "ssid": str,
        "ap": str,
        "radio-type": str,
        "ieee80211-radio-type": str,
        "radio-type-alias": str,
        "channel": str,
        "num-sta": str,
        "assoc-stas": str,
        "vap-up": str,
        "tx-ucast-pkts": str,
        "rx-ucast-pkts": str,
        "rx-drop-pkt": str,
        "tx-drop-pkt": str,
        "tx-errors": str,
        "tx-pkts": str,
        "rx-pkts": str,
        "multicast": str,
        "rx-errors": str,
        "num-interval-stats": str,
        "tx-bcast-pkts": str,
        "tx-mcast-pkts": str,
        "rx-bcast-pkts": str,
        "rx-mcast-pkts": str,
        "tx-mgmt-pkts": str,
        "rx-mgmt-pkts": str,
        "tx-mgmt-drop-pkts": str,
        "tx-data-drop-pkts": str,
        "tx-bytes": str,
        "rx-bytes": str,
        "tx-data-pkts": str,
        "rx-data-pkts": str,
        # --- Unleashed 200.15 Additions ---
        "radio-band": str,
    },
    total=False,
)

_ApVapL3 = TypedDict(
    "_ApVapL3",
    {
        "client": list[ApVapClient],
        "interval-stats": list[ApVapInterval],
    },
)


class ApVapL3(ApVapL2, _ApVapL3):
    """ApVap type with client and interval stats."""


_ApL2 = TypedDict(
    "_ApL2",
    {
        "vap": list[ApVapL2],
        "rogue": list[Rogue],
    },
)

_ApL3 = TypedDict(
    "_ApL3",
    {
        "vap": list[ApVapL3],
        "rogue": list[Rogue],
        "interval-stats": list[ApInterval],
    },
)


class AccessPoint:

    class ApL1(_ApL1, Level1, total=False):
        """Basic AP operational data."""


    class ApL2(ApL1, _ApL2, Level2, total=False):
        """Enhanced AP operational data with VAP and Rogue info."""


    class ApL3(ApL1, _ApL3, Level3, total=False):
        """Enhanced AP operational data plus interval statistics."""

    ApLevelT = TypeVar("ApLevelT", ApL1, ApL2, ApL3)

ap = AccessPoint()
