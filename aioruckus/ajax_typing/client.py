"""Type Hints for AJAX Client Payloads"""

from __future__ import annotations
import sys

from .stats import Level1, Level2, Level3

if sys.version_info >= (3, 11):
    from typing import ClassVar, TypedDict, TypeVar
else:
    from typing_extensions import ClassVar, TypedDict, TypeVar

_ClientL1 = TypedDict(
    "_ClientL1",
    {
        # --- Base ZD 9.10 Fields ---
        "acct-multi-session-id": str,
        "acct-session-id": str,
        "ap": str,
        "auth-method": str,
        "called-station-id-type": str,
        "channel": str,
        "description": str,
        "dvcinfo-group": str,
        "dvcinfo": str,
        "first-assoc": str,
        "hostname": str,
        "ieee80211-radio-type": str,
        "ip": str,
        "ipv6": str,
        "location": str,
        "mac": str,
        "noise-floor": str,
        "num-interval-stats": str,
        "radio-type-text": str,
        "radio-type": str,
        "received-signal-strength": str,
        "role-id": str,
        "rssi": str,
        "ssid": str,
        "status": str,
        "user": str,
        "vap-mac": str,
        "vap-nasid": str,
        "vlan": str,
        "wlan-id": str,
        "wlan": str,
        "channelization": str,
        # --- ZD 10.1 Additions ---
        "ap-name": str,
        "ext-status": str,
        "rssi-level": str,
        # --- ZD 10.5 Additions ---
        "blocked": str,
        "dpsk-id": str,
        "dvctype": str,
        "encryption": str,
        "favourite": str,
        "model": str,
        "oldname": str,
        # --- Unleashed 200.7 Additions ---
        "group-id": str,
        # --- Unleashed 200.15 Additions ---
        "display-health-level": str,
        "health-level": str,
        "iot": str,
        "radio-band": str,
        "wpa-passphrase-len": str,
        "wpa-passphrase": str,
    },
)

ClientInterval = TypedDict(
    "ClientInterval",
    {
        # --- Base ZD 9.10 Fields ---
        "acct-multi-session-id": str,
        "acct-session-id": str,
        "ap": str,
        "associated-time": str,
        "authorized-time": str,
        "bin-start-time": str,
        "channel": str,
        "channelization": str,
        "dvcinfo": str,
        "first-received-signal-strength": str,
        "first-rssi": str,
        "hostname": str,
        "ieee80211-radio-type": str,
        "last-received-signal-strength": str,
        "last-rssi": str,
        "last-sample-time": str,
        "mac": str,
        "max-received-signal-strength": str,
        "max-rssi": str,
        "min-received-signal-strength": str,
        "min-rssi": str,
        "noise-floor": str,
        "peak-rx-bytes": str,
        "peak-tx-bytes": str,
        "radio-type": str,
        "received-signal-strength": str,
        "rssi": str,
        "rx-bytes": str,
        "rx-crc-errs": str,
        "rx-dup": str,
        "rx-pkts": str,
        "ssid": str,
        "throughput-est": str,
        "time": str,
        "tx-bytes": str,
        "tx-drop-data": str,
        "tx-drop-mgmt": str,
        "tx-pkts": str,
        "tx-rate": str,
        "user": str,
        "vap-mac": str,
        "vlan": str,
        "wlan": str,
        # --- ZD 10.5 Additions ---
        "dvctype": str,
        "model": str,
        # --- Unleashed 200.15 Additions ---
        "radio-band": str,
    },
)

_ClientL2 = TypedDict(
    "_ClientL2",
    {
        "avg-rssi": str,
        "total-rx-pkts": str,
        "total-tx-pkts": str,
        "total-retry-bytes": str,
        "total-rx-dup": str,
        "total-tx-reassoc": str,
        "total-rx-crc-errs": str,
        "total-usage-bytes": str,
        "total-rx-bytes": str,
        "total-tx-bytes": str,
        "total-retries": str,
        "total-rx-management": str,
        "total-tx-management": str,
        "tx-drop-data": str,
        "tx-drop-mgmt": str,
    },
)

_ClientL3 = TypedDict(
    "_ClientL3",
    {
        "interval-stats": list[ClientInterval],
    },
)

ApVapClientHistory = TypedDict(
    "ApVapClientHistory",
    {
        "tx-bytes": str,
        "rx-bytes": str,
    },
)

class Client:

    # pylint: disable=duplicate-bases
    class ClientL1(_ClientL1, Level1, total=False):
        """Client type with Level 1 stats."""

    class ClientL2(ClientL1, _ClientL2, Level2, total=False):
        """Client type with Level 2 stats."""


    class ClientL3(
        ClientL2, _ClientL3, Level3, total=False
    ):
        """Client type with Level 2 and interval stats."""

    ApLevelT = TypeVar("ApLevelT", ApL1, ApL2, ApL3)

    class ApVapClient(ClientL2, total=False):
        """Client type with level 2 and history stats."""

        history: ApVapClientHistory

client = Client()