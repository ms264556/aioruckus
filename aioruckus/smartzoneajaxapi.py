"""Add enough AJAX methods to support Home Assistant"""

from __future__ import annotations

import asyncio
import sys
import time
from itertools import groupby
from operator import itemgetter

if sys.version_info >= (3, 12):
    from typing import Any, cast, override
else:
    from typing import cast

    from typing_extensions import Any, override

from .abcsession import ConfigItem
from .ajaxsession import AjaxSession
from .ajaxtyping import *
from .const import (
    ERROR_GUEST_PASS_BATCH_SIZE,
    ERROR_INVALID_WLAN,
    StatsLevel,
    SystemStat,
)
from .exceptions import AuthorizationError
from .ruckusajaxapi import RuckusAjaxApi
from .smartzonesession import SmartZoneSession
from .smartzonetyping import BlockClientDict, GuestPassDict
from .utility import *


class SmartZoneAjaxApi(RuckusAjaxApi):
    """Ruckus SmartZone compatibility shim"""
    __session: SmartZoneSession

    def __init__(self, session: AjaxSession):
        """Initialize the API with the given AjaxSession."""
        super().__init__(session)

    async def login(self) -> SmartZoneAjaxApi:
        """Create a SmartZone HTTPS session and log in."""
        self.__session = await SmartZoneSession(
            self.session.host,
            self.session.username,
            self.session.password,
            self.session.websession
        ).login()
        return self

    async def close(self) -> None:
        """Close the underlying HTTPS session."""
        await self.__session.close()

    async def get_aps(self) -> list[Ap]:
        """Return a list of APs"""
        aps = await self.__session.query("query/ap")
        return cast(list[Ap], [
            {**ap, "id": ap["apMac"], "mac": ap["apMac"], "devname": ap["deviceName"], "version": ap["firmwareVersion"]} 
            for ap in aps
        ])

    async def get_wlans(self) -> list[Wlan]:
        """Return a list of WLANs"""
        wlans = await self.__session.query("query/wlan")
        return cast(list[Wlan], [
            {**wlan, "id": wlan["wlanId"]}
            for wlan in wlans
        ])

    async def get_system_info(self, *sections: SystemStat) -> dict:
        """Return system information"""
        sz = self.__session.session_info
        assert sz
        return{
            "sysinfo": { "version": sz["controllerVersion"] ,"serial": sz["domainId"] if "partnerDomain" in sz else sz.get("cpSerialNumber", sz["cpId"]) },
            "identity": await self.get_mesh_info()
        }

    async def get_mesh_info(self) -> Mesh:
        """Return dummy mesh information"""
        # Mesh is per-zone in SmartZone. But we need to implement this because
        # Home Assistant uses the mesh name as the display name for any Ruckus
        # network. We will use the Partner Domain or Cluster Name if available.
        sz = self.__session.session_info
        assert sz
        return { "name": sz.get("partnerDomain") or sz.get("cpName", "SmartZone") }

    async def get_blocked_client_macs(self) -> list[L2Rule]:
        """Return a list of blocked client MACs"""
        blocks = await self.__session.query("blockClient/query")
        mac_key = itemgetter('mac')
        blocks.sort(key=mac_key)
        return cast(list[L2Rule], [
            {'mac': mac, 'zones': list(zones)}
            for mac, zones in groupby(blocks, key=mac_key)
        ])

    async def do_block_client(self, mac: str) -> None:
        """Block a client"""
        mac = normalize_mac_upper(mac)
        blocked_clients, aps = await asyncio.gather(
            self.get_blocked_client_macs(),
            self.__session.query("query/ap")
        )
        blocks = cast(list[BlockClientDict], blocked_clients)
        # identify zones where client is already blocked
        zones = next((b["zones"] for b in blocks if b["mac"] == mac), [])
        already_blocked_zones = {z["zoneId"] for z in zones}
        # identify a sample member AP per zone
        zone_ap_map = {ap["zoneId"]: ap for ap in aps}
        block_client_list = [
            ap for zone_id, ap in zone_ap_map.items()
            if zone_id not in already_blocked_zones
        ]
        if block_client_list:
            sz = self.__session.session_info
            assert sz
            ap_access = next((p["access"] for p in sz["permissionCategories"]["list"] if p["resource"].endswith("AP_CATEGORY")), None)
            if ap_access == "FULL_ACCESS":
                await self.__session.post("blockClient", {"blockClientList": [{"mac": mac, "apMac": ap["apMac"]} for ap in block_client_list]})
                return
            try:
                for block_client in block_client_list:
                    await self.__session.post(f"blockClient/byZoneId/{block_client['zoneId']}", {"mac": mac})
            except AuthorizationError:
                raise AuthorizationError("Blocking clients requires AP [Full Access] and Device [Read], or AP [Read] and Device [Full Access] permissions")

    async def do_unblock_client(self, mac: str) -> None:
        """Unblock a client"""
        mac = normalize_mac_upper(mac)
        blocks = cast(list[BlockClientDict], await self.get_blocked_client_macs())
        zones = next((b["zones"] for b in blocks if b["mac"] == mac), [])
        id_list = [z["id"] for z in zones]
        if id_list:
            try:
                await self.__session.delete("blockClient", {"idList": id_list})
            except AuthorizationError:
                raise AuthorizationError("Unblocking clients requires Device [Full Access] permissions")

    def _sz_guest_from_json(self, payload: GuestPassDict) -> Guest:
        """Normalize a SmartZone identity guest pass payload to the ``Guest`` shape."""
        pass_valid_for = payload.get("passValidFor") or {}
        session_duration = payload.get("sessionDuration") or {}
        max_devices = payload.get("maxDevices") or {}
        wlan = payload.get("wlan") or {}
        guest: dict[str, Any] = {
            "key": payload.get("key", ""),
            "id": payload.get("id", ""),
            "name": payload.get("guestName", ""),
            "ssid": payload.get("ssid") or wlan.get("name", ""),
            "created-by": payload.get("creatorUsername", ""),
            "create-time": payload.get("generatedOn", ""),
            "expire-time": payload.get("expirationDate", ""),
            "duration": str(pass_valid_for.get("expirationValue", "")),
            "duration-unit": (pass_valid_for.get("expirationUnit") or "").lower(),
            "reauth-enabled": str(session_duration.get("requireLoginAgain", "")).lower(),
            "reauth-interval": str(session_duration.get("sessionValue", "")),
            "reauth-interval-unit": (session_duration.get("sessionUnit") or "").lower(),
            "shared-guestpass": str(max_devices.get("maxDevicesAllowed", "")).lower(),
            "share-number": str(max_devices.get("maxDevicesNumber", "")),
            "remarks": payload.get("remarks", ""),
        }
        # SmartZone deletes are keyed by the guest user id, not the pass id
        guest["userId"] = payload.get("userId", "")
        return cast(Guest, guest)

    async def _sz_resolve_wlan_zone(self, ssid: str) -> tuple[dict, dict]:
        """Resolve a WLAN reference and its zone from an SSID."""
        wlan = next(
            (w for w in await self.get_wlans()
             if w.get("ssid") == ssid or w.get("name") == ssid),
            None,
        )
        if not wlan:
            raise ValueError(ERROR_INVALID_WLAN)
        zone: dict = {}
        if wlan.get("zoneId"):
            zone["id"] = wlan["zoneId"]
        if wlan.get("zoneName"):
            zone["name"] = wlan["zoneName"]
        return {"id": wlan["id"], "name": wlan.get("name", ssid)}, zone

    @override
    async def get_guest_passes(self) -> list[Guest]:
        """Return a list of guest passes"""
        sz = self.__session.session_info
        assert sz
        guests = await self.__session.query(
            "identity/guestpassList",
            {"filters": [{"type": "DOMAIN", "value": sz["domainId"]}]},
        )
        return cast(list[Guest], [
            self._sz_guest_from_json(cast(GuestPassDict, guest))
            for guest in guests
        ])

    @override
    async def do_add_guest_passes(
        self,
        ssid: str,
        duration: int = 1,
        duration_unit: str = "day",
        batch_size: int = 2,
        name: str = "",
        shared: bool = False,
        share_number: int = 1,
        reauth_enabled: bool = False,
        reauth_interval: str = "",
        reauth_interval_unit: str = "min",
        email: str = "",
        country_code: str = "",
        phone_number: str = "",
        remarks: str = "",
    ) -> list[Guest]:
        """Create a batch of guest passes on ``ssid`` and return the created passes.

        SmartZone generates the pass keys itself (``autoGeneratedPassword``)
        and requires a non-empty ``ssid`` and a ``batch_size`` between 2 and
        100. ``email`` / ``country_code`` / ``phone_number`` are accepted for
        API compatibility but ignored: SmartZone has no equivalent fields.
        """
        if not 2 <= batch_size <= 100:
            raise ValueError(ERROR_GUEST_PASS_BATCH_SIZE)
        wlan, zone = await self._sz_resolve_wlan_zone(ssid)
        sz = self.__session.session_info
        assert sz
        before = {guest["id"] for guest in await self.get_guest_passes()}
        await self.__session.post("identity/guestpass/generate", {
            "domainId": sz["domainId"],
            "guestName": name or f"batch-{int(time.time())}",
            "wlan": wlan,
            "zone": zone,
            "numberOfPasses": batch_size,
            "passValidFor": {"expirationValue": duration, "expirationUnit": duration_unit.upper()},
            "autoGeneratedPassword": True,
            "passEffectSince": "CREATION_TIME",
            "maxDevices": {
                "maxDevicesAllowed": "UNLIMITED" if shared else "LIMITED",
                "maxDevicesNumber": share_number,
            },
            "sessionDuration": {
                "requireLoginAgain": reauth_enabled,
                "sessionValue": int(reauth_interval or 0),
                "sessionUnit": reauth_interval_unit.upper(),
            },
            "remarks": remarks,
        })
        # the generate response does not enumerate the created passes; re-list
        # and return the passes that did not exist before the create
        return [
            guest for guest in await self.get_guest_passes()
            if guest.get("id") not in before
        ]

    @override
    async def do_add_guest_pass(
        self,
        ssid: str,
        name: str = "",
        x_key: str | None = None,
        duration: int = 1,
        duration_unit: str = "day",
        shared: bool = False,
        share_number: int = 1,
        reauth_enabled: bool = False,
        reauth_interval: str = "",
        reauth_interval_unit: str = "min",
        email: str = "",
        country_code: str = "",
        phone_number: str = "",
        remarks: str = "",
    ) -> Guest:
        """Create a single guest pass on ``ssid`` and return it.

        Pass a custom ``x_key`` (2-16 characters; no whitespace, #, &, +,
        ", ', <, > or comma) to use it directly; otherwise SmartZone
        auto-generates the pass key. A non-empty ``ssid`` is required.
        ``email`` / ``country_code`` / ``phone_number`` are accepted for API
        compatibility but ignored: SmartZone has no equivalent fields.
        """
        wlan, zone = await self._sz_resolve_wlan_zone(ssid)
        sz = self.__session.session_info
        assert sz
        if x_key is None:
            auto_generated = True
            pass_value = ""
        else:
            auto_generated = False
            pass_value = validate_guest_key(x_key).upper()
        before = {guest["id"] for guest in await self.get_guest_passes()}
        await self.__session.post("identity/guestpass/generate", {
            "domainId": sz["domainId"],
            "guestName": name or f"guest-{int(time.time())}",
            "wlan": wlan,
            "zone": zone,
            "numberOfPasses": 1,
            "passValidFor": {"expirationValue": duration, "expirationUnit": duration_unit.upper()},
            "autoGeneratedPassword": auto_generated,
            "passValue": pass_value,
            "passEffectSince": "CREATION_TIME",
            "maxDevices": {
                "maxDevicesAllowed": "UNLIMITED" if shared else "LIMITED",
                "maxDevicesNumber": share_number,
            },
            "sessionDuration": {
                "requireLoginAgain": reauth_enabled,
                "sessionValue": int(reauth_interval or 0),
                "sessionUnit": reauth_interval_unit.upper(),
            },
            "remarks": remarks,
        })
        # complete the guest (create-time, ...) from the list
        for guest in await self.get_guest_passes():
            if guest.get("id") not in before and (not x_key or guest.get("key") == pass_value):
                return guest
        return {
            "key": pass_value,
            "name": name,
            "ssid": ssid,
            "duration": str(duration),
            "duration-unit": duration_unit.lower(),
            "remarks": remarks,
        }

    @override
    async def do_remove_guest_passes(self, *keys: str) -> None:
        """Remove guest passes by their keys.

        SmartZone's delete commands only honour the internal guest user
        ``userId`` (a delete keyed by the pass ``id`` reports permission
        denied), so each key is resolved to its userId via the guest list
        before a DELETE on ``identity/guestpass`` is issued.
        """
        if not keys:
            return
        key_set = set(keys)
        guests = await self.get_guest_passes()
        missing = [key for key in keys if key not in {g.get("key") for g in guests}]
        if missing:
            raise ValueError(f"Guest pass key(s) not found: {', '.join(missing)}")
        id_list = [
            uid for uid in (g.get("userId") for g in guests if g.get("key") in key_set)
            if uid
        ]
        if id_list:
            await self.__session.delete("identity/guestpass", {"idList": id_list})

    async def get_active_clients(
        self,
        stats_level: StatsLevel | bool = StatsLevel.L1,
        interval_stats: bool | None = None,
    ) -> list[Client]:
        """Return a list of active clients

        SmartZone does not support the Unleashed/ZoneDirector stats levels;
        ``stats_level`` / ``interval_stats`` are accepted for interface
        compatibility with :class:`RuckusAjaxApi` and ignored.
        """
        clients = await self.__session.query("query/client")
        return cast(list[Client], [
            {**client, "mac": client["clientMac"], "ip": client["ipAddress"], "ap": client["apMac"]}
            for client in clients
        ])

    async def get_inactive_clients(self) -> list[Client]:
        """Return a list of inactive clients"""
        clients = await self.__session.query("query/historicalclient")
        return cast(list[Client], [
            {**client, "mac": client["clientMac"], "ip": client["ipAddress"], "ap": client["apMac"]}
            for client in clients
        ])

    async def get_ap_stats(
        self,
        stats_level: StatsLevel | bool = StatsLevel.L1,
        interval_stats: bool | None = None,
    ) -> list[ApStats]:
        """Return a list of AP statistics

        SmartZone does not support the Unleashed/ZoneDirector stats levels;
        ``stats_level`` / ``interval_stats`` are accepted for interface
        compatibility with :class:`RuckusAjaxApi` and ignored.
        """
        aps = await self.__session.query("query/ap")
        return cast(list[ApStats], [
            {**ap, "mac": ap["apMac"], "devname": ap["deviceName"], "firmware-version": ap["firmwareVersion"], "serial-number": ap["serial"]} 
            for ap in aps
        ])

    async def do_disable_wlan(self, name: str, disable_wlan: bool = True) -> None:
        """Disable a WLAN"""
        id_list = [wlan["wlanId"] for wlan in await self.__session.query("query/wlan") if wlan["name"] == name]
        if id_list:
            action = "disable" if disable_wlan else "enable"
            try:
                await self.__session.post(f"rkszones/wlans/{action}", {"idList": id_list})
            except AuthorizationError:
                raise AuthorizationError("Enable/disable WLAN requires WLAN [Modify] permissions")

    async def do_hide_ap_leds(self, mac: str, leds_off: bool = True) -> None:
        """Hide AP LEDs"""
        # This seems like A LOT of work to turn LEDs on and off!
        # Create an issue on github if you figure out a better way to achieve this
        mac = normalize_mac_upper(mac)
        leds_on = not leds_off
        ap = await self.__session.get(f"aps/{mac}")
        specific = ap.get("specific")
        if not specific:
            # PUT aps/{mac}/specific requires valid collection properties, even if
            # we just want defaults. So grab Group defaults
            specific = await self.__session.get(f"rkszones/{ap['zoneId']}/apgroups/{ap['apGroupId']}/apmodel/{ap['model']}")
        specific = remove_nones(specific)
        if specific.get("ledStatusEnabled") == leds_on:
            return
        specific["ledStatusEnabled"] = leds_on
        # GET aps/{mac} returns false for ledAdvancedEnabled if it's not applicable,
        # but PUT aps/{mac}/specific doesn't allow a false value in this case.
        # Hard to know what to do here, without maintaining a hard-coded
        # list of Advanced-LED APs
        if "ledAdvancedEnabled" in specific:
            del specific["ledAdvancedEnabled"]
        # GET aps/{mac} returns default lanPorts sub-properties which are
        # illegal to send back in our PUT aps/{mac}/specific payload
        for lanPort in specific["lanPorts"]:
            if "overwriteVlanEnabled" not in lanPort or not lanPort["overwriteVlanEnabled"]:
                if "vlanUntagId" in lanPort:
                    del lanPort["vlanUntagId"] 
                if "members" in lanPort:
                    del lanPort["members"]
        await self.__session.put(f"aps/{mac}/specific", specific)

    async def do_restart_ap(self, mac: str) -> None:
        """Restart AP"""
        mac = normalize_mac_upper(mac)
        await self.__session.put(f"aps/{mac}/reboot")

    #
    # Override the Unleashed/ZoneDirector base AJAX methods
    # so everything else fails.
    #
    @override
    async def _cmdstat_noparse(self, data: str, timeout: int | None = None) -> str:
        """Unsupported on SmartZone; always raises NotImplementedError."""
        raise NotImplementedError
    @override
    async def _conf_noparse(self, data: str, timeout: int | None = None) -> str:
        """Unsupported on SmartZone; always raises NotImplementedError."""
        raise NotImplementedError
    @override
    async def _get_conf_str(self, item: ConfigItem, timeout: int | None = None) -> str:
        """Unsupported on SmartZone; always raises NotImplementedError."""
        raise NotImplementedError
    @override
    async def _get_conf(self, item: ConfigItem, target_type: type | None = None) -> Any:
        """Unsupported on SmartZone; always raises NotImplementedError."""
        raise NotImplementedError