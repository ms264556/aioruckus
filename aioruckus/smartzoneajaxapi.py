"""Add enough AJAX methods to support Home Assistant"""

from __future__ import annotations
import asyncio
from operator import itemgetter
from typing import Any, cast, override
from itertools import groupby

from .abcsession import ConfigItem
from .ajaxsession import AjaxSession
from .ajaxtyping import *
from .const import SystemStat
from .exceptions import AuthorizationError
from .ruckusajaxapi import RuckusAjaxApi
from .smartzonesession import SmartZoneSession
from .smartzonetyping import BlockClientDict
from .utility import *

class SmartZoneAjaxApi(RuckusAjaxApi):
    """Ruckus SmartZone compatibility shim"""
    __session: SmartZoneSession

    def __init__(self, session: AjaxSession):
        super().__init__(session)

    async def login(self) -> SmartZoneAjaxApi:
        self.__session = await SmartZoneSession(
            self.session.host,
            self.session.username,
            self.session.password,
            self.session.websession
        ).login()
        return self

    async def close(self) -> None:
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
                    await self.__session.post(f"blockClient/byZoneId/{block_client["zoneId"]}", {"mac": mac})
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

    async def get_active_clients(self, interval_stats: bool = False) -> list[Client]:
        """Return a list of active clients"""
        clients = await self.__session.query("query/client")
        return cast(list[Client], [
            {**client, "mac": client["clientMac"]}
            for client in clients
        ])

    async def get_inactive_clients(self) -> list[Client]:
        """Return a list of inactive clients"""
        clients = await self.__session.query("query/historicalclient")
        return cast(list[Client], [
            {**client, "mac": client["clientMac"]}
            for client in clients
        ])

    async def get_ap_stats(self) -> list[ApStats]:
        """Return a list of AP statistics"""
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
            specific = await self.__session.get(f"rkszones/{ap["zoneId"]}/apgroups/{ap["apGroupId"]}/apmodel/{ap["model"]}")
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
        raise NotImplementedError
    #
    @override
    async def _get_conf(self, item: ConfigItem, collection_elements: list[str] | None = None) -> Any:
        raise NotImplementedError