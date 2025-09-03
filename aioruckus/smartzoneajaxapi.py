"""Adds enough AJAX methods to RuckusApi to support Home Assistant"""
from __future__ import annotations
import asyncio
from operator import itemgetter
from typing import cast
from itertools import groupby

from .exceptions import AuthorizationError
from .smartzonetyping import SzApOperational, SzBlockClient
from .ruckusajaxapi import RuckusAjaxApi
from .ajaxtyping import *

from .const import (
    SystemStat
)
from .ajaxsession import AjaxSession


class SmartZoneAjaxApi(RuckusAjaxApi):
    """Ruckus SmartZone Configuration, Statistics and Commands API"""
    session: AjaxSession

    def __init__(self, session: AjaxSession):
        super().__init__(session)

    async def get_aps(self) -> list[Ap]:
        """Return a list of APs"""
        aps = await self._get_ap_ops()
        compat_aps = [
            {**ap, "id": ap["apMac"], "mac": ap["apMac"], "devname": ap["deviceName"], "version": ap["firmwareVersion"]} 
            for ap in aps
        ]
        return cast(list[Ap], compat_aps)

    async def _get_ap_ops(self) -> list[SzApOperational]:
        """Return a list of AP Operational Information"""
        return await self.session.sz_query("ap")

    async def get_ap_groups(self) -> list[ApGroup]:
        """Return a list of AP groups"""
        raise NotImplementedError

    async def get_wlans(self) -> list[Wlan]:
        """Return a list of WLANs"""
        raise NotImplementedError

    async def get_wlan_groups(self) -> list[WlanGroup]:
        """Return a list of WLAN groups"""
        raise NotImplementedError

    async def get_urlfiltering_policies(self) -> list[UrlFilter]:
        """Return a list of URL Filtering Policies"""
        raise NotImplementedError

    async def get_urlfiltering_blockingcategories(self) -> list[UrlBlockCategory]:
        """Return a list of URL Filtering Blocking Categories"""
        raise NotImplementedError

    async def get_ip4_policies(self) -> list[Ip4Policy]:
        """Return a list of IP4 Policies"""
        raise NotImplementedError

    async def get_ip6_policies(self) -> list[Ip6Policy]:
        """Return a list of IP6 Policies"""
        raise NotImplementedError

    async def get_device_policies(self) -> list[DevicePolicy]:
        """Return a list of Device Policies"""
        raise NotImplementedError

    async def get_precedence_policies(self) -> list[PrecedencePolicy]:
        """Return a list of Precedence Policies"""
        raise NotImplementedError

    async def get_arc_policies(self) -> list[ArcPolicy]:
        """Return a list of Application Recognition & Control Policies"""
        raise NotImplementedError

    async def get_arc_applications(self) -> list[ArcApplication]:
        """Return a list of Application Recognition & Control User Defined Applications"""
        raise NotImplementedError

    async def get_arc_ports(self) -> list[ArcPort]:
        """Return a list of Application Recognition & Control User Defined Ports"""
        raise NotImplementedError

    async def get_roles(self) -> list[Role]:
        """Return a list of Roles"""
        raise NotImplementedError

    async def get_dpsks(self) -> list[Dpsk]:
        """Return a list of DPSKs"""
        raise NotImplementedError

    async def get_system_info(self, *sections: SystemStat) -> dict:
        """Return system information"""
        sz = self.session.smartzone_session
        assert sz
        mesh_info = await self.get_mesh_info()
        return{
            "sysinfo": { "version": sz["controllerVersion"] ,"serial": sz["domainId"] if "partnerDomain" in sz else sz.get("cpSerialNumber", sz["cpId"]) },
            "identity": mesh_info
        }

    async def get_mesh_info(self) -> Mesh:
        """Return dummy mesh information"""
        # Mesh is per-zone in SmartZone. But we need to implement this because
        # Home Assistant uses the mesh name as the display name for any Ruckus
        # network. We will use the Partner Domain or Cluster Name if available.
        sz = self.session.smartzone_session
        assert sz
        return { "name": sz.get("partnerDomain") or sz.get("cpName", "SmartZone") }

    async def get_zerotouch_mesh_ap_serials(self) -> list[dict]:
        """Return a list of Pre-approved AP serial numbers"""
        raise NotImplementedError

    async def get_acls(self) -> list[L2Policy]:
        """Return a list of ACLs"""
        raise NotImplementedError

    async def get_blocked_client_macs(self) -> list[L2Rule]:
        """Return a list of blocked client MACs"""
        blocks = (await self.session.sz_post(f"blockClient/query"))["list"]
        mac_key = itemgetter('mac')
        blocks.sort(key=mac_key)
        compat_blocks = [{'mac': mac, 'zones': list(zones)} for mac, zones in groupby(blocks, key=mac_key)]
        return cast(list[L2Rule], compat_blocks)

    async def do_block_client(self, mac: str) -> None:
        """Block a client"""
        mac = self.__normalize_mac(mac)
        blocked_clients, ap_ops = await asyncio.gather(
            self.get_blocked_client_macs(),
            self._get_ap_ops()
        )
        blocks = cast(list[SzBlockClient], blocked_clients)
        # identify zones where client is already blocked
        zones = next((b["zones"] for b in blocks if b["mac"] == mac), [])
        already_blocked_zones = {z["zoneId"] for z in zones}
        # identify a sample member AP per zone
        zone_ap_map = {ap["zoneId"]: ap for ap in ap_ops}
        block_client_list = [
            ap for zone_id, ap in zone_ap_map.items()
            if zone_id not in already_blocked_zones
        ]
        if block_client_list:
            assert self.session.smartzone_session
            ap_access = next((p["access"] for p in self.session.smartzone_session["permissionCategories"]["list"] if p["resource"].endswith("AP_CATEGORY")), None)
            if ap_access == "FULL_ACCESS":
                await self.session.sz_post("blockClient", {"blockClientList": [{"mac": mac, "apMac": ap["apMac"]} for ap in block_client_list]})
                return
            try:
                for block_client in block_client_list:
                    await self.session.sz_post(f"blockClient/byZoneId/{block_client["zoneId"]}", {"mac": mac})
            except AuthorizationError:
                raise AuthorizationError("Blocking clients requires AP [Full Access] and Device [Read], or AP [Read] and Device [Full Access] permissions")

    async def do_unblock_client(self, mac: str) -> None:
        """Unblock a client"""
        mac = self.__normalize_mac(mac)
        blocks = cast(list[SzBlockClient], await self.get_blocked_client_macs())
        zones = next((b["zones"] for b in blocks if b["mac"] == mac), [])
        id_list = [z["id"] for z in zones]
        if id_list:
            try:
                await self.session.sz_delete("blockClient", {"idList": id_list})
            except AuthorizationError:
                raise AuthorizationError("Unblocking clients requires Device [Full Access] permissions")

    async def get_active_clients(self, interval_stats: bool = False) -> list[Client]:
        """Return a list of active clients"""
        clients = await self.session.sz_query("client")
        compat_clients = [
            {**client, "mac": client["clientMac"]}
            for client in clients
        ]
        return cast(list[Client], compat_clients)

    async def get_inactive_clients(self) -> list[Client]:
        """Return a list of inactive clients"""
        clients = await self.session.sz_query("historicalclient")
        compat_clients = [
            {**client, "mac": client["clientMac"]}
            for client in clients
        ]
        return cast(list[Client], compat_clients)

    async def get_ap_stats(self) -> list[ApStats]:
        """Return a list of AP statistics"""
        aps = await self.session.sz_query("ap")
        compat_aps = [
            {**ap, "mac": ap["apMac"], "devname": ap["deviceName"], "firmware-version": ap["firmwareVersion"], "serial-number": ap["serial"]} 
            for ap in aps
        ]
        return cast(list[ApStats], compat_aps)

    async def get_ap_group_stats(self) -> list[ApGroup]:
        """Return a list of AP group statistics"""
        raise NotImplementedError

    async def get_vap_stats(self) -> list[Vap]:
        """Return a list of Virtual AP (per-radio WLAN) statistics"""
        raise NotImplementedError

    async def get_wlan_group_stats(self) -> list[WlanGroup]:
        """Return a list of WLAN group statistics"""
        raise NotImplementedError

    async def get_dpsk_stats(self) -> list[Dpsk]:
        """Return a list of AP group statistics"""
        raise NotImplementedError

    async def get_active_rogues(self) -> list[Rogue]:
        """Return a list of currently active rogue devices"""
        raise NotImplementedError

    async def get_known_rogues(self, limit: int = 300) -> list[Rogue]:
        """Return a list of known/recognized rogues devices"""
        raise NotImplementedError

    async def get_blocked_rogues(self, limit: int = 300) -> list[Rogue]:
        """Return a list of user blocked rogues devices"""
        raise NotImplementedError

    async def get_all_alarms(self, limit: int = 300) -> list[Alarm]:
        """Return a list of all alerts"""
        raise NotImplementedError

    async def get_all_events(self, limit: int = 300) -> list[Event]:
        """Return a list of all events"""
        raise NotImplementedError

    async def get_wlan_events(self, *wlan_ids, limit: int = 300) -> list[Event]:
        """Return a list of WLAN events"""
        raise NotImplementedError

    async def get_ap_events(self, *ap_macs, limit: int = 300) -> list[Event]:
        """Return a list of AP events"""
        raise NotImplementedError

    async def get_client_events(self, limit: int = 300) -> list[Event]:
        """Return a list of client events"""
        raise NotImplementedError

    async def get_wired_client_events(self, limit: int = 300) -> list[Event]:
        """Return a list of wired client events"""
        raise NotImplementedError

    async def get_syslog(self) -> str:
        """Return a list of syslog entries"""
        raise NotImplementedError

    async def get_backup(self) -> bytes:
        """Return a backup"""
        raise NotImplementedError

    async def do_delete_ap_group(self, name: str) -> bool:
        """Delete an AP group"""
        raise NotImplementedError

    async def do_disable_wlan(self, name: str, disable_wlan: bool = True) -> None:
        """Disable a WLAN"""
        raise NotImplementedError

    async def do_enable_wlan(self, name: str) -> None:
        """Enable a WLAN"""
        raise NotImplementedError

    async def do_set_wlan_password(
        self,
        name: str,
        passphrase: str,
        sae_passphrase: str | None = None
    ) -> None:
        raise NotImplementedError

    async def do_hide_ap_leds(self, mac: str, leds_off: bool = True) -> None:
        """Hide AP LEDs"""
        # This seems like A LOT of work to turn LEDs on and off!
        # Create an issue on github if you figure out a better way to achieve this
        mac = self.__normalize_mac(mac)
        leds_on = not leds_off
        ap = await self.session.sz_get(f"aps/{mac}")
        specific = ap.get("specific")
        if not specific:
            # PUT aps/{mac}/specific requires valid collection properties, even if
            # we just want defaults. So grab Group defaults
            specific = await self.session.sz_get(f"rkszones/{ap["zoneId"]}/apgroups/{ap["apGroupId"]}/apmodel/{ap["model"]}")
        specific = self.__remove_nones(specific)
        if specific.get("ledStatusEnabled") == leds_on:
            return
        specific["ledStatusEnabled"] = leds_on
        # GET aps/{mac} returns false for this property if it's not applicable,
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
        await self.session.sz_put(f"aps/{mac}/specific", specific)

    async def do_restart_ap(self, mac: str) -> None:
        """Restart AP"""
        mac = self.__normalize_mac(mac)
        await self.session.sz_put(f"aps/{mac}/reboot")

    @classmethod
    def __normalize_mac(cls, mac: str) -> str:
        """Normalize MAC address format and casing"""
        return cls._normalize_mac_nocase(mac).upper()
    
    @staticmethod
    def __remove_nones(data: dict) -> dict:
        return {key: value for key, value in data.items() if value is not None}
