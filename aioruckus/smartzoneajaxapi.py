"""Adds enough AJAX methods to RuckusApi to support Home Assistant"""

from re import IGNORECASE, match
from typing import List

from .ruckusajaxapi import RuckusAjaxApi
from .typing_policy import *

from .const import (
    ERROR_INVALID_MAC,
    ERROR_PASSPHRASE_LEN,
    ERROR_PASSPHRASE_JS,
    SystemStat
)
from .ajaxsession import AjaxSession

class SmartZoneAjaxApi(RuckusAjaxApi):
    """Ruckus SmartZone Configuration, Statistics and Commands API"""
    def __init__(self, session: AjaxSession):
        super().__init__(session)
    
    async def get_aps(self) -> List[dict]:
        """Return a list of APs"""
        aps = await self.session.sz_query("ap")
        compat_aps = [
            {**ap, "mac": ap["apMac"], "devname": ap["deviceName"], "version": ap["firmwareVersion"]} 
            for ap in aps
        ]
        return compat_aps

    async def get_ap_groups(self) -> List:
        """Return a list of AP groups"""
        raise NotImplementedError

    async def get_wlans(self) -> List[dict]:
        """Return a list of WLANs"""
        raise NotImplementedError

    async def get_wlan_groups(self) -> List[dict]:
        """Return a list of WLAN groups"""
        raise NotImplementedError

    async def get_urlfiltering_policies(self) -> list[UrlFilter | dict]:
        """Return a list of URL Filtering Policies"""
        raise NotImplementedError

    async def get_urlfiltering_blockingcategories(self) -> list[UrlBlockCategory | dict]:
        """Return a list of URL Filtering Blocking Categories"""
        raise NotImplementedError

    async def get_ip4_policies(self) -> list[Ip4Policy | dict]:
        """Return a list of IP4 Policies"""
        raise NotImplementedError

    async def get_ip6_policies(self) -> list[Ip6Policy | dict]:
        """Return a list of IP6 Policies"""
        raise NotImplementedError

    async def get_device_policies(self) -> list[DevicePolicy | dict]:
        """Return a list of Device Policies"""
        raise NotImplementedError

    async def get_precedence_policies(self) -> list[PrecedencePolicy | dict]:
        """Return a list of Precedence Policies"""
        raise NotImplementedError
    
    async def get_arc_policies(self) -> list[ArcPolicy | dict]:
        """Return a list of Application Recognition & Control Policies"""
        raise NotImplementedError

    async def get_arc_applications(self) -> list[ArcApplication | dict]:
        """Return a list of Application Recognition & Control User Defined Applications"""
        raise NotImplementedError

    async def get_arc_ports(self) -> list[ArcPort | dict]:
        """Return a list of Application Recognition & Control User Defined Ports"""
        raise NotImplementedError

    async def get_roles(self) -> list[Role | dict]:
        """Return a list of Roles"""
        raise NotImplementedError

    async def get_dpsks(self) -> list[Dpsk | dict]:
        """Return a list of DPSKs"""
        raise NotImplementedError

    async def get_system_info(self, *sections: SystemStat) -> dict:
        """Return system information"""
        cluster_info = await self.__get_cluster_state()
        cluster_info["name"] = cluster_info["clusterName"]
        current_controller_id = cluster_info["currentNodeId"]
        controllers = (await self.session.sz_get("controller"))["list"]
        sysinfo = next((controller for controller in controllers if controller["id"] == current_controller_id), controllers[0])
        sysinfo["serial"] = sysinfo["serialNumber"]
        return { "sysinfo": sysinfo, "identity": cluster_info }            

    async def get_mesh_info(self) -> dict:
        """Return dummy mesh information"""
        # Mesh is per-zone in SmartZone. But we need to implement this because
        # Home Assistant uses the mesh name as the display name for any Ruskus
        # network. We will use the Cluster Name instead.
        cluster_state = await self.session.sz_get("cluster/state")
        cluster_state["name"] = cluster_state["clusterName"]
        return cluster_state

    async def __get_cluster_state(self) -> dict:
        """Return Cluster State"""
        return await self.session.sz_get("cluster/state")

    async def get_zerotouch_mesh_ap_serials(self) -> dict:
        """Return a list of Pre-approved AP serial numbers"""
        raise NotImplementedError

    async def get_acls(self) -> list[L2Policy | dict]:
        """Return a list of ACLs"""
        raise NotImplementedError

    async def get_blocked_client_macs(self) -> list[L2Rule | dict]:
        """Return a list of blocked client MACs"""
        raise NotImplementedError

    async def get_active_clients(self, interval_stats: bool = False) -> List:
        """Return a list of active clients"""
        clients = await self.session.sz_query("client")
        compat_clients = [
            {**client, "mac": client["clientMac"], "ip": client["ipAddress"], "ap": client["apMac"]} 
            for client in clients
        ]
        return compat_clients

    async def get_inactive_clients(self) -> List:
        """Return a list of inactive clients"""
        return await self.session.sz_query("historicalclient")

    async def get_ap_stats(self) -> List:
        """Return a list of AP statistics"""
        aps = await self.session.sz_query("ap")
        compat_aps = [
            {**ap, "mac": ap["apMac"], "devname": ap["deviceName"], "firmware-version": ap["firmwareVersion"], "serial-number": ap["serial"]} 
            for ap in aps
        ]
        return compat_aps


    async def get_ap_group_stats(self) -> List:
        """Return a list of AP group statistics"""
        raise NotImplementedError

    async def get_vap_stats(self) -> List:
        """Return a list of Virtual AP (per-radio WLAN) statistics"""
        return await self.session.sz_query("wlan")

    async def get_wlan_group_stats(self) -> List:
        """Return a list of WLAN group statistics"""
        raise NotImplementedError

    async def get_dpsk_stats(self) -> List:
        """Return a list of AP group statistics"""
        raise NotImplementedError

    async def get_active_rogues(self) -> list[dict]:
        """Return a list of currently active rogue devices"""
        raise NotImplementedError

    async def get_known_rogues(self, limit: int = 300) -> list[dict]:
        """Return a list of known/recognized rogues devices"""
        raise NotImplementedError

    async def get_blocked_rogues(self, limit: int = 300) -> list[dict]:
        """Return a list of user blocked rogues devices"""
        raise NotImplementedError

    async def get_all_alarms(self, limit: int = 300) -> list[dict]:
        """Return a list of all alerts"""
        raise NotImplementedError

    async def get_all_events(self, limit: int = 300) -> list[dict]:
        """Return a list of all events"""
        raise NotImplementedError

    async def get_wlan_events(self, *wlan_ids, limit: int = 300) -> list[dict]:
        """Return a list of WLAN events"""
        raise NotImplementedError

    async def get_ap_events(self, *ap_macs, limit: int = 300) -> list[dict]:
        """Return a list of AP events"""
        raise NotImplementedError

    async def get_client_events(self, limit: int = 300) -> list[dict]:
        """Return a list of client events"""
        raise NotImplementedError

    async def get_wired_client_events(self, limit: int = 300) -> list[dict]:
        """Return a list of wired client events"""
        raise NotImplementedError

    async def get_syslog(self) -> str:
        """Return a list of syslog entries"""
        raise NotImplementedError

    async def get_backup(self) -> bytes:
        """Return a backup"""
        raise NotImplementedError

    async def do_block_client(self, mac: str) -> None:
        """Block a client"""
        raise NotImplementedError

    async def do_unblock_client(self, mac: str) -> None:
        """Unblock a client"""
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
        sae_passphrase: str = None
    ) -> None:
        raise NotImplementedError

    async def do_hide_ap_leds(self, mac: str, leds_off: bool = True) -> None:
        """Hide AP LEDs"""
        raise NotImplementedError

    async def do_show_ap_leds(self, mac: str) -> None:
        """Show AP LEDs"""
        raise NotImplementedError

    async def do_restart_ap(self, mac: str) -> None:
        """Restart AP"""
        raise NotImplementedError

    