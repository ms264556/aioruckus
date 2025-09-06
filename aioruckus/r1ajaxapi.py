"""Adds enough AJAX methods to RuckusApi to support Home Assistant"""

from __future__ import annotations
import asyncio
from copy import deepcopy
from typing import cast

from .ruckusajaxapi import RuckusAjaxApi
from .ajaxtyping import *
from .r1typing import R1AccessControlPolicy, R1AccessControlProfile, R1Ap

from .const import (
    R1_CLIENT_BLOCK_NAME,
    SystemStat,
)
from .ajaxsession import AjaxSession


class R1AjaxApi(RuckusAjaxApi):
    """Ruckus One Configuration, Statistics and Commands API"""

    session: AjaxSession

    def __init__(self, session: AjaxSession):
        super().__init__(session)

    async def get_aps(self) -> list[Ap]:
        """Return a list of APs"""
        aps = await self._get_aps()
        compat_aps = [
            {
                **ap,
                "id": ap["mac"],
                "devname": ap["name"],
                "version": ap["firmware"],
                "serial": ap["serialNumber"],
            }
            for ap in aps
        ]
        return cast(list[Ap], compat_aps)

    async def _get_aps(self) -> list[R1Ap]:
        return await self.session.r1_get("venues/aps")

    async def get_ap_groups(self) -> list[ApGroup]:
        """Return a list of AP groups"""
        raise NotImplementedError

    async def get_wlans(self) -> list[Wlan]:
        """Return a list of WLANs"""
        wlans = await self.session.r1_post("wifiNetworks/query", {})
        return wlans["data"]

    async def get_wlan_groups(self) -> list[WlanGroup]:
        """Return a list of WLAN groups"""
        raise NotImplementedError

    async def get_urlfiltering_policies(self) -> list[UrlFilter]:
        """Return a list of URL Filtering Policies"""
        raise NotImplementedError

    async def get_urlfiltering_blockingcategories(
        self,
    ) -> list[UrlBlockCategory]:
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
        tenant = await self.session.r1_get("tenants/self")
        return {
            "tenant": tenant,
            "sysinfo": {"version": "R1", "serial": tenant["entitlementId"]},
            "identity": {"name": tenant["name"]},
        }

    async def get_mesh_info(self) -> Mesh:
        """Return dummy mesh information"""
        # We need to implement this because Home Assistant uses the mesh
        # name as the display name for any Ruckus network.
        # We will use the Tenant Name instead.
        return await self.session.r1_get("tenants/self")

    async def get_zerotouch_mesh_ap_serials(self) -> list[dict]:
        """Return a list of Pre-approved AP serial numbers"""
        raise NotImplementedError

    async def get_acls(self) -> list[L2Policy]:
        """Return a list of ACLs"""
        raise NotImplementedError

    async def get_blocked_client_macs(self) -> list[L2Rule]:
        """Return a list of blocked client MACs"""
        acl = await self._query_l2_acl(R1_CLIENT_BLOCK_NAME)
        return [] if not acl else [
            L2Rule({"mac": mac}) for mac in acl["macAddresses"]
        ]

    async def do_unblock_client(self, mac: str) -> None:
        """Unblock a client"""
        blocklist_acl = await self._query_l2_acl(R1_CLIENT_BLOCK_NAME)
        if not blocklist_acl:
            return
        mac = self.__normalize_mac(mac)
        update_tasks = [self._do_apply_block_acl_to_networks(blocklist_acl)]
        if mac in blocklist_acl["macAddresses"]:
            blocklist_acl["macAddresses"].remove(mac)
            if not blocklist_acl["macAddresses"]:
                await self._do_remove_block_acl_from_networks(blocklist_acl)
                return
            update_tasks.append(self._do_update_l2_acl(blocklist_acl))
        await asyncio.gather(*update_tasks)

    async def do_block_client(self, mac: str) -> None:
        """Block a client"""
        mac = self.__normalize_mac(mac)
        blocklist_acl = await self._query_l2_acl(R1_CLIENT_BLOCK_NAME)
        if not blocklist_acl:
            await self.session.r1_post(
                "l2AclPolicies",
                {"name": R1_CLIENT_BLOCK_NAME, "macAddresses": [mac]},
            )
            blocklist_acl = await self._query_l2_acl(R1_CLIENT_BLOCK_NAME)
            assert blocklist_acl
        elif mac not in blocklist_acl["macAddresses"]:
            blocklist_acl["macAddresses"].append(mac)
            await self._do_update_l2_acl(blocklist_acl)
        await self._do_apply_block_acl_to_networks(blocklist_acl)

    async def _do_remove_block_acl_from_networks(self, blocklist: R1AccessControlPolicy) -> None:
        blocklist_id = blocklist["id"]
        update_tasks = []
        for acl_set in await self._query_acl_sets():
            if "l2AclPolicy" in acl_set and acl_set["l2AclPolicy"]["id"] == blocklist_id:
                update_tasks.append(
                    self.session.r1_delete(f"accessControlProfiles/{acl_set['id']}/l2AclPolicies/{blocklist_id}")
                )
        if "wifiNetworkIds" in blocklist:
            for id in blocklist["wifiNetworkIds"]:
                update_tasks.append(
                    self.session.r1_delete(f"wifiNetworks/{id}/l2AclPolicies/{blocklist_id}")
                )
        if update_tasks:
            await asyncio.gather(*update_tasks)
        await self.session.r1_delete(f"l2AclPolicies/{blocklist_id}")

    async def _do_apply_block_acl_to_networks(self, blocklist: R1AccessControlPolicy) -> None:
        blocklist_id = blocklist["id"]
        all_l2_acls, all_wlans = await asyncio.gather(
            self._query_l2_acls(),
            self.get_wlans()
        )
        update_tasks = []
        covered_wlan_ids = set()
        acl_sets = await self._query_acl_sets(l2_acls=all_l2_acls)
        for acl_set in acl_sets:
            if "wifiNetworkIds" in acl_set:
                if "l2AclPolicy" not in acl_set:
                    update_tasks.append(
                        self.session.r1_put(f"accessControlProfiles/{acl_set['id']}/l2AclPolicies/{blocklist_id}")
                    )
                covered_wlan_ids.update(acl_set["wifiNetworkIds"])
        for acl_l2 in all_l2_acls:
            if "wifiNetworkIds" in acl_l2:
                covered_wlan_ids.update(acl_l2["wifiNetworkIds"])
        uncovered_wlan_ids = {wlan["id"] for wlan in all_wlans} - covered_wlan_ids
        if uncovered_wlan_ids:
            for wlan_id in uncovered_wlan_ids:
                task = self.session.r1_put(f"wifiNetworks/{wlan_id}/l2AclPolicies/{blocklist_id}")
                update_tasks.append(task)
        if update_tasks:
            await asyncio.gather(*update_tasks)

    async def get_active_clients(self, interval_stats: bool = False) -> list[Client]:
        """Return a list of active clients"""
        clients = await self.session.r1_get("clients")
        compat_clients = [
            {
                **client,
                "ap": client.get("apMac"),
                "hostname": client.get("hostname") or client.get("mac"),
            }
            for client in clients
        ]
        return cast(list[Client], compat_clients)

    async def get_inactive_clients(self) -> list[Client]:
        """Return a list of inactive clients"""
        raise NotImplementedError

    async def get_ap_stats(self) -> list[ApStats]:
        """Return a list of AP statistics"""
        aps = await self.session.r1_get("venues/aps")
        compat_aps = [
            {
                **ap,
                "devname": ap["name"],
                "firmware-version": ap["firmware"],
                "serial-number": ap["serialNumber"],
            }
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
        self, name: str, passphrase: str, sae_passphrase: str | None = None
    ) -> None:
        raise NotImplementedError

    async def do_hide_ap_leds(self, mac: str, leds_off: bool = True) -> None:
        """Hide AP LEDs"""
        mac = self.__normalize_mac(mac)
        aps = await self._get_aps()
        ap = next((a for a in aps if a["mac"] == mac), None)
        if ap:
            await self.session.r1_put(
                f"venues/{ap["venueId"]}/aps/{ap["serialNumber"]}/ledSettings",
                {"ledEnabled": not leds_off, "useVenueSettings": False},
                fire_and_forget=True
            )

    async def do_restart_ap(self, mac: str) -> None:
        """Restart AP"""
        mac = self.__normalize_mac(mac)
        aps = await self._get_aps()
        ap = next((a for a in aps if a["mac"] == mac), None)
        if ap:
            await self.session.r1_patch(
                f"venues/{ap["venueId"]}/aps/{ap["serialNumber"]}/systemCommands",
                {"type": "REBOOT"},
                fire_and_forget=True
            )

    @classmethod
    def __normalize_mac(cls, mac: str) -> str:
        """Normalize MAC address format and casing"""
        return cls._normalize_mac_nocase(mac).upper()

    async def _query_acl_set(self, name: str) -> R1AccessControlProfile | None:
        sets = await self._query_acl_sets({"name": [name]})
        return sets[0] if sets else None

    async def _query_acl_sets(self, filters: dict | None = None, l2_acls: list[R1AccessControlPolicy] | None = None) -> list[R1AccessControlProfile]:
        query_params = { "filters": filters } if filters else {}
        sets = (await self.session.r1_post("accessControlProfiles/query", query_params)).get("data")
        if not sets:
            return []
        await self._enrich_acl_sets_l2_acls(sets, l2_acls)
        return sets

    async def _enrich_acl_sets_l2_acls(self, sets: list[R1AccessControlProfile], acls: list[R1AccessControlPolicy] | None) -> None:
        if acls is None:
            acls_to_fetch = {
                id for s in sets if (id := s.get("l2AclPolicyId"))
            }
            if acls_to_fetch:
                acls = await asyncio.gather(
                    *(self._get_l2_acl(id) for id in acls_to_fetch)
                )
            else:
                acls = []
        acl_map = {acl["id"]: acl for acl in acls}
        for set in sets:
            if id := set.pop("l2AclPolicyId", None):
                assert id in acl_map
                set["l2AclPolicy"] = acl_map[id]
            set.pop("l2AclPolicyName", None)

    async def _query_l2_acl(self, name: str) -> R1AccessControlPolicy | None:
        acls = await self._query_l2_acls({"name": [name]})
        return acls[0] if acls else None

    async def _query_l2_acls(self, filters: dict | None = None) -> list[R1AccessControlPolicy]:
        query_params = { "filters": filters } if filters else {}
        acls = (await self.session.r1_post("l2AclPolicies/query", query_params))["data"]
        if not acls:
            return []
        # queried L2 policies don't include MAC addresses, so get these separately then merge
        acls_with_macs = await asyncio.gather(*[self._get_l2_acl(acl["id"]) for acl in acls])
        return [
            acl | acl_with_mac
            for acl, acl_with_mac in zip(acls, acls_with_macs)
        ]

    async def _get_l2_acl(self, id: str) -> R1AccessControlPolicy:
        return await self.session.r1_get(f"l2AclPolicies/{id}")

    async def _do_update_l2_acl(self, acl: R1AccessControlPolicy) -> None:
        json = cast(dict, deepcopy(acl))
        id = json["id"]
        del json["id"]
        await self.session.r1_put(f"l2AclPolicies/{id}", json)
