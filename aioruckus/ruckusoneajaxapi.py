"""Add enough AJAX methods to support Home Assistant"""

from __future__ import annotations
import asyncio
from copy import deepcopy
from typing import Any, cast

from aioruckus.abcsession import ConfigItem
from aioruckus.ajaxtyping import Wlan

from .ruckusonesession import RuckusOneSession
from .ruckusajaxapi import RuckusAjaxApi
from .ajaxtyping import *
from .ruckusonetyping import R1AccessControlPolicy, R1AccessControlProfile, R1Ap
from .utility import *

from .const import (
    R1_CLIENT_BLOCK_NAME,
    SystemStat,
)
from .ajaxsession import AjaxSession


class RuckusOneAjaxApi(RuckusAjaxApi):
    """Ruckus One compatibility shim"""
    __session: RuckusOneSession

    def __init__(self, session: AjaxSession):
        super().__init__(session)

    async def login(self) -> RuckusOneAjaxApi:
        self.__session = await RuckusOneSession(self.session.host, self.session.username, self.session.password).login()
        return self

    async def close(self) -> None:
        await self.__session.close()

    async def get_aps(self) -> list[Ap]:
        """Return a list of APs"""
        aps = await self.__session.get("venues/aps")
        return cast(list[Ap], [
            {
                **ap,
                "id": ap["mac"],
                "devname": ap["name"],
                "version": ap["firmware"],
                "serial": ap["serialNumber"],
            }
            for ap in aps
        ])
    
    async def get_wlans(self) -> list[Wlan]:
        return await self.__session.query("wifiNetworks/query")

    async def get_system_info(self, *sections: SystemStat) -> dict:
        """Return system information"""
        tenant = await self.__session.get("tenants/self")
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
        return await self.__session.get("tenants/self")
    
    #
    # Client blocking is not supported on Ruckus One.
    # We'll create an L2 ACL to manage blocked clients
    # and attach this ACL to networks/profiles which
    # don't already have an L2 ACL.
    #

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
        mac = normalize_mac_upper(mac)
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
        mac = normalize_mac_upper(mac)
        blocklist_acl = await self._query_l2_acl(R1_CLIENT_BLOCK_NAME)
        if not blocklist_acl:
            await self.__session.post(
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
                    self.__session.delete(f"accessControlProfiles/{acl_set['id']}/l2AclPolicies/{blocklist_id}")
                )
        if "wifiNetworkIds" in blocklist:
            for id in blocklist["wifiNetworkIds"]:
                update_tasks.append(
                    self.__session.delete(f"wifiNetworks/{id}/l2AclPolicies/{blocklist_id}")
                )
        if update_tasks:
            await asyncio.gather(*update_tasks)
        await self.__session.delete(f"l2AclPolicies/{blocklist_id}")

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
                        self.__session.put(f"accessControlProfiles/{acl_set['id']}/l2AclPolicies/{blocklist_id}")
                    )
                covered_wlan_ids.update(acl_set["wifiNetworkIds"])
        for acl_l2 in all_l2_acls:
            if "wifiNetworkIds" in acl_l2:
                covered_wlan_ids.update(acl_l2["wifiNetworkIds"])
        uncovered_wlan_ids = {wlan["id"] for wlan in all_wlans} - covered_wlan_ids
        if uncovered_wlan_ids:
            for wlan_id in uncovered_wlan_ids:
                task = self.__session.put(f"wifiNetworks/{wlan_id}/l2AclPolicies/{blocklist_id}")
                update_tasks.append(task)
        if update_tasks:
            await asyncio.gather(*update_tasks)

    async def get_active_clients(self, interval_stats: bool = False) -> list[Client]:
        """Return a list of active clients"""
        clients = await self.__session.get("clients")
        return cast(list[Client], [
            {
                **client,
                "ap": client.get("apMac"),
                "hostname": client.get("hostname") or client.get("mac"),
            }
            for client in clients
        ])

    async def get_ap_stats(self) -> list[ApStats]:
        """Return a list of AP statistics"""
        aps = await self.__session.get("venues/aps")
        return cast(list[ApStats], [
            {
                **ap,
                "devname": ap["name"],
                "firmware-version": ap["firmware"],
                "serial-number": ap["serialNumber"],
            }
            for ap in aps
        ])

    async def do_hide_ap_leds(self, mac: str, leds_off: bool = True) -> None:
        """Hide AP LEDs"""
        mac = normalize_mac_upper(mac)
        aps = await self.__session.get("venues/aps")
        ap = next((a for a in aps if a["mac"] == mac), None)
        if ap:
            await self.__session.put(
                f"venues/{ap["venueId"]}/aps/{ap["serialNumber"]}/ledSettings",
                {"ledEnabled": not leds_off, "useVenueSettings": False},
                fire_and_forget=True
            )

    async def do_restart_ap(self, mac: str) -> None:
        """Restart AP"""
        mac = normalize_mac_upper(mac)
        aps = await self.__session.get("venues/aps")
        ap = next((a for a in aps if a["mac"] == mac), None)
        if ap:
            await self.__session.patch(
                f"venues/{ap["venueId"]}/aps/{ap["serialNumber"]}/systemCommands",
                {"type": "REBOOT"},
                fire_and_forget=True
            )

    async def _query_acl_set(self, name: str) -> R1AccessControlProfile | None:
        sets = await self._query_acl_sets({"name": [name]})
        return sets[0] if sets else None

    async def _query_acl_sets(self, filters: dict | None = None, l2_acls: list[R1AccessControlPolicy] | None = None) -> list[R1AccessControlProfile]:
        query_params = { "filters": filters } if filters else {}
        sets = await self.__session.query("accessControlProfiles/query", query_params)
        if sets:
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
        acls = await self.__session.query("l2AclPolicies/query", query_params)
        if acls:
            # queried L2 policies don't include MAC addresses, so get these separately then merge
            acls_with_macs = await asyncio.gather(*[self._get_l2_acl(acl["id"]) for acl in acls])
            acls = [
                acl | acl_with_mac
                for acl, acl_with_mac in zip(acls, acls_with_macs)
            ]
        return acls

    async def _get_l2_acl(self, id: str) -> R1AccessControlPolicy:
        return await self.__session.get(f"l2AclPolicies/{id}")

    async def _do_update_l2_acl(self, acl: R1AccessControlPolicy) -> None:
        json = cast(dict, deepcopy(acl))
        id = json["id"]
        del json["id"]
        await self.__session.put(f"l2AclPolicies/{id}", json)

    #
    # Override the Unleashed/ZoneDirector base AJAX methods
    # so everything else fails.
    #
    async def _cmdstat_noparse(self, data: str, timeout: int | None = None) -> str:
        raise NotImplementedError
    #
    async def _get_conf(self, item: ConfigItem, collection_elements: list[str] | None = None) -> Any:
        raise NotImplementedError