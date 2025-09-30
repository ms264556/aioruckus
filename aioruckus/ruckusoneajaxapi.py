"""Add enough AJAX methods to support Home Assistant"""

from __future__ import annotations
import asyncio
from copy import deepcopy
from typing import Any, cast, override

from aioruckus.abcsession import ConfigItem
from aioruckus.ajaxtyping import Wlan

from .ruckusonesession import RuckusOneSession
from .ruckusajaxapi import RuckusAjaxApi
from .ajaxtyping import *
from .ruckusonetyping import AccessControlPolicyDict, AccessControlProfileDict
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
        self.__session = await RuckusOneSession(
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
        acl = await self._query_l2_policy(R1_CLIENT_BLOCK_NAME)
        return [] if not acl else [
            L2Rule({"mac": mac}) for mac in acl["macAddresses"]
        ]

    async def do_unblock_client(self, mac: str) -> None:
        """Unblock a client"""
        blocklist_policy = await self._query_l2_policy(R1_CLIENT_BLOCK_NAME)
        if not blocklist_policy:
            return
        mac = normalize_mac_upper(mac)
        update_tasks = [self._do_apply_block_policy_to_networks(blocklist_policy)]
        if mac in blocklist_policy["macAddresses"]:
            blocklist_policy["macAddresses"].remove(mac)
            if not blocklist_policy["macAddresses"]:
                await self._do_remove_block_policy_from_networks(blocklist_policy)
                return
            update_tasks.append(self._do_update_l2_policy(blocklist_policy))
        await asyncio.gather(*update_tasks)

    async def do_block_client(self, mac: str) -> None:
        """Block a client"""
        mac = normalize_mac_upper(mac)
        blocklist_policy = await self._query_l2_policy(R1_CLIENT_BLOCK_NAME)
        if not blocklist_policy:
            await self.__session.post(
                "l2AclPolicies",
                {"name": R1_CLIENT_BLOCK_NAME, "macAddresses": [mac]},
            )
            blocklist_policy = await self._query_l2_policy(R1_CLIENT_BLOCK_NAME)
            assert blocklist_policy
        elif mac not in blocklist_policy["macAddresses"]:
            blocklist_policy["macAddresses"].append(mac)
            await self._do_update_l2_policy(blocklist_policy)
        await self._do_apply_block_policy_to_networks(blocklist_policy)

    async def _do_remove_block_policy_from_networks(self, blocklist: AccessControlPolicyDict) -> None:
        blocklist_id = blocklist["id"]
        update_tasks = []
        for acl_profile in await self._query_acl_profiles():
            if "l2AclPolicy" in acl_profile and acl_profile["l2AclPolicy"]["id"] == blocklist_id:
                update_tasks.append(
                    self.__session.delete(f"accessControlProfiles/{acl_profile['id']}/l2AclPolicies/{blocklist_id}")
                )
        if "wifiNetworkIds" in blocklist:
            for id in blocklist["wifiNetworkIds"]:
                update_tasks.append(
                    self.__session.delete(f"wifiNetworks/{id}/l2AclPolicies/{blocklist_id}")
                )
        if update_tasks:
            await asyncio.gather(*update_tasks)
        await self.__session.delete(f"l2AclPolicies/{blocklist_id}")

    async def _do_apply_block_policy_to_networks(self, blocklist: AccessControlPolicyDict) -> None:
        blocklist_id = blocklist["id"]
        all_l2_policies, all_wlans = await asyncio.gather(
            self._query_l2_policies(),
            self.get_wlans()
        )
        update_tasks = []
        covered_wlan_ids = set()
        acl_profiles = await self._query_acl_profiles(l2_policies=all_l2_policies)
        for acl_profile in acl_profiles:
            if "wifiNetworkIds" in acl_profile:
                if "l2AclPolicy" not in acl_profile:
                    update_tasks.append(
                        self.__session.put(f"accessControlProfiles/{acl_profile['id']}/l2AclPolicies/{blocklist_id}")
                    )
                covered_wlan_ids.update(acl_profile["wifiNetworkIds"])
        for l2_policy in all_l2_policies:
            if "wifiNetworkIds" in l2_policy:
                covered_wlan_ids.update(l2_policy["wifiNetworkIds"])
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

    async def _query_acl_profile(self, name: str) -> AccessControlProfileDict | None:
        profiles = await self._query_acl_profiles({"name": [name]})
        return profiles[0] if profiles else None

    async def _query_acl_profiles(self, filters: dict | None = None, l2_policies: list[AccessControlPolicyDict] | None = None) -> list[AccessControlProfileDict]:
        query_params = { "filters": filters } if filters else {}
        profiles = await self.__session.query("accessControlProfiles/query", query_params)
        if profiles:
            await self._enrich_acl_profiles_with_l2_policies(profiles, l2_policies)
        return profiles

    async def _enrich_acl_profiles_with_l2_policies(self, profiles: list[AccessControlProfileDict], policies: list[AccessControlPolicyDict] | None) -> None:
        if policies is None:
            policies_to_fetch = {
                id for p in profiles if (id := p.get("l2AclPolicyId"))
            }
            if policies_to_fetch:
                policies = await asyncio.gather(
                    *(self._get_l2_policy(id) for id in policies_to_fetch)
                )
            else:
                policies = []
        policy_map = {policy["id"]: policy for policy in policies}
        for profile in profiles:
            if id := profile.pop("l2AclPolicyId", None):
                assert id in policy_map
                profile["l2AclPolicy"] = policy_map[id]
            profile.pop("l2AclPolicyName", None)

    async def _query_l2_policy(self, name: str) -> AccessControlPolicyDict | None:
        policies = await self._query_l2_policies({"name": [name]})
        return policies[0] if policies else None

    async def _query_l2_policies(self, filters: dict | None = None) -> list[AccessControlPolicyDict]:
        query_params = { "filters": filters } if filters else {}
        policies = await self.__session.query("l2AclPolicies/query", query_params)
        if policies:
            # queried L2 policies don't include MAC addresses, so get these separately then merge
            policies_with_macs = await asyncio.gather(*[self._get_l2_policy(policy["id"]) for policy in policies])
            policies = [
                policy | policy_with_mac
                for policy, policy_with_mac in zip(policies, policies_with_macs)
            ]
        return policies

    async def _get_l2_policy(self, id: str) -> AccessControlPolicyDict:
        return await self.__session.get(f"l2AclPolicies/{id}")

    async def _do_update_l2_policy(self, policy: AccessControlPolicyDict) -> None:
        json = cast(dict, deepcopy(policy))
        id = json["id"]
        del json["id"]
        await self.__session.put(f"l2AclPolicies/{id}", json)

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