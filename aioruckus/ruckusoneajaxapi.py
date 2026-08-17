"""Add enough AJAX methods to support Home Assistant"""

from __future__ import annotations

import asyncio
import sys
import time
from copy import deepcopy
from typing import Any, cast

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from aioruckus.abcsession import ConfigItem
from aioruckus.ajaxtyping import Wlan

from .ajaxsession import AjaxSession
from .ajaxtyping import *
from .const import (
    ERROR_GUEST_PASS_BATCH_SIZE,
    ERROR_INVALID_WLAN,
    R1_CLIENT_BLOCK_NAME,
    StatsLevel,
    SystemStat,
)
from .ruckusajaxapi import RuckusAjaxApi
from .ruckusonesession import RuckusOneSession
from .ruckusonetyping import (
    AccessControlPolicyDict,
    AccessControlProfileDict,
    GuestUserDict,
)
from .utility import *

_R1_DURATION_UNITS = {
    "min": "Minute",
    "hour": "Hour",
    "day": "Day",
    "week": "Week",
    "month": "Month",
    "year": "Year",
    "never": "Never",
}


def _r1_duration_unit(unit: str) -> str:
    """Map a shared duration unit onto the Ruckus One expiration unit enum."""
    return _R1_DURATION_UNITS.get(unit.lower(), unit.capitalize())


class RuckusOneAjaxApi(RuckusAjaxApi):
    """Ruckus One compatibility shim"""
    __session: RuckusOneSession

    def __init__(self, session: AjaxSession):
        """Initialize the API with the given AjaxSession."""
        super().__init__(session)

    async def login(self) -> RuckusOneAjaxApi:
        """Create a Ruckus One HTTPS session and log in."""
        self.__session = await RuckusOneSession(
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
        aps = await self.__session.query("venues/aps/query")
        return cast(list[Ap], [
            {
                **ap,
                "id": ap["macAddress"],
                "mac": ap["macAddress"],
                "devname": ap["name"],
                "version": ap["firmwareVersion"],
                "serial": ap["serialNumber"],
            }
            for ap in aps
        ])
    
    async def get_wlans(self) -> list[Wlan]:
        """Return a list of WLANs (WiFi networks)."""
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
        """Detach the blocklist L2 policy from all networks and delete it."""
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
        """Attach the blocklist L2 policy to all networks without an L2 ACL."""
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

    async def get_active_clients(
        self,
        stats_level: StatsLevel | bool = StatsLevel.L1,
        interval_stats: bool | None = None,
    ) -> list[Client]:
        """Return a list of active clients

        Ruckus One does not support the Unleashed/ZoneDirector stats levels;
        ``stats_level`` / ``interval_stats`` are accepted for interface
        compatibility with :class:`RuckusAjaxApi` and ignored.
        """
        clients = await self.__session.get("clients")
        return cast(list[Client], [
            {
                **client,
                "ap": client.get("apMac"),
                "hostname": client.get("hostname") or client.get("mac"),
            }
            for client in clients
        ])

    async def get_ap_stats(
        self,
        stats_level: StatsLevel | bool = StatsLevel.L1,
        interval_stats: bool | None = None,
    ) -> list[ApStats]:
        """Return a list of AP statistics

        Ruckus One does not support the Unleashed/ZoneDirector stats levels;
        ``stats_level`` / ``interval_stats`` are accepted for interface
        compatibility with :class:`RuckusAjaxApi` and ignored.
        """
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
                f"venues/{ap['venueId']}/aps/{ap['serialNumber']}/ledSettings",
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
                f"venues/{ap['venueId']}/aps/{ap['serialNumber']}/systemCommands",
                {"type": "REBOOT"},
                fire_and_forget=True
            )

    #
    # Guest passes are "guest users" on a Wi-Fi network in Ruckus One:
    # listed via the guestUsers query, created one at a time via
    # wifiNetworks/{id}/guestUsers (there is no batch create), optionally
    # re-keyed via a PATCH password update, and deleted per guest user id.
    #

    def _r1_guest_from_json(self, payload: GuestUserDict) -> Guest:
        """Normalize a Ruckus One guest user payload to the ``Guest`` shape."""
        expiration = payload.get("expiration") or {}
        max_devices = payload.get("maxDevices", 0)
        return {
            "key": payload.get("password", ""),
            "id": payload.get("id", ""),
            "name": payload.get("name", ""),
            "ssid": payload.get("ssid", ""),
            "email": payload.get("email", ""),
            "phone-number": payload.get("mobilePhoneNumber", ""),
            "create-time": str(payload.get("createdDate", "")),
            "expire-time": str(payload.get("expirationDate", "")),
            "duration": str(expiration.get("duration", "")),
            "duration-unit": (expiration.get("unit") or "").lower(),
            "shared-guestpass": "true" if max_devices == -1 else "false",
            "share-number": str(max_devices),
            "remarks": payload.get("notes", ""),
            "networkId": payload.get("networkId", ""),
            "guest-user-type": payload.get("guestUserType", ""),
        }

    async def _r1_resolve_wifi_network(self, ssid: str) -> dict:
        """Resolve a Wi-Fi network id and name from an SSID."""
        wlan = next(
            (w for w in await self.get_wlans()
             if w.get("ssid") == ssid or w.get("name") == ssid),
            None,
        )
        if not wlan:
            raise ValueError(ERROR_INVALID_WLAN)
        return wlan

    def _r1_guest_payload(self, name: str, duration: int, duration_unit: str,
                          shared: bool, share_number: int, email: str,
                          phone_number: str, remarks: str) -> dict:
        """Build a Ruckus One create-guest-user request payload."""
        delivery_methods = []
        if email:
            delivery_methods.append("MAIL")
        if phone_number:
            delivery_methods.append("SMS")
        if not delivery_methods:
            delivery_methods.append("STUB")
        return {
            "name": name,
            "deliveryMethods": delivery_methods,
            "expiration": {
                "activationType": "Creation",
                "duration": duration,
                "unit": _r1_duration_unit(duration_unit),
            },
            "maxDevices": -1 if shared else max(1, share_number),
            "email": email,
            "mobilePhoneNumber": phone_number,
            "notes": remarks,
        }

    def _r1_guest_from_json(self, payload: GuestUserDict) -> Guest:
        """Normalize a Ruckus One guest user payload to the ``Guest`` shape.

        Ruckus One never exposes the guest user password (the pass key shown
        on vouchers) outside of the create response, so the guest user
        ``id`` is used as the pass ``key`` to keep list/create/remove
        coherent; the password is kept as an extra field when known.
        """
        expiration = payload.get("expiration") or {}
        max_devices = payload.get("maxDevices", 0)
        guest: dict[str, Any] = {
            "key": payload.get("id", ""),
            "id": payload.get("id", ""),
            "name": payload.get("name", ""),
            "ssid": payload.get("ssid", ""),
            "email": payload.get("email", ""),
            "phone-number": payload.get("mobilePhoneNumber", ""),
            "create-time": str(payload.get("createdDate", "")),
            "expire-time": str(payload.get("expirationDate", "")),
            "duration": str(expiration.get("duration", "")),
            "duration-unit": (expiration.get("unit") or "").lower(),
            "shared-guestpass": "true" if max_devices == -1 else "false",
            "share-number": str(max_devices),
            "remarks": payload.get("notes", ""),
            "networkId": payload.get("networkId", ""),
            "guest-user-type": payload.get("guestUserType", ""),
        }
        if payload.get("password"):
            guest["password"] = payload["password"]
        return cast(Guest, guest)

    @override
    async def get_guest_passes(self) -> list[Guest]:
        """Return a list of guest passes"""
        guests = await self.__session.query("guestUsers/query")
        return [
            self._r1_guest_from_json(cast(GuestUserDict, guest))
            for guest in guests
        ]

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

        Ruckus One has no batch create, so each pass is created as an
        individual guest user with an auto-generated key. ``reauth_*`` /
        ``country_code`` are accepted for API compatibility but ignored:
        Ruckus One has no equivalent fields.
        """
        if not 2 <= batch_size <= 100:
            raise ValueError(ERROR_GUEST_PASS_BATCH_SIZE)
        wlan = await self._r1_resolve_wifi_network(ssid)
        before = {guest["id"] for guest in await self.get_guest_passes()}
        batch_name = name or f"batch-{int(time.time())}"
        responses = await asyncio.gather(*[
            self.__session.post(
                f"wifiNetworks/{wlan['id']}/guestUsers",
                self._r1_guest_payload(
                    f"{batch_name}-{i}",
                    duration,
                    duration_unit,
                    shared,
                    share_number,
                    email,
                    phone_number,
                    remarks,
                ),
            )
            for i in range(1, batch_size + 1)
        ])
        # Ruckus One creates guest users asynchronously, so the 201 response
        # body (not a re-list) carries the created passes
        created = [
            self._r1_guest_from_json(cast(GuestUserDict, resp["response"]))
            for resp in responses
            if resp and resp.get("response")
        ]
        if len(created) < batch_size:
            # some creates did not echo the guest; pick them up from the list
            listed = {g["id"] for g in created}
            created += [
                guest for guest in await self.get_guest_passes()
                if guest.get("id") not in before and guest.get("id") not in listed
            ]
        return created

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

        Pass a custom ``x_key`` to re-key the pass after creation via a
        PATCH password update (Ruckus One always auto-generates the initial
        key). ``reauth_*`` / ``country_code`` are accepted for API
        compatibility but ignored: Ruckus One has no equivalent fields.
        """
        wlan = await self._r1_resolve_wifi_network(ssid)
        pass_value = validate_guest_key(x_key) if x_key else ""
        guest_name = name or f"guest-{int(time.time())}"
        resp = await self.__session.post(
            f"wifiNetworks/{wlan['id']}/guestUsers",
            self._r1_guest_payload(
                guest_name,
                duration,
                duration_unit,
                shared,
                share_number,
                email,
                phone_number,
                remarks,
            ),
        )
        # Ruckus One creates guest users asynchronously, so the 201 response
        # body (not a re-list) carries the created pass
        created = (resp or {}).get("response")
        guest = (
            self._r1_guest_from_json(cast(GuestUserDict, created))
            if created
            else {
                "id": "",
                "key": "",
                "name": guest_name,
                "ssid": ssid,
                "duration": str(duration),
                "duration-unit": duration_unit.lower(),
                "remarks": remarks,
                "networkId": wlan["id"],
            }
        )
        if pass_value and guest["id"]:
            await self.__session.patch(
                f"wifiNetworks/{wlan['id']}/guestUsers/{guest['id']}",
                {"password": pass_value},
            )
            guest = {**guest, "password": pass_value}
        return guest

    @override
    async def do_remove_guest_passes(self, *keys: str) -> None:
        """Remove guest passes by their keys.

        Each key is resolved to its guest user id (and network id) via the
        guest user list before per-user DELETE requests are issued.
        """
        if not keys:
            return
        key_set = set(keys)
        guests = await self.get_guest_passes()
        missing = [key for key in keys if key not in {g.get("key") for g in guests}]
        if missing:
            raise ValueError(f"Guest pass key(s) not found: {', '.join(missing)}")
        targets = [
            g for g in guests
            if g.get("key") in key_set and g.get("id") and g.get("networkId")
        ]
        if targets:
            await asyncio.gather(*[
                self.__session.delete(
                    f"wifiNetworks/{g['networkId']}/guestUsers/{g['id']}"
                )
                for g in targets
            ])

    async def _query_acl_profile(self, name: str) -> AccessControlProfileDict | None:
        """Return the access control profile with the given name, or None."""
        profiles = await self._query_acl_profiles({"name": [name]})
        return profiles[0] if profiles else None

    async def _query_acl_profiles(self, filters: dict | None = None, l2_policies: list[AccessControlPolicyDict] | None = None) -> list[AccessControlProfileDict]:
        """Query access control profiles, enriching them with their L2 policies."""
        query_params = { "filters": filters } if filters else {}
        profiles = await self.__session.query("accessControlProfiles/query", query_params)
        if profiles:
            await self._enrich_acl_profiles_with_l2_policies(profiles, l2_policies)
        return profiles

    async def _enrich_acl_profiles_with_l2_policies(self, profiles: list[AccessControlProfileDict], policies: list[AccessControlPolicyDict] | None) -> None:
        """Replace l2AclPolicyId/l2AclPolicyName keys on profiles with their L2 policy objects."""
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
        """Return the L2 policy with the given name, or None."""
        policies = await self._query_l2_policies({"name": [name]})
        return policies[0] if policies else None

    async def _query_l2_policies(self, filters: dict | None = None) -> list[AccessControlPolicyDict]:
        """Query L2 policies, merging in MAC addresses fetched per policy."""
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
        """Return the L2 policy with the given id."""
        return await self.__session.get(f"l2AclPolicies/{id}")

    async def _do_update_l2_policy(self, policy: AccessControlPolicyDict) -> None:
        """Persist updates to the given L2 policy."""
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
        """Unsupported on Ruckus One; always raises NotImplementedError."""
        raise NotImplementedError
    @override
    async def _conf_noparse(self, data: str, timeout: int | None = None) -> str:
        """Unsupported on Ruckus One; always raises NotImplementedError."""
        raise NotImplementedError
    @override
    async def _get_conf_str(self, item: ConfigItem, timeout: int | None = None) -> str:
        """Unsupported on Ruckus One; always raises NotImplementedError."""
        raise NotImplementedError
    @override
    async def _get_conf(self, item: ConfigItem, target_type: type | None = None) -> Any:
        """Unsupported on Ruckus One; always raises NotImplementedError."""
        raise NotImplementedError