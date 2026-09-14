"""Ruckus ZoneDirector or Unleashed Configuration API"""
from __future__ import annotations

import asyncio
from abc import ABC
from copy import deepcopy
from typing import Any

from .abcsession import AbcSession, ConfigItem
from .ajaxtyping import (
    Ap,
    ApGroup,
    ArcApplication,
    ArcPolicy,
    ArcPort,
    DevicePolicy,
    Dpsk,
    Ip4Policy,
    Ip6Policy,
    L2Policy,
    L2Rule,
    Mesh,
    PrecedencePolicy,
    Role,
    SystemInfo,
    UrlBlockCategory,
    UrlFilter,
    Wlan,
    WlanGroup,
)
from .const import URL_FILTERING_CATEGORIES, SystemStat
from .unleashedtojson import parse_ajax_response


class RuckusConfigurationApi(ABC):
    """Ruckus ZoneDirector/Unleashed Configuration API"""
    def __init__(self, session: AbcSession):
        """Initialize the API with the given session."""
        self.session = session

    async def get_aps(self, timeout: int | None = None) -> list[Ap]:
        """Return a list of APs

        Args:
            timeout: per-request timeout in seconds; defaults to the session's.
        """
        return await self._get_conf(
            ConfigItem.AP_LIST, target_type=list[Ap], timeout=timeout
        )

    async def get_ap_groups(self, timeout: int | None = None) -> list[ApGroup]:
        """Return a list of AP groups

        Args:
            timeout: per-request timeout in seconds; defaults to the session's.
                Applies to each of the four requests this makes (APs, WLANs,
                WLAN groups and the group list) rather than to the whole
                operation.
        """
        ap_map = {ap['id']: ap for ap in await self.get_aps(timeout=timeout)}
        wlan_map = {wlan['id']: wlan for wlan in await self.get_wlans(timeout=timeout)}
        wlang_map = {wlang['id']: wlang for wlang in await self.get_wlan_groups(timeout=timeout)}
        ap_groups = await self._get_conf(
            ConfigItem.APGROUP_LIST, target_type=list[ApGroup], timeout=timeout
        )
        for ap_group in ap_groups:
            # replace ap links with ap objects
            if (
                "members" not in ap_group or ap_group["members"] is None or
                "ap" not in ap_group["members"] or ap_group["members"]["ap"] is None
            ):
                ap_group["ap"] = []
            else:
                ap_group["ap"] = [
                    deepcopy(ap_map[ap["id"]])
                    for ap in ap_group["members"]["ap"]
                ]
            ap_group.pop("members", None)
            # replace Unleashed wlangroup links with wlangroup objects
            if "wlangroup" in ap_group:
                if (
                    ap_group["wlangroup"] is None or "wlansvc" not in ap_group["wlangroup"] or
                    ap_group["wlangroup"]["wlansvc"] is None
                ):
                    ap_group["wlansvc"] = []
                else:
                    ap_group["wlansvc"] = [
                        deepcopy(wlan_map[wlan["id"]])
                        for wlan in ap_group["wlangroup"]["wlansvc"] if wlan["id"] in wlan_map
                    ]
                del ap_group["wlangroup"]
            # replace ZoneDirector wlangroup links with wlangroup objects
            if (
                "ap-property" in ap_group and ap_group["ap-property"] is not None and
                "radio" in ap_group["ap-property"] and ap_group["ap-property"]["radio"] is not None
            ):
                for radio in ap_group["ap-property"]["radio"]:
                    if "wlangroup-id" in radio:
                        if radio["wlangroup-id"] in wlang_map:
                            # wlangroup-id will be '*' if we're inheriting from System Default
                            radio["wlangroup"] = deepcopy(wlang_map[radio["wlangroup-id"]])
                        del radio["wlangroup-id"]
        return ap_groups

    async def get_wlans(self, timeout: int | None = None) -> list[Wlan]:
        """Return a list of WLANs

        Args:
            timeout: per-request timeout in seconds; defaults to the session's.
                Applies to each of the eight requests this makes (the WLAN list
                plus the policy lists it resolves) rather than to the whole
                operation.
        """
        wlans = await self._get_conf(
            ConfigItem.WLANSVC_LIST, target_type=list[Wlan], timeout=timeout
        )
        if wlans:
            acl_list, urlfilter_list, precedence_list, devicepolicy_list, arcpolicy_list, policy_list, policy6_list = await asyncio.gather(
                self.get_acls(timeout=timeout),
                self.get_urlfiltering_policies(timeout=timeout),
                self.get_precedence_policies(timeout=timeout),
                self.get_device_policies(timeout=timeout),
                self.get_arc_policies(timeout=timeout),
                self.get_ip4_policies(timeout=timeout),
                self.get_ip6_policies(timeout=timeout)
            )
            acl_map = {policy['id']: policy for policy in acl_list}
            urlfilter_map = {policy['id']: policy for policy in urlfilter_list}
            precedence_map = {policy['id']: policy for policy in precedence_list}
            devicepolicy_map = {policy['id']: policy for policy in devicepolicy_list}
            arcpolicy_map = {policy['id']: policy for policy in arcpolicy_list}
            policy_map = {policy['id']: policy for policy in policy_list}
            policy6_map = {policy['id']: policy for policy in policy6_list}
            for wlan in wlans:
                urlfiltering_policy = wlan.get("urlfiltering-policy")
                if (
                    urlfiltering_policy
                    and self._parse_conf_bool(urlfiltering_policy.get("urlfiltering-enabled")) is True
                    and urlfiltering_policy.get("urlfiltering-id") in urlfilter_map
                ):
                    wlan["urlfiltering-policy"] = deepcopy(urlfilter_map[urlfiltering_policy["urlfiltering-id"]])
                else:
                    wlan.pop("urlfiltering-policy", None)
                if "precedence-id" in wlan:
                    if wlan["precedence-id"] and wlan["precedence-id"] in precedence_map:
                        wlan["precedence"] = deepcopy(precedence_map[wlan["precedence-id"]])
                    del wlan["precedence-id"]
                if "devicepolicy-id" in wlan:
                    if wlan["devicepolicy-id"] and wlan["devicepolicy-id"] in devicepolicy_map:
                        wlan["devicepolicy"] = deepcopy(devicepolicy_map[wlan["devicepolicy-id"]])
                    del wlan["devicepolicy-id"]
                if "arc-pcy-id" in wlan:
                    if wlan["arc-pcy-id"] and wlan["arc-pcy-id"] in arcpolicy_map:
                        wlan["arc-pcy"] = deepcopy(arcpolicy_map[wlan["arc-pcy-id"]])
                    del wlan["arc-pcy-id"]
                if "acl-id" in wlan:
                    if wlan["acl-id"] and wlan["acl-id"] in acl_map:
                        wlan["acl"] = deepcopy(acl_map[wlan["acl-id"]])
                    del wlan["acl-id"]
                if "policy-id" in wlan:
                    if wlan["policy-id"] and wlan["policy-id"] in policy_map:
                        wlan["policy"] = deepcopy(policy_map[wlan["policy-id"]])
                    del wlan["policy-id"]
                if "policy6-id" in wlan:
                    if wlan["policy6-id"] and wlan["policy6-id"] in policy6_map:
                        wlan["policy6"] = deepcopy(policy6_map[wlan["policy6-id"]])
                    del wlan["policy6-id"]
                avp_policy = wlan.get("avp-policy")
                if (
                    avp_policy
                    and self._parse_conf_bool(avp_policy.get("avp-enabled")) is True
                    and avp_policy.get("avpdeny-id") in arcpolicy_map
                ):
                    wlan["avp-policy"] = deepcopy(arcpolicy_map[avp_policy["avpdeny-id"]])
                else:
                    wlan.pop("avp-policy", None)
        return wlans

    async def get_wlan_groups(self, timeout: int | None = None) -> list[WlanGroup]:
        """Return a list of WLAN groups

        Args:
            timeout: per-request timeout in seconds; defaults to the session's.
                Applies to each of the requests this makes (the WLAN list and
                the group list) rather than to the whole operation.
        """
        wlan_map = {wlan['id']: wlan for wlan in await self.get_wlans(timeout=timeout)}
        wlan_groups = await self._get_conf(
            ConfigItem.WLANGROUP_LIST, target_type=list[WlanGroup], timeout=timeout
        )
        for wlan_group in wlan_groups:
            if "wlansvc" in wlan_group:
                wlan_group["wlansvc"] = [
                    deepcopy(wlan_map[wlansvc["id"]])
                    for wlansvc in wlan_group["wlansvc"] if wlansvc["id"] in wlan_map
                ]
        return wlan_groups

    async def get_urlfiltering_policies(self, timeout: int | None = None) -> list[UrlFilter]:
        """Return a list of URL Filtering Policies

        Args:
            timeout: per-request timeout in seconds; defaults to the session's.
        """
        try:
            policies = await self._get_conf(
                ConfigItem.URLFILTERINGPOLICY_LIST, target_type=list[UrlFilter], timeout=timeout
            )
        except KeyError:
            return []
        block_map = {category['id']: category for category in await self.get_urlfiltering_blockingcategories(timeout=timeout)}
        for policy in policies:
            if "blockcategories" in policy and policy["blockcategories"]:
                split_categories = policy["blockcategories"].split(",")
                policy["blockcategories"] = deepcopy(
                    [block_map[category] for category in split_categories if category in block_map] +
                    [{"id": category} for category in split_categories if category not in block_map]
                )
            else:
                policy.pop("blockcategories", None)
            policy.pop("blockcategories-num", None)
            if "blacklist" in policy and policy["blacklist"]:
                policy["blacklist"] = [item["domain-name"] for item in policy["blacklist"]]
            else:
                policy.pop("blacklist", None)
            policy.pop("blacklist-num", None)
            if "whitelist" in policy and policy["whitelist"]:
                policy["whitelist"] = [item["domain-name"] for item in policy["whitelist"]]
            else:
                policy.pop("whitelist", None)
            policy.pop("whitelist-num", None)
        return policies

    async def get_urlfiltering_blockingcategories(
        self, timeout: int | None = None
    ) -> list[UrlBlockCategory]:
        """Return a list of URL Filtering Blocking Categories

        Args:
            timeout: per-request timeout in seconds; defaults to the session's.
        """
        try:
            return await self._get_conf(
                ConfigItem.URLFILTERINGCATEGORY_LIST,
                target_type=list[UrlBlockCategory], timeout=timeout
            )
        except KeyError:
            return [{"id": k, "name": v} for k, v in URL_FILTERING_CATEGORIES.items()]

    async def get_ip4_policies(self, timeout: int | None = None) -> list[Ip4Policy]:
        """Return a list of IP4 Policies

        Args:
            timeout: per-request timeout in seconds; defaults to the session's.
        """
        return await self._get_conf(
            ConfigItem.POLICY_LIST, target_type=list[Ip4Policy], timeout=timeout
        )

    async def get_ip6_policies(self, timeout: int | None = None) -> list[Ip6Policy]:
        """Return a list of IP6 Policies

        Args:
            timeout: per-request timeout in seconds; defaults to the session's.
        """
        return await self._get_conf(
            ConfigItem.POLICY6_LIST, target_type=list[Ip6Policy], timeout=timeout
        )

    async def get_device_policies(self, timeout: int | None = None) -> list[DevicePolicy]:
        """Return a list of Device Policies

        Args:
            timeout: per-request timeout in seconds; defaults to the session's.
        """
        try:
            return await self._get_conf(
                ConfigItem.DEVICEPOLICY_LIST, target_type=list[DevicePolicy], timeout=timeout
            )
        except KeyError:
            return []

    async def get_precedence_policies(
        self, timeout: int | None = None
    ) -> list[PrecedencePolicy]:
        """Return a list of Precedence Policies

        Args:
            timeout: per-request timeout in seconds; defaults to the session's.
        """
        try:
            policies = await self._get_conf(
                ConfigItem.PRECEDENCE_LIST, target_type=list[PrecedencePolicy], timeout=timeout
            )
            for policy in policies:
                if "prerule" in policy:
                    for prerule in policy["prerule"]:
                        prerule["order"] = prerule["order"].split(",")
            return policies
        except KeyError:
            return [{'id': '1', 'name': 'Default', 'EDITABLE': 'true', 'prerule': [{'description': '', 'attr': 'vlan', 'order': ['AAA', 'Device Policy', 'WLAN'], 'EDITABLE': 'false'}, {'description': '', 'attr': 'rate-limit', 'order': ['AAA', 'Device Policy', 'WLAN'], 'EDITABLE': 'false'}]}]

    async def get_arc_policies(self, timeout: int | None = None) -> list[ArcPolicy]:
        """Return a list of Application Recognition & Control Policies

        Args:
            timeout: per-request timeout in seconds; defaults to the session's.
        """
        return await self._get_conf(
            ConfigItem.AVPPOLICY_LIST, target_type=list[ArcPolicy], timeout=timeout
        )

    async def get_arc_applications(
        self, timeout: int | None = None
    ) -> list[ArcApplication]:
        """Return a list of Application Recognition & Control User Defined Applications

        Args:
            timeout: per-request timeout in seconds; defaults to the session's.
        """
        try:
            return await self._get_conf(
                ConfigItem.AVPAPPLICATION_LIST,
                target_type=list[ArcApplication], timeout=timeout
            )
        except KeyError:
            return []

    async def get_arc_ports(self, timeout: int | None = None) -> list[ArcPort]:
        """Return a list of Application Recognition & Control User Defined Ports

        Args:
            timeout: per-request timeout in seconds; defaults to the session's.
        """
        try:
            return await self._get_conf(
                ConfigItem.AVPPORT_LIST, target_type=list[ArcPort], timeout=timeout
            )
        except KeyError:
            return []

    async def get_roles(self, timeout: int | None = None) -> list[Role]:
        """Return a list of Roles

        Args:
            timeout: per-request timeout in seconds; defaults to the session's.
                Applies to each of the requests this makes rather than to the
                whole operation.
        """
        wlan_map = {wlan['id']: wlan for wlan in await self.get_wlans(timeout=timeout)}
        return await self.__get_roles(wlan_map, timeout)

    async def __get_roles(
        self, wlan_map: dict[str, Wlan], timeout: int | None = None
    ) -> list[Role]:
        """Return a list of Roles"""
        try:
            roles = await self._get_conf(
                ConfigItem.ROLE_LIST, target_type=list[Role], timeout=timeout
            )
        except KeyError:
            return []
        urlfilter_list, devicepolicy_list, arcpolicy_list, policy_list, policy6_list = await asyncio.gather(
            self.get_urlfiltering_policies(timeout=timeout),
            self.get_device_policies(timeout=timeout),
            self.get_arc_policies(timeout=timeout),
            self.get_ip4_policies(timeout=timeout),
            self.get_ip6_policies(timeout=timeout)
        )
        urlfilter_map = {policy['id']: policy for policy in urlfilter_list}
        devicepolicy_map = {policy['id']: policy for policy in devicepolicy_list}
        arcpolicy_map = {policy['id']: policy for policy in arcpolicy_list}
        policy_map = {policy['id']: policy for policy in policy_list}
        policy6_map = {policy['id']: policy for policy in policy6_list}
        for role in roles:
            if "allow-wlansvc" in role:
                role["allow-wlansvc"] = [
                        deepcopy(wlan_map[wlansvc["id"]])
                        for wlansvc in role["allow-wlansvc"]
                    ]
            if "url-filtering-id" in role:
                if role["url-filtering-id"] and role["url-filtering-id"] in urlfilter_map:
                    role["url-filtering"] = deepcopy(urlfilter_map[role["url-filtering-id"]])
                del role["url-filtering-id"]
            if "dvc-pcy-id" in role:
                if role["dvc-pcy-id"] and role["dvc-pcy-id"] in devicepolicy_map:
                    role["dvc-pcy"] = deepcopy(devicepolicy_map[role["dvc-pcy-id"]])
                del role["dvc-pcy-id"]
            if "arc-pcy-id" in role:
                if role["arc-pcy-id"] and role["arc-pcy-id"] in arcpolicy_map:
                    role["arc-pcy"] = deepcopy(arcpolicy_map[role["arc-pcy-id"]])
                del role["arc-pcy-id"]
            if "policy-id" in role:
                if role["policy-id"] and role["policy-id"] in policy_map:
                    role["policy"] = deepcopy(policy_map[role["policy-id"]])
                del role["policy-id"]
            if "policy6-id" in role:
                if role["policy6-id"] and role["policy6-id"] in policy6_map:
                    role["policy6"] = deepcopy(policy6_map[role["policy6-id"]])
                del role["policy6-id"]
        return roles

    async def get_dpsks(self, timeout: int | None = None) -> list[Dpsk]:
        """Return a list of DPSKs

        Args:
            timeout: per-request timeout in seconds; defaults to the session's.
                Applies to each of the requests this makes rather than to the
                whole operation.
        """
        try:
            dpsks = await self._get_conf(
                ConfigItem.DPSK_LIST, target_type=list[Dpsk], timeout=timeout
            )
        except KeyError:
            return []
        wlan_map = {wlan['id']: wlan for wlan in await self.get_wlans(timeout=timeout)}
        role_map = {role['id']: role for role in await self.__get_roles(wlan_map, timeout)}
        for dpsk in dpsks:
            if "wlansvc-id" in dpsk:
                dpsk["wlansvc"] = deepcopy(wlan_map[dpsk["wlansvc-id"]])
                del dpsk["wlansvc-id"]
            if "role-id" in dpsk:
                if dpsk["role-id"] and dpsk["role-id"] in role_map:
                    dpsk["role"] = deepcopy(role_map[dpsk["role-id"]])
                del dpsk["role-id"]
        return dpsks

    async def get_system_info(
        self, *sections: SystemStat, timeout: int | None = None
    ) -> dict:
        """Return system information, optionally limited to the given sections.

        Args:
            sections: SystemStat sections to fetch; defaults to
                ``SystemStat.DEFAULT``. Passed positionally — ``timeout`` must
                be a keyword argument.
            timeout: per-request timeout in seconds; defaults to the session's.
        """
        section_keys = self._section_keys(sections)
        system_info = await self._get_conf(
            ConfigItem.SYSTEM, target_type=SystemInfo, timeout=timeout
        )
        if not section_keys:
            return system_info
        return {k: v for k, v in system_info.items() if k in section_keys}

    @staticmethod
    def _section_keys(sections: tuple[SystemStat, ...]) -> list[str]:
        """Flatten the SystemStat sections passed to ``get_system_info``.

        ``get_system_info`` takes sections as varargs, so a stray positional
        argument of any type is silently swallowed into ``sections`` and then
        either breaks later with a confusing error or, worse, is ignored. Since
        ``timeout`` can only be passed by keyword as a result, reject anything
        that is not a SystemStat up front and point at the right call.
        """
        for section in sections:
            if not isinstance(section, SystemStat):
                raise TypeError(
                    f"get_system_info() sections must be SystemStat members, "
                    f"got {section!r}; pass timeout as a keyword argument."
                )
        if not sections:
            return SystemStat.DEFAULT.value
        return [key for section in sections for key in section.value]

    async def get_mesh_info(self, timeout: int | None = None) -> Mesh:
        """Return mesh information

        Args:
            timeout: per-request timeout in seconds; defaults to the session's.
        """
        return await self._get_conf(
            ConfigItem.MESH_LIST, target_type=Mesh, timeout=timeout
        )

    async def get_zerotouch_mesh_ap_serials(
        self, timeout: int | None = None
    ) -> list[dict]:
        """Return a list of Pre-approved AP serial numbers

        Args:
            timeout: per-request timeout in seconds; defaults to the session's.
        """
        return await self._get_conf(
            ConfigItem.ZTMESHSERIAL_LIST, target_type=list[dict], timeout=timeout
        )

    async def get_acls(self, timeout: int | None = None) -> list[L2Policy]:
        """Return a list of ACLs

        Args:
            timeout: per-request timeout in seconds; defaults to the session's.
        """
        try:
            return await self._get_conf(
                ConfigItem.ACL_LIST, target_type=list[L2Policy], timeout=timeout
            )
        except KeyError:
            return []

    async def get_blocked_client_macs(self, timeout: int | None = None) -> list[L2Rule]:
        """Return a list of blocked client MACs

        Args:
            timeout: per-request timeout in seconds; defaults to the session's.
        """
        acls = await self.get_acls(timeout=timeout)
        # blocklist is always first acl
        return acls[0].get("deny", []) if acls else []

    async def _get_conf(
        self, item: ConfigItem, target_type: type | None = None, timeout: int | None = None
    ) -> Any:
        """Return the relevant config xml, given a configuration key.

        The response is parsed via :func:`parse_ajax_response`; pass a
        TypedDict (or ``dict`` / ``list``) as ``target_type`` to describe
        the desired structure.
        """
        result_text = await self.session.get_conf_str(item, timeout)
        return parse_ajax_response(
            result_text, target_type, self.session.redact_secrets,
            self.session.decrypts_secrets,
        )

    @staticmethod
    def _normalize_conf_value(current_value: str, new_value: Any) -> str:
        """Normalize new_value format to match current_value"""
        normalization_map = {
            "enable": ("ENABLE", "DISABLE"),
            "disable": ("ENABLE", "DISABLE"),
            "enabled": ("enabled", "disabled"),
            "disabled": ("enabled", "disabled"),
            "true": ("true", "false"),
            "false": ("true", "false"),
            "yes": ("yes", "no"),
            "no": ("yes", "no"),
            "1": ("1", "0"),
            "0": ("1", "0"),
        }
        current_value_lowered = current_value.lower()
        if current_value_lowered in normalization_map:
            new_value = RuckusConfigurationApi._parse_conf_bool(new_value)
            if isinstance(new_value, bool):
                true_value, false_value = normalization_map[current_value_lowered]
                new_value = true_value if new_value else false_value
        return str(new_value)

    @staticmethod
    def _parse_conf_bool(value: Any) -> bool | Any:
        """Coerce common boolean representations to bool, else return unchanged.

        Accepts bools, numeric 1/0 and strings like "enable"/"disabled"/"yes"/"no".
        """
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            if value == 1:
                return True
            if value == 0:
                return False
        if isinstance(value, str):
            value_lowered = value.lower()
            if value_lowered in ("enable", "enabled", "true", "yes", "1"):
                return True
            if value_lowered in ("disable", "disabled", "false", "no", "0"):
                return False
        return value