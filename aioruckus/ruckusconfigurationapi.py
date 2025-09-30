"""Ruckus ZoneDirector or Unleashed Configuration API"""
from __future__ import annotations
from abc import ABC
import asyncio
from copy import deepcopy
from typing import Any

from .abcsession import AbcSession, ConfigItem
from .ajaxtyping import Ap, ApGroup, ArcApplication, ArcPolicy, ArcPort, DevicePolicy, Dpsk, Ip4Policy, Ip6Policy, L2Policy, L2Rule, Mesh, PrecedencePolicy, Role, UrlBlockCategory, UrlFilter, Wlan, WlanGroup
from .const import URL_FILTERING_CATEGORIES, SystemStat
from .utility import unwrap_xml

class RuckusConfigurationApi(ABC):
    """Ruckus ZoneDirector/Unleashed Configuration API"""
    def __init__(self, session: AbcSession):
        self.session = session

    async def get_aps(self) -> list[Ap]:
        """Return a list of APs"""
        return await self._get_conf(ConfigItem.AP_LIST, ["ap"])

    async def get_ap_groups(self) -> list[ApGroup]:
        """Return a list of AP groups"""
        ap_map = {ap['id']: ap for ap in await self.get_aps()}
        wlan_map = {wlan['id']: wlan for wlan in await self.get_wlans()}
        wlang_map = {wlang['id']: wlang for wlang in await self.get_wlan_groups()}
        ap_groups = await self._get_conf(
            ConfigItem.APGROUP_LIST, ["apgroup", "radio", "model", "port", "ap", "wlansvc"]
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
                        for wlan in ap_group["wlangroup"]["wlansvc"]
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

    async def get_wlans(self) -> list[Wlan]:
        """Return a list of WLANs"""
        wlans = await self._get_conf(ConfigItem.WLANSVC_LIST, ["wlansvc"])
        if wlans:
            acl_list, urlfilter_list, precedence_list, devicepolicy_list, arcpolicy_list, policy_list, policy6_list = await asyncio.gather(
                self.get_acls(),
                self.get_urlfiltering_policies(),
                self.get_precedence_policies(),
                self.get_device_policies(),
                self.get_arc_policies(),
                self.get_ip4_policies(),
                self.get_ip6_policies()
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
                if urlfiltering_policy and self._parse_conf_bool(urlfiltering_policy.get("urlfiltering-enabled")) is True:
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
                if avp_policy and self._parse_conf_bool(avp_policy.get("avp-enabled")) is True:
                    wlan["avp-policy"] = deepcopy(arcpolicy_map[avp_policy["avpdeny-id"]])
                else:
                    wlan.pop("avp-policy", None)
        return wlans

    async def get_wlan_groups(self) -> list[WlanGroup]:
        """Return a list of WLAN groups"""
        wlan_map = {wlan['id']: wlan for wlan in await self.get_wlans()}
        wlan_groups = await self._get_conf(ConfigItem.WLANGROUP_LIST, ["wlangroup", "wlansvc"])
        for wlan_group in wlan_groups:
            if "wlansvc" in wlan_group:
                wlan_group["wlansvc"] = [
                    deepcopy(wlan_map[wlansvc["id"]])
                    for wlansvc in wlan_group["wlansvc"]
                ]
        return wlan_groups

    async def get_urlfiltering_policies(self) -> list[UrlFilter]:
        """Return a list of URL Filtering Policies"""
        try:
            policies = await self._get_conf(ConfigItem.URLFILTERINGPOLICY_LIST, ["urlfilteringpolicy", "rule", "whitelist", "blacklist"])
        except KeyError:
            return []
        block_map = {category['id']: category for category in await self.get_urlfiltering_blockingcategories()}
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

    async def get_urlfiltering_blockingcategories(self) -> list[UrlBlockCategory]:
        """Return a list of URL Filtering Blocking Categories"""
        try:
            return await self._get_conf(ConfigItem.URLFILTERINGCATEGORY_LIST, ["urlfiltering-blockcategories", "list"])
        except KeyError:
            return [{"id": k, "name": v} for k, v in URL_FILTERING_CATEGORIES.items()]

    async def get_ip4_policies(self) -> list[Ip4Policy]:
        """Return a list of IP4 Policies"""
        return await self._get_conf(ConfigItem.POLICY_LIST, ["policy", "rule"])

    async def get_ip6_policies(self) -> list[Ip6Policy]:
        """Return a list of IP6 Policies"""
        return await self._get_conf(ConfigItem.POLICY6_LIST, ["policy6", "rule6"])

    async def get_device_policies(self) -> list[DevicePolicy]:
        """Return a list of Device Policies"""
        try:
            return await self._get_conf(ConfigItem.DEVICEPOLICY_LIST, ["devicepolicy", "devrule"])
        except KeyError:
            return []

    async def get_precedence_policies(self) -> list[PrecedencePolicy]:
        """Return a list of Precedence Policies"""
        try:
            policies = await self._get_conf(ConfigItem.PRECEDENCE_LIST, ["precedence", "prerule"])
            for policy in policies:
                if "prerule" in policy:
                    for prerule in policy["prerule"]:
                        prerule["order"] = prerule["order"].split(",")
            return policies
        except KeyError:
            return [{'id': '1', 'name': 'Default', 'EDITABLE': 'true', 'prerule': [{'description': '', 'attr': 'vlan', 'order': ['AAA', 'Device Policy', 'WLAN'], 'EDITABLE': 'false'}, {'description': '', 'attr': 'rate-limit', 'order': ['AAA', 'Device Policy', 'WLAN'], 'EDITABLE': 'false'}]}]

    async def get_arc_policies(self) -> list[ArcPolicy]:
        """Return a list of Application Recognition & Control Policies"""
        return await self._get_conf(ConfigItem.AVPPOLICY_LIST, ["avppolicy", "avprule"])

    async def get_arc_applications(self) -> list[ArcApplication]:
        """Return a list of Application Recognition & Control User Defined Applications"""
        try:
            return await self._get_conf(ConfigItem.AVPAPPLICATION_LIST, ["avpapplication"])
        except KeyError:
            return []

    async def get_arc_ports(self) -> list[ArcPort]:
        """Return a list of Application Recognition & Control User Defined Ports"""
        try:
            return await self._get_conf(ConfigItem.AVPPORT_LIST, ["avpport"])
        except KeyError:
            return []

    async def get_roles(self) -> list[Role]:
        """Return a list of Roles"""
        wlan_map = {wlan['id']: wlan for wlan in await self.get_wlans()}
        return await self.__get_roles(wlan_map)

    async def __get_roles(self, wlan_map: dict[str, Wlan]) -> list[Role]:
        """Return a list of Roles"""
        try:
            roles = await self._get_conf(ConfigItem.ROLE_LIST, ["role", "allow-wlansvc"])
        except KeyError:
            return []
        urlfilter_list, devicepolicy_list, arcpolicy_list, policy_list, policy6_list = await asyncio.gather(
            self.get_urlfiltering_policies(),
            self.get_device_policies(),
            self.get_arc_policies(),
            self.get_ip4_policies(),
            self.get_ip6_policies()
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

    async def get_dpsks(self) -> list[Dpsk]:
        """Return a list of DPSKs"""
        try:
            dpsks = await self._get_conf(ConfigItem.DPSK_LIST, ["dpsk"])
        except KeyError:
            return []
        wlan_map = {wlan['id']: wlan for wlan in await self.get_wlans()}
        role_map = {role['id']: role for role in await self.__get_roles(wlan_map)}
        for dpsk in dpsks:
            if "wlansvc-id" in dpsk:
                dpsk["wlansvc"] = deepcopy(wlan_map[dpsk["wlansvc-id"]])
                del dpsk["wlansvc-id"]
            if "role-id" in dpsk:
                if dpsk["role-id"] and dpsk["role-id"] in role_map:
                    dpsk["role"] = deepcopy(role_map[dpsk["role-id"]])
                del dpsk["role-id"]
        return dpsks

    async def get_system_info(self, *sections: SystemStat) -> dict:
        """Return system information"""
        system_info = (await self._get_conf(ConfigItem.SYSTEM))["system"]
        
        section_keys: list[str]
        if sections:
            section_keys = [s for section_list in sections for s in section_list.value]
        else:
            section_keys = SystemStat.DEFAULT.value
        if not section_keys:
            return system_info
        return {k: v for k, v in system_info.items() if k in section_keys}

    async def get_mesh_info(self) -> Mesh:
        """Return mesh information"""
        return (await self._get_conf(ConfigItem.MESH_LIST))["mesh-list"]["mesh"]
    
    async def get_zerotouch_mesh_ap_serials(self) -> list[dict]:
        """Return a list of Pre-approved AP serial numbers"""
        return await self._get_conf(ConfigItem.ZTMESHSERIAL_LIST, ["ztmeshSerial"])

    async def get_acls(self) -> list[L2Policy]:
        """Return a list of ACLs"""
        try:
            return await self._get_conf(ConfigItem.ACL_LIST, ["accept", "deny", "acl"])
        except KeyError:
            return []

    async def get_blocked_client_macs(self) -> list[L2Rule]:
        """Return a list of blocked client MACs"""
        acls = await self.get_acls()
        # blocklist is always first acl
        return acls[0].get("deny", []) if acls else []

    async def _get_conf(
        self, item: ConfigItem, collection_elements: list[str] | None = None
    ) -> Any:
        """Return the relevant config xml, given a configuration key"""
        result_text = await self.session.get_conf_str(item)
        return unwrap_xml(result_text, collection_elements)

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