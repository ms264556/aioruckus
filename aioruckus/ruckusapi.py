from abc import ABC
from copy import deepcopy
from typing import List

import xmltodict

from .abcsession import AbcSession, ConfigItem
from .const import SystemStat

class RuckusApi(ABC):

    def __init__(self, session: AbcSession):
        self.session = session

    async def get_aps(self) -> List[dict]:
        return await self._get_conf(ConfigItem.AP_LIST, ["ap"])

    async def get_ap_groups(self) -> List:
        ap_map = {ap['id']: ap for ap in await self.get_aps()}
        wlang_map = {wlang['id']: wlang for wlang in await self.get_wlan_groups()}
        ap_groups = await self._get_conf(ConfigItem.APGROUP_LIST, ["apgroup", "radio", "model", "port", "ap", "wlansvc"])
        for ap_group in ap_groups:
            if "members" not in ap_group or ap_group["members"] is None or "ap" not in ap_group["members"] or ap_group["members"]["ap"] is None:
                ap_group["ap"] = []
            else:
                ap_group["ap"] = [deepcopy(ap_map[ap["id"]]) for ap in ap_group["members"]["ap"]]
            ap_group.pop("members", None)
            if "wlangroup" in ap_group:
                if ap_group["wlangroup"] is None or "wlansvc" not in ap_group["wlangroup"] or ap_group["wlangroup"]["wlansvc"] is None:
                    ap_group["wlansvc"] = []
                else:
                    ap_group["wlansvc"] = [deepcopy(wlang_map[wlang["id"]])  for wlang in ap_group["wlangroup"]["wlansvc"]]
                del ap_group["wlangroup"]
        return ap_groups

    async def get_wlans(self) -> List[dict]:
        return await self._get_conf(ConfigItem.WLANSVC_LIST, ["wlansvc"])
    
    async def get_wlan_groups(self) -> List[dict]:
        wlan_map = {wlan['id']: wlan for wlan in await self.get_wlans()}
        wlan_groups = await self._get_conf(ConfigItem.WLANGROUP_LIST, ["wlangroup", "wlansvc"])
        for wlan_group in wlan_groups:
            if "wlansvc" in wlan_group:
                wlan_group["wlansvc"] = [deepcopy(wlan_map[wlansvc["id"]])  for wlansvc in wlan_group["wlansvc"]]
        return wlan_groups

    async def get_system_info(self, *sections: SystemStat) -> dict:
        system_info = (await self._get_conf(ConfigItem.SYSTEM))["system"]
        sections = [s for section_list in sections for s in section_list.value] if sections else SystemStat.DEFAULT.value
        if not sections:
            return system_info
        else:
            return {k:v for k,v in system_info.items() if k in sections}

    async def get_mesh_info(self) -> dict:
        return (await self._get_conf(ConfigItem.MESH_LIST))["mesh-list"]["mesh"]

    async def get_zerotouch_mesh_ap_serials(self) -> dict:
        return await self._get_conf(ConfigItem.ZTMESHSERIAL_LIST, ["ztmeshSerial"])

    async def get_acls(self) -> List:
        return await self._get_conf(ConfigItem.ACL_LIST, ["accept", "deny", "acl"])
    
    async def get_blocked_client_macs(self) -> List:
        blockedinfo = await self.get_acls()
        denylist = blockedinfo[0]["deny"] if "deny" in blockedinfo[0] else None
        return [] if not denylist else [d for d in denylist if d]

    @staticmethod
    def _ruckus_xml_unwrap(xml: str, collection_elements: List[str] = None) -> dict | List:
        # convert xml and unwrap collection
        force_list = None if not collection_elements else {ce: True for ce in collection_elements}
        result = xmltodict.parse(xml, encoding="utf-8", attr_prefix='', postprocessor=RuckusApi._process_ruckus_xml, force_list=force_list)
        collection_list = [] if not collection_elements else [f"{ce}-list" for ce in collection_elements] + collection_elements
        for key in ["ajax-response", "response", "apstamgr-stat"] + collection_list:
            if result and key and key in result:
                result = result[key]
        return result or []

    @staticmethod
    def _process_ruckus_xml(path, key, value):
        # passphrases are obfuscated and stored with an x- prefix; decrypt these
        if key.startswith("x-"):
            return key[2:], ''.join(chr(ord(letter) - 1) for letter in value) if value else value
        elif key == "apstamgr-stat" and not value:  # return an empty array rather than None, for ease of use
            return key, []
        # client status is numeric code for active, and name for inactive. Show name for everything
        elif key == "status" and value and value.isnumeric() and path and len(path) > 0 and path[-1][0] == "client":
            description = "Authorized" if value == "1" else "Authenticating" if value == "2" else "PSK Expired" if value == "3" else "Authorized(Deny)" if value == "4" else "Authorized(Permit)" if value == "5" else "Unauthorized"
            return key, description
        else:
            return key, value

    async def _get_conf(self, item: ConfigItem, collection_elements: List[str] = None) -> dict | List[dict]:
        result_text = await self.session.get_conf_str(item)
        return self._ruckus_xml_unwrap(result_text, collection_elements)