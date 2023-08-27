"""Adds AJAX Statistics and Command methods to RuckusApi"""

from collections.abc import AsyncIterator
import datetime
import random
from re import IGNORECASE, match
from typing import Any, Dict, List
import xml.etree.ElementTree as ET
from xml.sax import saxutils
import xmltodict

from .const import (
    ERROR_INVALID_MAC,
    ERROR_PASSPHRASE_LEN,
    ERROR_PASSPHRASE_JS,
    ERROR_PASSPHRASE_MISSING,
    ERROR_SAEPASSPHRASE_MISSING,
    ERROR_INVALID_WLAN,
    ERROR_PASSPHRASE_NAME,
    SystemStat,
    WlanEncryption
)
from .abcsession import ConfigItem
from .ajaxsession import AjaxSession
from .ruckusapi import RuckusApi

class RuckusAjaxApi(RuckusApi):
    """Ruckus ZoneDirector or Unleashed Configuration, Statistics and Commands API"""
    def __init__(self, session: AjaxSession):
        super().__init__(session)

    async def get_system_info(self, *sections: SystemStat) -> dict:
        sections = (
            [s for section_list in sections for s in section_list.value]
            if sections else SystemStat.DEFAULT.value
        )
        section = ''.join(f"<{s}/>" for s in sections)
        sysinfo = await self.cmdstat(
            f"<ajax-request action='getstat' comp='system'>{section}</ajax-request>"
        )
        return sysinfo.get("response", sysinfo.get("system"))

    async def get_active_clients(self, interval_stats: bool = False) -> List:
        """Return a list of active clients"""
        if interval_stats:
            endtime = await self._get_timestamp_at_controller()
            starttime = endtime - 86400
            clientrequest = f"<client INTERVAL-STATS='yes' INTERVAL-START='{starttime}' INTERVAL-STOP='{endtime}' />"
        else:
            clientrequest = "<client LEVEL='1' />"
        return await self.cmdstat(f"<ajax-request action='getstat' comp='stamgr' enable-gzip='0'>{clientrequest}</ajax-request>", ["client"])

    async def get_inactive_clients(self) -> List:
        """Return a list of inactive clients"""
        return await self.cmdstat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><clientlist period='0' /></ajax-request>", ["client"])

    async def get_ap_stats(self) -> List:
        """Return a list of AP statistics"""
        return await self.cmdstat(
            "<ajax-request action='getstat' comp='stamgr' enable-gzip='0'>"
            "<ap LEVEL='1' /></ajax-request>", ["ap"]
        )

    async def get_ap_group_stats(self) -> List:
        """Return a list of AP group statistics"""
        return await self.cmdstat(
            "<ajax-request action='getstat' comp='stamgr' enable-gzip='0'>"
            "<apgroup /></ajax-request>", ["group", "radio", "ap"]
        )

    async def get_vap_stats(self) -> List:
        """Return a list of Virtual AP (per-radio WLAN) statistics"""
        return await self.cmdstat(
            "<ajax-request action='getstat' comp='stamgr' enable-gzip='0' caller='SCI'>"
            "<vap INTERVAL-STATS='no' LEVEL='1' /></ajax-request>", ["vap"]
        )

    async def get_wlan_group_stats(self) -> List:
        """Return a list of WLAN group statistics"""
        return await self.cmdstat(
            "<ajax-request action='getstat' comp='stamgr' enable-gzip='0' caller='SCI'>"
            "<wlangroup /></ajax-request>", ["wlangroup", "wlan"]
        )

    async def get_active_rogues(self) -> list[dict]:
        """Return a list of currently active rogue devices"""
        return await self.cmdstat(
            "<ajax-request action='getstat' comp='stamgr' enable-gzip='0'>"
            "<rogue LEVEL='1' recognized='!true'/></ajax-request>", ["rogue"]
        )

    async def get_known_rogues(self, limit: int = 300) -> list[dict]:
        """Return a list of known/recognized rogues devices"""
        return [rogue async for rogue in self.cmdstat_piecewise("stamgr", "rogue", "apstamgr-stat", filter={"LEVEL": "1", "recognized": "true"}, updater="krogue", limit=limit)]

    async def get_blocked_rogues(self, limit: int = 300) -> list[dict]:
        """Return a list of user blocked rogues devices"""
        return [rogue async for rogue in self.cmdstat_piecewise("stamgr", "rogue", "apstamgr-stat", filter={"LEVEL": "1", "blocked": "true"}, updater="brogue", limit=limit)]

    async def get_all_alarms(self, limit: int = 300) -> list[dict]:
        """Return a list of all alerts"""
        return [alarm async for alarm in self.cmdstat_piecewise("eventd", "alarm", updater="page", limit=limit)]

    async def get_all_events(self, limit: int = 300) -> list[dict]:
        """Return a list of all events"""
        return [xevent async for xevent in self.cmdstat_piecewise("eventd", "xevent", limit=limit)]

    async def get_wlan_events(self, *wlan_ids, limit: int = 300) -> list[dict]:
        """Return a list of WLAN events"""
        return [xevent async for xevent in self.cmdstat_piecewise("eventd", "xevent", filter={"wlan": list(wlan_ids) if wlan_ids else "*"}, limit=limit)]

    async def get_ap_events(self, *ap_macs, limit: int = 300) -> list[dict]:
        """Return a list of AP events"""
        return [xevent async for xevent in self.cmdstat_piecewise("eventd", "xevent", filter={"ap": list(self._normalize_mac(mac) for mac in ap_macs) if ap_macs else "*"}, limit=limit)]

    async def get_client_events(self, limit: int = 300) -> list[dict]:
        """Return a list of client events"""
        return [xevent async for xevent in self.cmdstat_piecewise("eventd", "xevent", filter={"c": "user"}, limit=limit)]

    async def get_wired_client_events(self, limit: int = 300) -> list[dict]:
        """Return a list of wired client events"""
        return [xevent async for xevent in self.cmdstat_piecewise("eventd", "xevent", filter={"c": "wire"}, limit=limit)]

    async def get_syslog(self) -> str:
        """Return a list of syslog entries"""
        ts = self._ruckus_timestamp()
        syslog = await self.cmdstat(
            f"<ajax-request action='docmd' xcmd='get-syslog' updater='system.{ts}' comp='system'>"
            f"<xcmd cmd='get-syslog' type='sys'/></ajax-request>"
        )
        return syslog["xmsg"]["res"]

    async def do_block_client(self, mac: str) -> None:
        """Block a client"""
        mac = self._normalize_mac(mac)
        await self.cmdstat(
            f"<ajax-request action='docmd' xcmd='block' checkAbility='10' comp='stamgr'>"
            f"<xcmd check-ability='10' tag='client' acl-id='1' client='{mac}' cmd='block'>"
            f"<client client='{mac}' acl-id='1' hostname=''></client></xcmd></ajax-request>"
        )

    async def do_unblock_client(self, mac: str) -> None:
        """Unblock a client"""
        mac = self._normalize_mac(mac)
        blocked = await self.get_blocked_client_macs()
        remaining = ''.join((
            f"<deny mac='{deny['mac']}' type='single'/>" for deny in blocked
            if deny["mac"] != mac
        ))
        await self._do_conf(
            f"<ajax-request action='updobj' comp='acl-list' updater='blocked-clients'>"
            f"<acl id='1' name='System' description='System' default-mode='allow' EDITABLE='false'>"
            f"{remaining}</acl></ajax-request>"
        )

    async def do_delete_ap_group(self, name: str) -> bool:
        """Delete an AP group"""
        ap_group = await self._find_ap_group_by_name(name)
        if ap_group is None:
            return False
        ts = self._ruckus_timestamp()
        await self._do_conf(
            f"<ajax-request action='delobj' updater='apgroup-list.{ts}' comp='apgroup-list'>"
            f"<apgroup id='{ap_group['id']}'/></ajax-request>"
        )
        return True

    async def do_disable_wlan(self, name: str, disable_wlan: bool = True) -> None:
        """Disable a WLAN"""
        wlan = await self._find_wlan_by_name(name)
        if wlan:
            ts = self._ruckus_timestamp()
            await self._do_conf(
                f"<ajax-request action='updobj' updater='wlansvc-list.{ts}' comp='wlansvc-list'>"
                f"<wlansvc id='{wlan['id']}' name='{wlan['name']}' "
                f"enable-type='{1 if disable_wlan else 0}' IS_PARTIAL='true'/></ajax-request>"
            )

    async def do_enable_wlan(self, name: str) -> None:
        """Enable a WLAN"""
        await self.do_disable_wlan(name, False)

    async def do_set_wlan_password(
        self,
        name: str,
        passphrase: str,
        sae_passphrase: str = None
    ) -> None:
        """Set a WLAN password"""
        sae_passphrase = sae_passphrase or passphrase
        await self.do_edit_wlan(
            name, {"wpa": {"passphrase": passphrase, "sae-passphrase": sae_passphrase}}, True
        )

    async def do_add_wlan(
        self,
        name: str,
        encryption: WlanEncryption = WlanEncryption.WPA2,
        passphrase: str = None,
        sae_passphrase: str = None,
        ssid_override: str = None,
        ignore_unknown_attributes: bool = False
    ) -> None:
        """Add a WLAN"""
        patch = {"name": name, "ssid": ssid_override or name, "encryption": encryption.value}
        if passphrase is not None or sae_passphrase is not None:
            patch_wpa = {}
            patch["wpa"] = patch_wpa
            if passphrase is not None:
                patch_wpa["passphrase"] = passphrase
            if sae_passphrase is not None:
                patch_wpa["sae-passphrase"] = sae_passphrase
        await self.do_clone_wlan(patch)

    async def do_clone_wlan(
        self, template: dict, new_name: str = None, new_ssid: str = None
    ) -> None:
        """Clone a WLAN"""
        wlansvc = await self._get_default_wlan_template()
        self._normalize_encryption(wlansvc, template)
        self._patch_template(wlansvc, template, True)
        if new_name is not None or new_ssid is not None:
            if new_name is None:
                raise ValueError(ERROR_PASSPHRASE_NAME)
            self._patch_template(wlansvc, {"name": new_name, "ssid": new_ssid or new_name })
        await self._add_wlan_template(wlansvc)

    async def do_edit_wlan(
        self, name: str, patch: dict, ignore_unknown_attributes: bool = False
    ) -> None:
        """Edit a WLAN"""
        wlansvc = await self._get_wlan_template(name)
        if wlansvc:
            self._normalize_encryption(wlansvc, patch)
            self._patch_template(wlansvc, patch, ignore_unknown_attributes)
            await self._update_wlan_template(wlansvc)

    async def do_delete_wlan(self, name: str) -> bool:
        """Delete a WLAN"""
        wlan = await self._find_wlan_by_name(name)
        if wlan is None:
            return False
        ts = self._ruckus_timestamp()
        await self._do_conf(
            f"<ajax-request action='delobj' updater='wlansvc-list.{ts}' comp='wlansvc-list'>"
            f"<wlansvc id='{wlan['id']}'/></ajax-request>", timeout=20
        )
        return True

    async def do_add_wlan_group(self, name: str, description: str = "", wlans: List = None) -> None:
        """Add a WLAN group"""
        wlangroup = ET.Element("wlangroup", {"name": name, "description": description or ""})
        if wlans is not None:
            wlan_map = {wlan["name"]:wlan["id"] for wlan in await self.get_wlans()}
            for wlansvc in wlans:
                wlan_name = None
                if isinstance(wlansvc, str):
                    if wlansvc in wlan_map:
                        wlan_name = wlansvc
                elif isinstance(wlansvc, dict):
                    if "name" in wlansvc and wlansvc["name"] in wlan_map:
                        wlan_name = wlansvc["name"]
                if wlan_name is None:
                    raise ValueError(ERROR_INVALID_WLAN)
                ET.SubElement(wlangroup, "wlansvc", {"id": wlan_map[wlan_name]})
        await self._do_conf(
            f"<ajax-request action='addobj' comp='wlangroup-list' updater='wgroup'>"
            f"{ET.tostring(wlangroup).decode('utf-8')}</ajax-request>"
        )

    async def do_clone_wlan_group(self, template: dict, name: str, description: str = None) -> None:
        """Clone a WLAN group"""
        wlangroup = ET.Element("wlangroup", {
            "name": name,
            "description": description or template.get("description", "")
        })
        if "wlan" in template:
            wlan_map = {wlan["name"]:wlan["id"] for wlan in await self.get_wlans()}
            for wlansvc in template["wlan"]:
                ET.SubElement(wlangroup, "wlansvc", {"id": wlan_map[wlansvc["name"]]})
        await self._do_conf(
            f"<ajax-request action='addobj' comp='wlangroup-list' updater='wgroup'>"
            f"{ET.tostring(wlangroup).decode('utf-8')}</ajax-request>"
        )

    async def do_delete_wlan_group(self, name: str) -> bool:
        """Delete a WLAN group"""
        wlang = await self._find_wlan_group_by_name(name)
        if wlang is None:
            return False
        ts = self._ruckus_timestamp()
        await self._do_conf(
            f"<ajax-request action='delobj' updater='wlangroup-list.{ts}' comp='wlangroup-list'>"
            f"<wlangroup id='{wlang['id']}'/></ajax-request>"
        )
        return True

    async def do_hide_ap_leds(self, mac: str, leds_off: bool = True) -> None:
        """Hide AP LEDs"""
        mac = self._normalize_mac(mac)
        found_ap = await self._find_ap_by_mac(mac)
        if found_ap:
            ts = self._ruckus_timestamp()
            await self._do_conf(
                f"<ajax-request action='updobj' updater='ap-list.{ts}' comp='ap-list'>"
                f"<ap id='{found_ap['id']}' IS_PARTIAL='true' led-off='{str(leds_off).lower()}' />"
                f"</ajax-request>"
            )

    async def do_show_ap_leds(self, mac: str) -> None:
        """Show AP LEDs"""
        await self.do_hide_ap_leds(mac, False)

    async def do_restart_ap(self, mac: str) -> None:
        """Restart AP"""
        mac = self._normalize_mac(mac)
        ts = self._ruckus_timestamp()
        return await self._cmdstat_noparse(
            f"<ajax-request action='docmd' xcmd='reset' checkAbility='2' updater='stamgr.{ts}' "
            f"comp='stamgr'><xcmd cmd='reset' ap='{mac}' tag='ap' checkAbility='2'/></ajax-request>"
        )

    async def _get_default_apgroup_template(self) -> ET.Element:
        """Get default AP group template"""
        xml = await self.session.get_conf_str(ConfigItem.APGROUP_TEMPLATE)
        root = ET.fromstring(xml)
        return root.find(".//apgroup")

    async def _get_default_wlan_template(self) -> ET.Element:
        """Get default WLAN template"""
        xml = await self.session.get_conf_str(ConfigItem.WLANSVC_STANDARD_TEMPLATE)
        root = ET.fromstring(xml)
        wlansvc = root.find(".//wlansvc")
        if wlansvc is not None:
            return wlansvc
        return self._get_default_cli_wlan_template()

    @staticmethod
    def _get_default_cli_wlan_template() -> ET.Element:
        wlansvc = ET.Element("wlansvc", {
            "name": "default-standard-wlan", "ssid": "", "authentication": "open",
            "encryption": "none", "is-guest": "false", "max-clients-per-radio": "100",
            "do-802-11d": "disabled", "sta-info-extraction": "1", "force-dhcp": "0",
            "force-dhcp-timeout": "10", "usage": "user", "policy-id": "", "policy6-id": "",
            "precedence-id": "1", "devicepolicy-id": "", "role-based-access-ctrl": "false",
            "acl-id": "1", "local-bridge": "1", "client-isolation": "disabled",
            "ci-whitelist-id": "0", "bgscan": "1", "idle-timeout": "1", "max-idle-timeout": "300",
            "dis-dgaf": "0", "authstats": "0", "https-redirection": "disabled"
        })
        ET.SubElement(wlansvc, "qos", {"uplink-preset": "DISABLE", "downlink-preset": "DISABLE"})
        ET.SubElement(wlansvc, "queue-priority", {
            "voice": "0", "video": "2", "data": "4", "background": "6"
        })
        ET.SubElement(wlansvc, "wlan-schedule", {
            "value": "0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:"
            "0x0:0x0:0x0:0x0: 0x0:0x0:0x0:0x0:0x0:0x0"
        })
        return wlansvc

    async def _get_wlan_template(self, name: str) -> ET.Element | None:
        xml = await self.session.get_conf_str(ConfigItem.WLANSVC_LIST)
        root = ET.fromstring(xml)
        wlansvc = root.find(f".//wlansvc[@name='{saxutils.escape(name)}']")
        return wlansvc

    def _normalize_encryption(self, wlansvc: ET.Element, patch: dict):
        patch_wpa = patch["wpa"] if "wpa" in patch else None
        if patch_wpa is not None:
            if "passphrase" in patch_wpa:
                self._validate_passphrase(patch_wpa["passphrase"])
            if "sae-passphrase" in patch_wpa:
                self._validate_passphrase(patch_wpa["sae-passphrase"])

        encryption = wlansvc.get("encryption")
        if "encryption" in patch and patch["encryption"] != encryption:
            new_encryption = patch["encryption"]
            wlansvc.set("encryption", new_encryption)

            wpa = wlansvc.find("wpa")
            new_wpa = {"cipher": "aes", "dynamic-psk": "disabled"}

            if new_encryption in (WlanEncryption.WPA2.value, WlanEncryption.WPA23_MIXED.value):
                passphrase = wpa.get("passphrase") if wpa is not None else None
                if not patch_wpa.get("passphrase") and passphrase is None:
                    raise ValueError(ERROR_PASSPHRASE_MISSING)
                new_wpa["passphrase"] = passphrase or "<passphrase>"
            if new_encryption in (WlanEncryption.WPA3.value, WlanEncryption.WPA23_MIXED.value):
                sae_passphrase = wpa.get("sae_passphrase") if wpa is not None else None
                if not patch_wpa.get("sae_passphrase") and sae_passphrase is None:
                    raise ValueError(ERROR_SAEPASSPHRASE_MISSING)
                new_wpa["sae-passphrase"] = sae_passphrase or "<passphrase>"

            if wpa is not None:
                wlansvc.remove(wpa)
            if new_encryption != WlanEncryption.NONE.value:
                wpa = ET.SubElement(wlansvc, "wpa", new_wpa)

    def _patch_template(
        self,
        element: ET.Element,
        patch: dict,
        ignore_unknown_attributes: bool = False,
        current_path: str = ""
    ) -> None:
        visited_children = set()
        for child in element:
            if child.tag in patch and isinstance(patch[child.tag], dict):
                self._patch_template(
                    child,
                    patch[child.tag],
                    ignore_unknown_attributes,
                    f"{current_path}/{child.tag}"
                )
                visited_children.add(child.tag)
        for name, value in patch.items():
            if name in visited_children:
                pass
            else:
                current_value = element.get(name)
                if isinstance(value, List):
                    raise ValueError(f"Applying lists is unsupported: {current_path}/{name}")
                if current_value is None:
                    if not ignore_unknown_attributes:
                        raise ValueError(f"Unknown attribute: {current_path}/{name}")
                else:
                    new_value = self._normalize_conf_value(current_value, value)
                    element.set(name, new_value)
                    x_name = f"x-{name}"
                    if x_name not in patch and x_name in element.attrib:
                        element.set(x_name, new_value)

    async def _update_wlan_template(self, wlansvc: ET.Element):
        """Update WLAN template"""
        xml_bytes = ET.tostring(wlansvc)
        await self._do_conf(
            f"<ajax-request action='updobj' updater='wlan' comp='wlansvc-list'>"
            f"{xml_bytes.decode('utf-8')}</ajax-request>", timeout=20
        )

    async def _add_wlan_template(self, wlansvc: ET.Element):
        """Add WLAN template"""
        xml_bytes = ET.tostring(wlansvc)
        await self._do_conf(
            f"<ajax-request action='addobj' updater='wlansvc-list' comp='wlansvc-list'>"
            f"{xml_bytes.decode('utf-8')}</ajax-request>", timeout=20
        )

    async def _find_ap_by_mac(self, mac: str) -> dict:
        """Find AP by MAC"""
        return next((ap for ap in await self.get_aps() if ap["mac"] == mac), None)

    async def _find_ap_group_by_name(self, name: str) -> dict:
        """Find AP group by name"""
        return next((
            ap_group for ap_group in await self.get_ap_groups() if ap_group["name"] == name
        ), None)

    async def _find_wlan_by_name(self, name: str) -> dict:
        """Find WLAN by name"""
        return next((
            wlan for wlan in await self.get_wlans() if wlan["name"] == name
        ), None)

    async def _find_wlan_group_by_name(self, name: str) -> dict:
        """Find WLAN group by name"""
        return next((
            wlang for wlang in await self.get_wlan_groups() if wlang["name"] == name
        ), None)

    async def _get_timestamp_at_controller(self) -> int:
        """Get timestamp at controller"""
        ts = self._ruckus_timestamp()
        timeinfo = await self.cmdstat(
            f"<ajax-request action='getstat' updater='system.{ts}' comp='system'>"
            f"<time/></ajax-request>"
        )
        return int(timeinfo["response"]["time"]["time"])

    async def _cmdstat_noparse(self, data: str, timeout: int | None = None) -> str:
        """Call cmdstat without parsing response"""
        return await self.session.request(self.session.cmdstat_url, data, timeout)

    async def cmdstat(
        self, data: str, collection_elements: List[str] = None, aggressive_unwrap: bool = True,
        timeout: int | None = None
    ) -> dict | List:
        """Call cmdstat and parse xml result"""
        result_text = await self._cmdstat_noparse(data, timeout)
        return self._ruckus_xml_unwrap(result_text, collection_elements, aggressive_unwrap)

    async def cmdstat_piecewise(
        self, comp: str, element_type: str, element_collection: str | None = None, filter: Dict[str, Any] | None = None, limit: int = 300, page_size: int | None = None,  updater: str | None = None, timeout: int | None = None
    ) -> AsyncIterator[dict]:
        """Call cmdstat and parse piecewise xml results"""

        ts_time = self._ruckus_timestamp(random_part=False)
        ts_random = self._ruckus_timestamp(time_part=False)
        updater = updater or comp
        page_size = page_size or limit

        piece_stat = {
              "@pid": 0,
              "@start": 0,
              "@number": page_size,
              "@requestId": f"{updater}.{ts_time}",
              "@cleanupId": f"{updater}.{ts_time}.{ts_random}"
          }

        request = {"ajax-request": {
          "@action": "getstat",
          "@comp": comp,
          "@updater": f"{updater}.{ts_time}.{ts_random}",
          element_type : self._get_event_filter(filter),
          "pieceStat" : piece_stat
        }}

        pid = 0
        item_number = 0
        element_collection = element_collection or "response"

        while True:
            pid += 1
            if page_size > limit > 0:
                page_size = limit

            piece_stat["@pid"] = pid
            piece_stat["@start"] = item_number
            piece_stat["@number"] = page_size

            request_xml = xmltodict.unparse(request, full_document=False, short_empty_elements=True)
            response = (await self.cmdstat(request_xml, [element_type], aggressive_unwrap=False))[element_collection]
            
            if element_type not in response:
                return
            for element in response[element_type]:
                yield element
                item_number += 1
                if limit == 1:
                    return
                limit -= 1
            if response["done"] == "true":
                return        

    @staticmethod
    def _get_event_filter(filter: Dict[str, Any] = None, sort_by: str = "time", sort_descending: bool = True) -> str:

        result = {
            "@sortBy": sort_by,
            "@sortDirection": -1 if sort_descending else 1
        }
        if filter is not None:
            for key, values in filter.items():
                if isinstance(values, str):
                    result[f"@{key}"] = values
                else:
                    joined_values = f"|{'|'.join(values)}|"
                    result[f"@{key}"] = joined_values
        return result

    async def _conf_noparse(self, data: str, timeout: int | None = None) -> str:
        """Call conf without parsing response"""
        return await self.session.request(self.session.conf_url, data, timeout)

    async def conf(
        self, data: str, collection_elements: List[str] = None, timeout: int | None = None
    ) -> dict | List:
        """Call conf and parse xml result"""
        result_text = await self._conf_noparse(data, timeout)
        return self._ruckus_xml_unwrap(result_text, collection_elements)

    async def _do_conf(
        self, data: str, collection_elements: List[str] = None, timeout: int | None = None
    ) -> None:
        """Call conf and confirm success"""
        result = await self.conf(data, collection_elements, timeout)
        if "xmsg" in result:
            raise ValueError(result["xmsg"]["lmsg"])

    @staticmethod
    def _ruckus_timestamp(time_part: bool = True, random_part: bool = True) -> str:
        return f"{int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000) if time_part else ''}{('.' if time_part and random_part else '')}{int(9000 * random.random()) + 1000 if random_part else ''}"

    @staticmethod
    def _normalize_mac(mac: str) -> str:
        """Normalize MAC address format"""
        if mac and match(r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", string=mac, flags=IGNORECASE):
            return mac.replace('-', ':').lower()
        raise ValueError(ERROR_INVALID_MAC)

    @staticmethod
    def _validate_passphrase(passphrase: str) -> str:
        """Validate passphrase against ZoneDirector/Unleashed rules"""
        if passphrase and match(r".*<.*>.*", string=passphrase):
            raise ValueError(ERROR_PASSPHRASE_JS)
        if passphrase and match(
            r"(^[!-~]([ -~]){6,61}[!-~]$)|(^([0-9a-fA-F]){64}$)", string=passphrase
        ):
            return passphrase
        raise ValueError(ERROR_PASSPHRASE_LEN)

    @staticmethod
    def _normalize_conf_value(current_value: str, new_value: Any) -> str:
        """Normalize new_value format to match current_value"""
        truthy_values = ("enable", "enabled", "true", "yes", "1")
        falsy_values = ("disable", "disabled", "false", "no", "0")
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
            if isinstance(new_value, str):
                new_value_lowered = new_value.lower()
                if new_value_lowered in truthy_values:
                    new_value = True
                elif new_value_lowered in falsy_values:
                    new_value = False
            elif isinstance(new_value, (int, float)) and not isinstance(new_value, bool):
                if new_value == 1:
                    new_value = True
                elif new_value == 0:
                    new_value = False

            if isinstance(new_value, bool):
                true_value, false_value = normalization_map[current_value_lowered]
                new_value = true_value if new_value else false_value
        return new_value
