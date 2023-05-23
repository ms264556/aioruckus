from re import IGNORECASE, match
from typing import Any, List
import xml.etree.ElementTree as ET
import xml.sax.saxutils as saxutils

from .abcsession import ConfigItem

from .const import (
    VALUE_ERROR_INVALID_MAC,
    VALUE_ERROR_INVALID_PASSPHRASE_LEN,
    VALUE_ERROR_INVALID_PASSPHRASE_JS,
    VALUE_ERROR_INVALID_PASSPHRASE_MISSING,
    VALUE_ERROR_INVALID_SAEPASSPHRASE_MISSING,
    VALUE_ERROR_INVALID_WLAN,
    VALUE_ERROR_WLAN_SSID_SETTING_REQUIRES_NAME
)
from .const import SystemStat as SystemStat
from .const import WlanEncryption as WlanEncryption
from .ajaxsession import AjaxSession
from .ruckusapi import RuckusApi

class RuckusAjaxApi(RuckusApi):

    def __init__(self, session: AjaxSession):
        self.session = session

    async def get_system_info(self, *sections: SystemStat) -> dict:
        sections = [s for section_list in sections for s in section_list.value] if sections else SystemStat.DEFAULT.value
        section = ''.join(f"<{s}/>" for s in sections)
        sysinfo = await self.cmdstat(f"<ajax-request action='getstat' comp='system'>{section}</ajax-request>")
        return sysinfo["response"] if "response" in sysinfo else sysinfo["system"]

    async def get_active_clients(self, interval_stats: bool = False) -> List:
        if interval_stats:
            endtime = await self._get_timestamp_at_controller()
            starttime = endtime - 86400
            clientrequest = f"<client INTERVAL-STATS='yes' INTERVAL-START='{starttime}' INTERVAL-STOP='{endtime}' />"
        else:
            clientrequest = "<client LEVEL='1' />"
        return await self.cmdstat(f"<ajax-request action='getstat' comp='stamgr' enable-gzip='0'>{clientrequest}</ajax-request>", ["client"])

    async def get_inactive_clients(self) -> List:
        return await self.cmdstat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><clientlist period='0' /></ajax-request>", ["client"])

    async def get_ap_stats(self) -> List:
        return await self.cmdstat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><ap LEVEL='1' /></ajax-request>", ["ap"])

    async def get_ap_group_stats(self) -> List:
        return await self.cmdstat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><apgroup /></ajax-request>", ["group", "radio", "ap"])

    async def get_vap_stats(self) -> List:
        return await self.cmdstat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0' caller='SCI'><vap INTERVAL-STATS='no' LEVEL='1' /></ajax-request>", ["vap"])

    async def get_wlan_group_stats(self) -> List:
        return await self.cmdstat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0' caller='SCI'><wlangroup /></ajax-request>", ["wlangroup", "wlan"])

    async def get_syslog(self) -> str:
        syslog = await self.cmdstat("<ajax-request action='docmd' xcmd='get-syslog' updater='system.0.5' comp='system'><xcmd cmd='get-syslog' type='sys'/></ajax-request>")
        return syslog["xmsg"]["res"]

    async def do_block_client(self, mac: str) -> None:
        mac = self._normalize_mac(mac)
        await self.cmdstat(f"<ajax-request action='docmd' xcmd='block' checkAbility='10' comp='stamgr'><xcmd check-ability='10' tag='client' acl-id='1' client='{mac}' cmd='block'><client client='{mac}' acl-id='1' hostname=''></client></xcmd></ajax-request>")

    async def do_unblock_client(self, mac: str) -> None:
        mac = self._normalize_mac(mac)
        blocked = await self.get_blocked_client_macs()
        remaining = ''.join((f"<deny mac='{deny['mac']}' type='single'/>" for deny in blocked if deny["mac"] != mac))
        await self._do_conf(f"<ajax-request action='updobj' comp='acl-list' updater='blocked-clients'><acl id='1' name='System' description='System' default-mode='allow' EDITABLE='false'>{remaining}</acl></ajax-request>")

    async def do_disable_wlan(self, name: str, disable_wlan: bool = True) -> None:
        wlan = await self._find_wlan_by_name(name)
        if wlan:
            await self._do_conf(f"<ajax-request action='updobj' updater='wlansvc-list.0.5' comp='wlansvc-list'><wlansvc id='{wlan['id']}' name='{wlan['name']}' enable-type='{1 if disable_wlan else 0}' IS_PARTIAL='true'/></ajax-request>")

    async def do_enable_wlan(self, name: str) -> None:
        await self.do_disable_wlan(name, False)

    async def do_set_wlan_password(self, name: str, passphrase: str, sae_passphrase: str = None) -> None:
        sae_passphrase = sae_passphrase or passphrase
        await self.do_edit_wlan(name, {"wpa": {"passphrase": passphrase, "sae-passphrase": sae_passphrase}}, True)

    async def do_add_wlan(self, name: str, encryption: WlanEncryption = WlanEncryption.WPA2, passphrase: str = None, sae_passphrase: str = None, ssid_override: str = None, ignore_unknown_attributes: bool = False) -> None:
        patch = {"name": name, "ssid": ssid_override or name, "encryption": encryption.value}
        if passphrase is not None or sae_passphrase is not None:
            patch_wpa = {}
            patch["wpa"] = patch_wpa
            if passphrase is not None:
                patch_wpa["passphrase"] = passphrase
            if sae_passphrase is not None:
                patch_wpa["sae-passphrase"] = sae_passphrase
        await self.do_clone_wlan(patch)

    async def do_clone_wlan(self, template: dict, new_name: str = None, new_ssid: str = None) -> None:
        wlansvc = await self._get_default_wlan_template()
        self._normalize_encryption(wlansvc, template)
        self._patch_template(wlansvc, template, True)
        if new_name is not None or new_ssid is not None:
            if new_name is None:
                raise ValueError(VALUE_ERROR_WLAN_SSID_SETTING_REQUIRES_NAME)
            self._patch_template(wlansvc, {"name": new_name, "ssid": new_ssid or new_name })
        await self._add_wlan_template(wlansvc)

    async def do_edit_wlan(self, name: str, patch: dict, ignore_unknown_attributes: bool = False) -> None:
        wlansvc = await self._get_wlan_template(name)
        if wlansvc:
            self._normalize_encryption(wlansvc, patch)
            self._patch_template(wlansvc, patch, ignore_unknown_attributes)
            await self._update_wlan_template(wlansvc)

    async def do_delete_wlan(self, name: str) -> bool:
        wlan = await self._find_wlan_by_name(name)
        if wlan is None:
            return False
        else:
            await self._do_conf(f"<ajax-request action='delobj' updater='wlansvc-list.0.5' comp='wlansvc-list'><wlansvc id='{wlan['id']}'/></ajax-request>", timeout=20)
            return True

    async def do_add_wlan_group(self, name: str, description: str = "", wlans: List = None) -> None:
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
                    raise ValueError(VALUE_ERROR_INVALID_WLAN)
                ET.SubElement(wlangroup, "wlansvc", {"id": wlan_map[wlan_name]})
        await self._do_conf(f"<ajax-request action='addobj' comp='wlangroup-list' updater='wgroup'>{ET.tostring(wlangroup).decode('utf-8')}</ajax-request>")

    async def do_clone_wlan_group(self, template: dict, name: str, description: str = None) -> None:
        wlangroup = ET.Element("wlangroup", {"name": name, "description": description or (template["description"] if "description" in template else "")})
        if "wlan" in template:
            wlan_map = {wlan["name"]:wlan["id"] for wlan in await self.get_wlans()}
            for wlansvc in template["wlan"]:
                ET.SubElement(wlangroup, "wlansvc", {"id": wlan_map[wlansvc["name"]]})
        await self._do_conf(f"<ajax-request action='addobj' comp='wlangroup-list' updater='wgroup'>{ET.tostring(wlangroup).decode('utf-8')}</ajax-request>")

    async def do_delete_wlan_group(self, name: str) -> bool:
        wlang = await self._find_wlan_group_by_name(name)
        if wlang is None:
            return False
        else:
            await self._do_conf(f"<ajax-request action='delobj' updater='wlangroup-list.0.5' comp='wlangroup-list'><wlangroup id='{wlang['id']}'/></ajax-request>")
            return True

    async def do_hide_ap_leds(self, mac: str, leds_off: bool = True) -> None:
        mac = self._normalize_mac(mac)
        ap = await self._find_ap_by_mac(mac)
        if ap:
            await self._do_conf(f"<ajax-request action='updobj' updater='ap-list.0.5' comp='ap-list'><ap id='{ap['id']}' IS_PARTIAL='true' led-off='{str(leds_off).lower()}' /></ajax-request>")

    async def do_show_ap_leds(self, mac: str) -> None:
        await self.do_hide_ap_leds(mac, False)

    async def do_restart_ap(self, mac: str) -> None:
        mac = self._normalize_mac(mac)
        return await self._cmdstat_noparse(f"<ajax-request action='docmd' xcmd='reset' checkAbility='2' updater='stamgr.0.5' comp='stamgr'><xcmd cmd='reset' ap='{mac}' tag='ap' checkAbility='2'/></ajax-request>")

    async def _get_default_wlan_template(self) -> ET.Element:
        xml = await self._conf_noparse("<ajax-request action='getconf' DECRYPT_X='true' updater='wlansvc-standard-template.0.5' comp='wlansvc-standard-template'/>")
        root = ET.fromstring(xml)
        wlansvc = root.find(".//wlansvc")
        if wlansvc is not None:
            return wlansvc
        else:
            return self._get_default_cli_wlan_template()

    @staticmethod
    def _get_default_cli_wlan_template() -> ET.Element:
        wlansvc = ET.Element("wlansvc", {"name": "default-standard-wlan", "ssid": "", "authentication": "open", "encryption": "none",
                                         "is-guest": "false", "max-clients-per-radio": "100", "do-802-11d": "disabled", "sta-info-extraction": "1",
                                         "force-dhcp": "0", "force-dhcp-timeout": "10", "usage": "user", "policy-id": "", "policy6-id": "",
                                         "precedence-id": "1", "devicepolicy-id": "", "role-based-access-ctrl": "false", "acl-id": "1", "local-bridge": "1",
                                         "client-isolation": "disabled", "ci-whitelist-id": "0", "bgscan": "1", "idle-timeout": "1", "max-idle-timeout": "300",
                                         "dis-dgaf": "0", "authstats": "0", "https-redirection": "disabled"})
        ET.SubElement(wlansvc, "qos", {"uplink-preset": "DISABLE", "downlink-preset": "DISABLE"})
        ET.SubElement(wlansvc, "queue-priority", {"voice": "0", "video": "2", "data": "4", "background": "6"})
        ET.SubElement(wlansvc, "wlan-schedule", {"value": "0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0: 0x0:0x0:0x0:0x0:0x0:0x0"})
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

            if new_encryption == WlanEncryption.WPA2.value or new_encryption == WlanEncryption.WPA23_MIXED.value:
                passphrase = wpa.get("passphrase") if wpa is not None else None
                if (patch_wpa is None or "passphrase" not in patch_wpa) and passphrase is None:
                    raise ValueError(VALUE_ERROR_INVALID_PASSPHRASE_MISSING)
                new_wpa["passphrase"] = passphrase or "<passphrase>"
            if new_encryption == WlanEncryption.WPA3.value or new_encryption == WlanEncryption.WPA23_MIXED.value:
                sae_passphrase = wpa.get("sae-passphrase") if wpa is not None else None
                if (patch_wpa is None or "sae-passphrase" not in patch_wpa) and sae_passphrase is None:
                    raise ValueError(VALUE_ERROR_INVALID_SAEPASSPHRASE_MISSING)
                new_wpa["sae-passphrase"] = sae_passphrase or "<passphrase>"

            if wpa is not None:
                wlansvc.remove(wpa)
            if new_encryption != WlanEncryption.NONE.value:
                wpa = ET.SubElement(wlansvc, "wpa", new_wpa)

    def _patch_template(self, element: ET.Element, patch: dict, ignore_unknown_attributes: bool = False, current_path: str = ""):
        visited_children = set()
        for child in element:
            if child.tag in patch and isinstance(patch[child.tag], dict):
                self._patch_template(child, patch[child.tag], ignore_unknown_attributes, f"{current_path}/{child.tag}")
                visited_children.add(child.tag)
        for name, value in patch.items():
            if name in visited_children:
                pass
            else:
                current_value = element.get(name)
                if isinstance(value, List):
                    raise ValueError(f"Applying lists is unsupported: {current_path}/{name}")
                elif current_value is None:
                    if not ignore_unknown_attributes:
                        raise ValueError(f"Unknown attribute: {current_path}/{name}")
                else:
                    new_value = self._normalize_conf_value(current_value, value)
                    element.set(name, new_value)
                    x_name = f"x-{name}"
                    if x_name not in patch and x_name in element.attrib:
                        element.set(x_name, new_value)

    async def _update_wlan_template(self, wlansvc: ET.Element):
        xml_bytes = ET.tostring(wlansvc)
        await self._do_conf(f"<ajax-request action='updobj' updater='wlan' comp='wlansvc-list'>{xml_bytes.decode('utf-8')}</ajax-request>", timeout=20)

    async def _add_wlan_template(self, wlansvc: ET.Element):
        xml_bytes = ET.tostring(wlansvc)
        await self._do_conf(f"<ajax-request action='addobj' updater='wlansvc-list' comp='wlansvc-list'>{xml_bytes.decode('utf-8')}</ajax-request>", timeout=20)

    async def _find_ap_by_mac(self, mac: str) -> dict:
        return next((ap for ap in await self.get_aps() if ap["mac"] == mac), None)

    async def _find_wlan_by_name(self, name: str) -> dict:
        return next((wlan for wlan in await self.get_wlans() if wlan["name"] == name), None)

    async def _find_wlan_group_by_name(self, name: str) -> dict:
        return next((wlang for wlang in await self.get_wlan_groups() if wlang["name"] == name), None)

    async def _get_timestamp_at_controller(self) -> int:
        timeinfo = await self.cmdstat("<ajax-request action='getstat' updater='system.0.5' comp='system'><time/></ajax-request>")
        return int(timeinfo["response"]["time"]["time"])

    async def _cmdstat_noparse(self, data: str, timeout: int | None = None) -> str:
        return await self.session.request(self.session.cmdstat_url, data, timeout)

    async def cmdstat(self, data: str, collection_elements: List[str] = None, timeout: int | None = None) -> dict | List:
        result_text = await self._cmdstat_noparse(data, timeout)
        return self._ruckus_xml_unwrap(result_text, collection_elements)

    async def _conf_noparse(self, data: str, timeout: int | None = None) -> str:
        return await self.session.request(self.session.conf_url, data, timeout)

    async def conf(self, data: str, collection_elements: List[str] = None, timeout: int | None = None) -> dict | List:
        result_text = await self._conf_noparse(data, timeout)
        return self._ruckus_xml_unwrap(result_text, collection_elements)

    async def _do_conf(self, data: str, collection_elements: List[str] = None, timeout: int | None = None) -> None:
        result = await self.conf(data, collection_elements, timeout)
        if "xmsg" in result:
            raise ValueError(result["xmsg"]["lmsg"])

    @staticmethod
    def _normalize_mac(mac: str) -> str:
        if mac and match(r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", string=mac, flags=IGNORECASE):
            return mac.replace('-', ':').lower()
        raise ValueError(VALUE_ERROR_INVALID_MAC)

    @staticmethod
    def _validate_passphrase(passphrase: str) -> str:
        if passphrase and match(r".*<.*>.*", string=passphrase):
            raise ValueError(VALUE_ERROR_INVALID_PASSPHRASE_JS)
        if passphrase and match(r"(^[!-~]([ -~]){6,61}[!-~]$)|(^([0-9a-fA-F]){64}$)", string=passphrase):
            return passphrase
        raise ValueError(VALUE_ERROR_INVALID_PASSPHRASE_LEN)

    @staticmethod
    def _normalize_conf_value(current_value: str, new_value: Any) -> str:
        current_value_lowered = current_value.lower()
        if current_value_lowered in ("enable", "disable", "enabled", "disabled", "true", "false", "yes", "no", "1", "0"):
            if isinstance(new_value, str):
                new_value_lowered = new_value.lower()
                new_value = True if new_value_lowered in ("enable", "enabled", "true", "yes", "1") else False if new_value_lowered in ("disable", "disabled", "false", "no", "0") else new_value
            elif isinstance(new_value, (int, float)) and not isinstance(new_value, bool):
                new_value = True if new_value == 1 else False if new_value == 0 else new_value

            if isinstance(new_value, bool):
                if current_value_lowered in ("enable", "disable"):
                    new_value = "ENABLE" if new_value else "DISABLE"
                elif current_value_lowered in ("enabled", "disabled"):
                    new_value = "enabled" if new_value else "disabled"
                elif current_value_lowered in ("yes", "no"):
                    new_value = "yes" if new_value else "no"
                elif current_value_lowered in ("true", "false"):
                    new_value = "true" if new_value else "false"
                elif current_value_lowered in ("1", "0"):
                    new_value = "1" if new_value else "0"
        return new_value
