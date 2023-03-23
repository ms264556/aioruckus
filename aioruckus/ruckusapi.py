from re import IGNORECASE, match
from typing import List
from warnings import warn
import xml.etree.ElementTree as ET
import xml.sax.saxutils as saxutils

import xmltodict

from .const import (
    VALUE_ERROR_INVALID_MAC,
    VALUE_ERROR_INVALID_PASSPHRASE_LEN,
    VALUE_ERROR_INVALID_PASSPHRASE_JS
)
from .const import SystemStat as SystemStat
from .ajaxsession import AjaxSession


class RuckusApi:

    def __init__(self, auth: AjaxSession):
        self.auth = auth

    async def get_mesh_info(self) -> dict:
        meshinfo = await self.conf("<ajax-request action='getconf' comp='mesh-list' DECRYPT_X='true'/>")
        return meshinfo["mesh-list"]["mesh"]

    async def get_zerotouch_mesh_ap_serials(self) -> dict:
        return await self.conf("<ajax-request action='getconf' updater='ztmeshSerial-list.0.5' comp='ztmeshSerial-list'/>", ["ztmeshSerial"])

    async def get_blocked_client_macs(self) -> List:
        blockedinfo = await self.conf("<ajax-request action='getconf' comp='acl-list' updater='page.0.5' />", ["accept", "deny", "acl"])
        denylist = blockedinfo[0]["deny"] if "deny" in blockedinfo[0] else None
        return [] if not denylist else [d for d in denylist if d]

    async def get_system_info(self, *sections: SystemStat) -> dict:
        section = ''.join(s.value for s in sections) if sections else SystemStat.DEFAULT.value
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

    async def get_aps(self) -> List:
        return await self.cmdstat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><ap LEVEL='1' /></ajax-request>", ["ap"])

    async def get_ap_groups(self) -> List:
        return await self.cmdstat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><apgroup /></ajax-request>", ["group", "radio", "ap"])

    async def get_vaps(self) -> List:
        return await self.cmdstat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0' caller='SCI'><vap INTERVAL-STATS='no' LEVEL='1' /></ajax-request>", ["vap"])

    async def get_wlans(self) -> List:
        return await self.conf("<ajax-request action='getconf' DECRYPT_X='true' updater='wlansvc-list.0.5' comp='wlansvc-list'/>", ["wlansvc"])

    async def get_wlan_groups(self) -> List:
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
        await self._conf_noparse(f"<ajax-request action='updobj' comp='acl-list' updater='blocked-clients'><acl id='1' name='System' description='System' default-mode='allow' EDITABLE='false'>{remaining}</acl></ajax-request>")

    async def do_disable_wlan(self, ssid: str, disable_wlan: bool = True) -> None:
        wlan = await self._find_wlan_by_ssid(ssid)
        if wlan:
            await self._conf_noparse(f"<ajax-request action='updobj' updater='wlansvc-list.0.5' comp='wlansvc-list'><wlansvc id='{wlan['id']}' enable-type='{1 if disable_wlan else 0}' IS_PARTIAL='true'/></ajax-request>")

    async def do_enable_wlan(self, ssid: str) -> None:
        await self.do_disable_wlan(ssid, False)

    async def do_set_wlan_password(self, ssid: str, password: str, sae_password: str = None) -> None:
        # IS_PARTIAL prepopulates all subelements, so that any wpa element we provide would result in 2 wpa elements.
        # So we have to do what the web UI does: grab the wlan definition, make our changes, then post the entire thing back.
        password = self._validate_passphrase(password)
        sae_password = self._validate_passphrase(sae_password or password)
        xml = await self._conf_noparse("<ajax-request action='getconf' DECRYPT_X='true' updater='wlansvc-list.0.5' comp='wlansvc-list'/>")
        root = ET.fromstring(xml)
        wlansvc = root.find(".//wlansvc[@ssid='%s']" % saxutils.escape(ssid))
        if wlansvc:
            wpa = wlansvc.find("wpa")
            if wpa.get("passphrase") is not None:
                wpa.set("passphrase", password)
                wpa.set("x-passphrase", password)
            if wpa.get("sae-passphrase") is not None:
                wpa.set("sae-passphrase", sae_password)
                wpa.set("x-sae-passphrase", sae_password)
            xml_bytes = ET.tostring(wlansvc)
            await self.conf(f"<ajax-request action='updobj' updater='wlan' comp='wlansvc-list'>{xml_bytes.decode('utf-8')}</ajax-request>")

    async def do_hide_ap_leds(self, mac: str, leds_off: bool = True) -> None:
        mac = self._normalize_mac(mac)
        ap = await self._find_ap_by_mac(mac)
        if ap:
            await self._conf_noparse(f"<ajax-request action='updobj' updater='ap-list.0.5' comp='ap-list'><ap id='{ap['id']}' IS_PARTIAL='true' led-off='{str(leds_off).lower()}' /></ajax-request>")

    async def do_show_ap_leds(self, mac: str) -> None:
        await self.do_hide_ap_leds(mac, False)

    async def do_restart_ap(self, mac: str) -> None:
        mac = self._normalize_mac(mac)
        return await self._cmdstat_noparse(f"<ajax-request action='docmd' xcmd='reset' checkAbility='2' updater='stamgr.0.5' comp='stamgr'><xcmd cmd='reset' ap='{mac}' tag='ap' checkAbility='2'/></ajax-request>")

    async def _find_ap_by_mac(self, mac: str) -> dict:
        return next((ap for ap in await self.get_aps() if ap["mac"] == mac), None)

    async def _find_wlan_by_ssid(self, ssid: str) -> dict:
        return next((wlan for wlan in await self.get_wlans() if wlan["ssid"] == ssid), None)
    
    async def _get_timestamp_at_controller(self) -> int:
        timeinfo = await self.cmdstat("<ajax-request action='getstat' updater='system.0.5' comp='system'><time/></ajax-request>")
        return int(timeinfo["response"]["time"]["time"])

    async def cmdstat(self, data: str, collection_elements: List[str] = None) -> dict | List:
        result_text = await self._cmdstat_noparse(data)
        return self._ajaxunwrap(result_text, collection_elements)

    async def _cmdstat_noparse(self, data: str) -> str:
        return await self.auth.request(self.auth.cmdstat_url, data)

    async def conf(self, data: str, collection_elements: List[str] = None) -> dict | List:
        result_text = await self._conf_noparse(data)
        return self._ajaxunwrap(result_text, collection_elements)

    async def _conf_noparse(self, data: str) -> str:
        return await self.auth.request(self.auth.conf_url, data)

    @staticmethod
    def _ajaxunwrap(xml: str, collection_elements: List[str] = None) -> dict | List:
        # convert xml and unwrap collection
        force_list = None if not collection_elements else {ce: True for ce in collection_elements}
        result = xmltodict.parse(xml, encoding="utf-8", attr_prefix='', postprocessor=RuckusApi._process_ruckus_ajax_xml, force_list=force_list)
        collection_list = [] if not collection_elements else [f"{ce}-list" for ce in collection_elements] + collection_elements
        for key in ["ajax-response", "response", "apstamgr-stat"] + collection_list:
            if result and key and key in result:
                result = result[key]
        return result or []

    @staticmethod
    def _process_ruckus_ajax_xml(path, key, value):
        if key.startswith("x-"):  # passphrases are obfuscated and stored with an x- prefix; decrypt these
            return key[2:], ''.join(chr(ord(letter) - 1) for letter in value) if value else value
        elif key == "apstamgr-stat" and not value:  # return an empty array rather than None, for ease of use
            return key, []
        elif key == "status" and value and value.isnumeric() and path and len(path) > 0 and path[-1][0] == "client":  # client status is numeric code for active, and name for inactive. Show name for everything
            description = "Authorized" if value == "1" else "Authenticating" if value == "2" else "PSK Expired" if value == "3" else "Authorized(Deny)" if value == "4" else "Authorized(Permit)" if value == "5" else "Unauthorized"
            return key, description
        else:
            return key, value

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
