"""Adds AJAX Statistics and Command methods to RuckusApi"""

from __future__ import annotations
from collections.abc import AsyncIterator
import datetime
import sys
import xml.etree.ElementTree as ET
from xml.sax import saxutils
import xmltodict

from .unleashedtojson import parse_ajax_response

from .ajaxtyping import (
    Alarm,
    Ap,
    ApGroup,
    Dpsk,
    Event,
    L2Policy,
    Wlan,
    WlanGroup,
    Vap,
)
from .ajax_typing import ap, client, Level1, Level2, Level3


from .const import (
    ERROR_ACL_NOT_FOUND,
    ERROR_ACL_SYSTEM,
    ERROR_ACL_TOO_BIG,
    ERROR_PASSPHRASE_MISSING,
    ERROR_SAEPASSPHRASE_MISSING,
    ERROR_INVALID_WLAN,
    ERROR_PASSPHRASE_NAME,
    PatchNewAttributeMode,
    SystemStat,
    WlanEncryption,
)
from .abcsession import ConfigItem, StatComp
from .ajaxsession import AjaxSession
from .ruckusconfigurationapi import RuckusConfigurationApi
from .unleashedsession import UnleashedSession
from .utility import *

from .ajax_typing import ap, client, Level1, Level2, Level3

if sys.version_info >= (3, 11):
    from typing import overload, Any, Literal, TypeVar, Type
else:
    from typing_extensions import overload, Any, Literal, TypeVar, Type

D = TypeVar("D")


class RuckusAjaxApi(RuckusConfigurationApi):
    """Ruckus ZoneDirector or Unleashed Configuration, Statistics and Commands API"""

    session: AjaxSession
    __session: UnleashedSession

    def __init__(self, session: AjaxSession):
        super().__init__(session)

    async def login(self) -> RuckusAjaxApi:
        self.__session = await UnleashedSession(
            self.session.host,
            self.session.username,
            self.session.password,
            self.session.websession,
        ).login()
        return self

    async def close(self) -> None:
        await self.__session.close()

    async def get_system_info(self, *sections: SystemStat) -> dict:
        if sections:
            section_keys = [s for section_list in sections for s in section_list.value]
        else:
            section_keys = SystemStat.DEFAULT.value

        section = "".join(f"<{s}/>" for s in section_keys)
        sysinfo = await self.cmdstat(
            f"<ajax-request action='getstat' comp='system'>{section}</ajax-request>"
        )
        return sysinfo.get("response", sysinfo.get("system"))

    async def get_active_clients(self, stats_level: Type[client.ClientLevelT] = Level1) -> list[ClientLevelT]:
        """Return a list of active clients"""
        return await self._get_entity_stats(
            "client", (ClientL1, ClientL2, ClientL3), stats_level
        )

    async def get_inactive_clients(self) -> list[ClientL1]:
        """Return a list of inactive clients"""
        return await self._getstat(list[ClientL1], "<clientlist period='0' />")

    async def get_ap_stats(self, stats_level: Type[ap.ApLevelT] = ap.ApL1) -> list[ApLevelT]:
        """Return a list of AP statistics"""
        return await self._get_entity_stats("ap", stats_level)

    async def get_ap_group_stats(self) -> list[ApGroup]:
        """Return a list of AP group statistics"""
        return await self.cmdstat(
            "<ajax-request action='getstat' comp='stamgr' enable-gzip='0'>"
            "<apgroup /></ajax-request>",
            ["group", "radio", "ap"],
        )

    async def get_vap_stats(self) -> list[Vap]:
        """Return a list of Virtual AP (per-radio WLAN) statistics"""
        return await self.cmdstat(
            "<ajax-request action='getstat' comp='stamgr' enable-gzip='0' caller='SCI'>"
            "<vap INTERVAL-STATS='no' LEVEL='1' /></ajax-request>",
            ["vap"],
        )

    async def get_wlan_group_stats(self) -> list[WlanGroup]:
        """Return a list of WLAN group statistics"""
        return await self.cmdstat(
            "<ajax-request action='getstat' comp='stamgr' enable-gzip='0' caller='SCI'>"
            "<wlangroup /></ajax-request>",
            ["wlangroup", "wlan"],
        )

    async def get_dpsk_stats(self) -> list[Dpsk]:
        """Return a list of AP group statistics"""
        return await self.cmdstat(
            "<ajax-request action='getstat' comp='stamgr' enable-gzip='0'>"
            "<dpsklist /></ajax-request>",
            ["dpsk"],
        )

    async def get_active_rogues(self) -> list[Rogue]:
        """Return a list of currently active rogue devices"""
        return await self.cmdstat(
            "<ajax-request action='getstat' comp='stamgr' enable-gzip='0'>"
            "<rogue LEVEL='1' recognized='!true'/></ajax-request>",
            ["rogue"],
        )

    async def get_known_rogues(self, limit: int = 300) -> list[Rogue]:
        """Return a list of known/recognized rogues devices"""
        return [
            rogue
            async for rogue in self.cmdstat_piecewise(
                "stamgr",
                "rogue",
                "apstamgr-stat",
                filters={"LEVEL": "1", "recognized": "true"},
                updater="krogue",
                limit=limit,
            )
        ]

    async def get_blocked_rogues(self, limit: int = 300) -> list[Rogue]:
        """Return a list of user blocked rogues devices"""
        return [
            rogue
            async for rogue in self.cmdstat_piecewise(
                "stamgr",
                "rogue",
                "apstamgr-stat",
                filters={"LEVEL": "1", "blocked": "true"},
                updater="brogue",
                limit=limit,
            )
        ]

    async def get_alarms(
        self, limit: int = 300, filters: dict | None = None
    ) -> list[Alarm]:
        """Return a list of alerts"""
        return [
            alarm
            async for alarm in self.cmdstat_piecewise(
                "eventd", "alarm", updater="page", filters=filters, limit=limit
            )
        ]

    async def get_events(
        self, limit: int = 300, filters: dict | None = None
    ) -> list[Event]:
        """Return a list of events"""
        return [
            xevent
            async for xevent in self.cmdstat_piecewise(
                "eventd", "xevent", filters=filters, limit=limit
            )
        ]

    async def get_wlan_events(self, *wlan_ids, limit: int = 300) -> list[Event]:
        """Return a list of WLAN events"""
        return await self.get_events(
            limit, {"wlan": list(wlan_ids) if wlan_ids else "*"}
        )

    async def get_ap_events(self, *ap_macs, limit: int = 300) -> list[Event]:
        """Return a list of AP events"""
        return await self.get_events(
            limit,
            {
                "ap": (
                    list(normalize_mac_lower(mac) for mac in ap_macs)
                    if ap_macs
                    else "*"
                )
            },
        )

    async def get_client_events(self, limit: int = 300) -> list[Event]:
        """Return a list of client events"""
        return await self.get_events(limit, {"c": "user"})

    async def get_wired_client_events(self, limit: int = 300) -> list[Event]:
        """Return a list of wired client events"""
        return await self.get_events(limit, {"c": "wire"})

    async def get_syslog(self) -> str:
        """Return a list of syslog entries"""
        ts = ruckus_timestamp()
        syslog = await self.cmdstat(
            f"<ajax-request action='docmd' xcmd='get-syslog' updater='system.{ts}' comp='system'>"
            f"<xcmd cmd='get-syslog' type='sys'/></ajax-request>"
        )
        return syslog["xmsg"]["res"]

    async def get_backup(self) -> bytes:
        """Return a backup"""
        assert self.session.base_url is not None
        backup_timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%m%d%y_%H_%M"
        )
        request = (self.session.base_url / "_savebackup.jsp").with_query(
            {"time": backup_timestamp}
        )
        return await self.session.request_file(request, 60)

    async def do_block_client(self, mac: str) -> None:
        """Block a client"""
        mac = normalize_mac_lower(mac)
        result = await self.cmdstat(
            f"<ajax-request action='docmd' xcmd='block' checkAbility='10' comp='stamgr'>"
            f"<xcmd check-ability='10' tag='client' acl-id='1' client='{mac}' cmd='block'>"
            f"<client client='{mac}' acl-id='1' hostname=''></client></xcmd></ajax-request>"
        )
        if "xmsg" in result and result["xmsg"].get("type") == "-1":
            await self.cmdstat(
                f"<ajax-request action='docmd' xcmd='block-client' comp='stamgr'>"
                f"<xcmd cmd='block-client'><client mac='{mac}'></client></xcmd>"
                f"</ajax-request>"
            )

    async def do_unblock_client(self, mac: str) -> None:
        """Unblock a client"""
        mac = normalize_mac_lower(mac)
        blocked = await self.get_blocked_client_macs()
        remaining = "".join(
            (
                f"<deny mac='{deny['mac']}' type='single'/>"
                for deny in blocked
                if deny["mac"] != mac
            )
        )
        await self._do_conf(
            f"<ajax-request action='updobj' comp='acl-list' updater='blocked-clients'>"
            f"<acl id='1' name='System' description='System' default-mode='allow' EDITABLE='false'>"
            f"{remaining}</acl></ajax-request>"
        )

    async def do_set_acl_members(self, name: str, macs: list[str]) -> None:
        """Set ACL members"""
        acl = await self._find_acl_by_name(name)
        if acl is None:
            raise ValueError(ERROR_ACL_NOT_FOUND)
        if acl["id"] == 1:
            raise ValueError(ERROR_ACL_SYSTEM)
        if len(macs) > 128:
            raise ValueError(ERROR_ACL_TOO_BIG)

        macs = [normalize_mac_lower(mac) for mac in macs]
        acl_tag = "deny" if acl["default-mode"] == "allow" else "accept"

        acl = ET.Element(
            "acl",
            {
                "id": acl["id"],
                "name": acl["name"],
                "description": acl["description"],
                "default-mode": acl["default-mode"],
            },
        )
        for mac in macs:
            ET.SubElement(acl, acl_tag, {"mac": mac})

        await self._do_conf(
            f"<ajax-request action='updobj' comp='acl-list' updater='acl-list'>"
            f"{ET.tostring(acl, encoding='unicode')}</ajax-request>"
        )

    async def do_delete_ap_group(self, name: str) -> bool:
        """Delete an AP group"""
        ap_group = await self._find_ap_group_by_name(name)
        if ap_group is None:
            return False
        ts = ruckus_timestamp()
        await self._do_conf(
            f"<ajax-request action='delobj' updater='apgroup-list.{ts}' comp='apgroup-list'>"
            f"<apgroup id='{ap_group['id']}'/></ajax-request>"
        )
        return True

    async def do_disable_wlan(self, name: str, disable_wlan: bool = True) -> None:
        """Disable a WLAN"""
        wlan = await self._find_wlan_by_name(name)
        if wlan:
            ts = ruckus_timestamp()
            await self._do_conf(
                f"<ajax-request action='updobj' updater='wlansvc-list.{ts}' comp='wlansvc-list'>"
                f"<wlansvc id='{wlan['id']}' name='{wlan['name']}' "
                f"enable-type='{1 if disable_wlan else 0}' IS_PARTIAL='true'/></ajax-request>"
            )

    async def do_enable_wlan(self, name: str) -> None:
        """Enable a WLAN"""
        await self.do_disable_wlan(name, False)

    async def do_set_wlan_password(
        self, name: str, passphrase: str, sae_passphrase: str | None = None
    ) -> None:
        """Set a WLAN password"""
        sae_passphrase = sae_passphrase or passphrase
        await self.do_edit_wlan(
            name,
            {"wpa": {"passphrase": passphrase, "sae-passphrase": sae_passphrase}},
            PatchNewAttributeMode.ADD,
        )

    async def do_add_wlan(
        self,
        name: str,
        encryption: WlanEncryption = WlanEncryption.WPA2,
        passphrase: str | None = None,
        sae_passphrase: str | None = None,
        ssid_override: str | None = None,
        ignore_unknown_attributes: bool = False,
    ) -> None:
        """Add a WLAN"""
        patch: dict[str, Any] = {
            "name": name,
            "ssid": ssid_override or name,
            "encryption": encryption.value,
        }
        if passphrase is not None or sae_passphrase is not None:
            patch_wpa: dict[str, str] = {}
            patch["wpa"] = patch_wpa
            if passphrase is not None:
                patch_wpa["passphrase"] = passphrase
            if sae_passphrase is not None:
                patch_wpa["sae-passphrase"] = sae_passphrase
        await self.do_clone_wlan(patch)

    async def do_clone_wlan(
        self, template: dict, new_name: str | None = None, new_ssid: str | None = None
    ) -> None:
        """Clone a WLAN"""
        wlansvc = await self._get_default_wlan_template()
        self._normalize_encryption(wlansvc, template)
        self._patch_template(wlansvc, template, PatchNewAttributeMode.ADD)
        if new_name is not None or new_ssid is not None:
            if new_name is None:
                raise ValueError(ERROR_PASSPHRASE_NAME)
            self._patch_template(
                wlansvc, {"name": new_name, "ssid": new_ssid or new_name}
            )
        await self._add_wlan_template(wlansvc)

    async def do_edit_wlan(
        self,
        name: str,
        patch: dict,
        patch_new_attributes: PatchNewAttributeMode = PatchNewAttributeMode.ERROR,
    ) -> None:
        """Edit a WLAN"""
        wlansvc = await self._get_wlan_template(name)
        if wlansvc:
            self._normalize_encryption(wlansvc, patch)
            self._patch_template(wlansvc, patch, patch_new_attributes)
            await self._update_wlan_template(wlansvc)

    async def do_delete_wlan(self, name: str) -> bool:
        """Delete a WLAN"""
        wlan = await self._find_wlan_by_name(name)
        if wlan is None:
            return False
        ts = ruckus_timestamp()
        await self._do_conf(
            f"<ajax-request action='delobj' updater='wlansvc-list.{ts}' comp='wlansvc-list'>"
            f"<wlansvc id='{wlan['id']}'/></ajax-request>",
            timeout=20,
        )
        return True

    async def do_add_wlan_group(
        self, name: str, description: str = "", wlans: list | None = None
    ) -> None:
        """Add a WLAN group"""
        wlangroup = ET.Element(
            "wlangroup", {"name": name, "description": description or ""}
        )
        if wlans is not None:
            wlan_map = {wlan["name"]: wlan["id"] for wlan in await self.get_wlans()}
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
            f"{ET.tostring(wlangroup, encoding='unicode')}</ajax-request>"
        )

    async def do_clone_wlan_group(
        self, template: dict, name: str, description: str | None = None
    ) -> None:
        """Clone a WLAN group"""
        wlangroup = ET.Element(
            "wlangroup",
            {
                "name": name,
                "description": description or template.get("description", ""),
            },
        )
        if "wlan" in template:
            wlan_map = {wlan["name"]: wlan["id"] for wlan in await self.get_wlans()}
            for wlansvc in template["wlan"]:
                ET.SubElement(wlangroup, "wlansvc", {"id": wlan_map[wlansvc["name"]]})
        await self._do_conf(
            f"<ajax-request action='addobj' comp='wlangroup-list' updater='wgroup'>"
            f"{ET.tostring(wlangroup, encoding='unicode')}</ajax-request>"
        )

    async def do_delete_wlan_group(self, name: str) -> bool:
        """Delete a WLAN group"""
        wlang = await self._find_wlan_group_by_name(name)
        if wlang is None:
            return False
        ts = ruckus_timestamp()
        await self._do_conf(
            f"<ajax-request action='delobj' updater='wlangroup-list.{ts}' comp='wlangroup-list'>"
            f"<wlangroup id='{wlang['id']}'/></ajax-request>"
        )
        return True

    async def do_hide_ap_leds(self, mac: str, leds_off: bool = True) -> None:
        """Hide AP LEDs"""
        mac = normalize_mac_lower(mac)
        found_ap = await self._find_ap_by_mac(mac)
        if found_ap:
            ts = ruckus_timestamp()
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
        mac = normalize_mac_lower(mac)
        ts = ruckus_timestamp()
        await self._cmdstat_noparse(
            f"<ajax-request action='docmd' xcmd='reset' checkAbility='2' updater='stamgr.{ts}' "
            f"comp='stamgr'><xcmd cmd='reset' ap='{mac}' tag='ap' checkAbility='2'/></ajax-request>"
        )

    async def _get_entity_stats(
        self,
        entity_name: str,
        types: tuple[type[D], type[D], type[D]],
        level: StatsLevel,
    ) -> Any:
        if level == StatsLevel.L3:
            interval_end = await self._get_timestamp_at_controller()
            interval_start = interval_end - 86400
            payload = (
                f"<{entity_name} INTERVAL-STATS='yes' "
                f"INTERVAL-START='{interval_start}' INTERVAL-STOP='{interval_end}' />"
            )
        else:
            payload = f"<{entity_name} LEVEL='{level.value}' />"
        return await self._getstat(list[types[level.value - 1]], payload)

    async def _get_default_apgroup_template(self) -> ET.Element:
        """Get default AP group template"""
        xml = await self.session.get_conf_str(ConfigItem.APGROUP_TEMPLATE)
        root = ET.fromstring(xml)
        apgroup = root.find(".//apgroup")
        if apgroup is None:
            raise ValueError("Could not find apgroup in template")
        return apgroup

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
        """Default WLAN for when (very old) ZDs don't provide one via AJAX"""
        wlansvc = ET.Element(
            "wlansvc",
            {
                "name": "default-standard-wlan",
                "ssid": "",
                "authentication": "open",
                "encryption": "none",
                "is-guest": "false",
                "max-clients-per-radio": "100",
                "do-802-11d": "disabled",
                "sta-info-extraction": "1",
                "force-dhcp": "0",
                "force-dhcp-timeout": "10",
                "usage": "user",
                "policy-id": "",
                "policy6-id": "",
                "precedence-id": "1",
                "devicepolicy-id": "",
                "role-based-access-ctrl": "false",
                "acl-id": "1",
                "local-bridge": "1",
                "client-isolation": "disabled",
                "ci-whitelist-id": "0",
                "bgscan": "1",
                "idle-timeout": "1",
                "max-idle-timeout": "300",
                "dis-dgaf": "0",
                "authstats": "0",
                "https-redirection": "disabled",
            },
        )
        ET.SubElement(
            wlansvc, "qos", {"uplink-preset": "DISABLE", "downlink-preset": "DISABLE"}
        )
        ET.SubElement(
            wlansvc,
            "queue-priority",
            {"voice": "0", "video": "2", "data": "4", "background": "6"},
        )
        ET.SubElement(
            wlansvc,
            "wlan-schedule",
            {
                "value": "0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:"
                "0x0:0x0:0x0:0x0: 0x0:0x0:0x0:0x0:0x0:0x0"
            },
        )
        return wlansvc

    async def _get_wlan_template(self, name: str) -> ET.Element | None:
        xml = await self.session.get_conf_str(ConfigItem.WLANSVC_LIST)
        root = ET.fromstring(xml)
        wlansvc = root.find(f".//wlansvc[@name='{saxutils.escape(name)}']")
        return wlansvc

    def _normalize_encryption(self, wlansvc: ET.Element, patch: dict):
        patch_wpa = patch.get("wpa")
        if patch_wpa is not None:
            if "passphrase" in patch_wpa:
                validate_passphrase(patch_wpa["passphrase"])
            if "sae-passphrase" in patch_wpa:
                validate_passphrase(patch_wpa["sae-passphrase"])

        encryption = wlansvc.get("encryption")
        if "encryption" in patch and patch["encryption"] != encryption:
            new_encryption = patch["encryption"]
            wlansvc.set("encryption", new_encryption)

            wpa = wlansvc.find("wpa")
            new_wpa = {"cipher": "aes", "dynamic-psk": "disabled"}

            if new_encryption in (WlanEncryption.WPA2, WlanEncryption.WPA23_MIXED):
                passphrase = wpa.get("passphrase") if wpa is not None else None
                if (
                    not (patch_wpa and patch_wpa.get("passphrase"))
                    and passphrase is None
                ):
                    raise ValueError(ERROR_PASSPHRASE_MISSING)
                new_wpa["passphrase"] = passphrase or "<passphrase>"
            if new_encryption in (WlanEncryption.WPA3, WlanEncryption.WPA23_MIXED):
                sae_passphrase = wpa.get("sae_passphrase") if wpa is not None else None
                if (
                    not (patch_wpa and patch_wpa.get("sae_passphrase"))
                    and sae_passphrase is None
                ):
                    raise ValueError(ERROR_SAEPASSPHRASE_MISSING)
                new_wpa["sae-passphrase"] = sae_passphrase or "<passphrase>"

            if wpa is not None:
                wlansvc.remove(wpa)
            if new_encryption != WlanEncryption.NONE:
                ET.SubElement(wlansvc, "wpa", new_wpa)

    def _patch_template(
        self,
        element: ET.Element,
        patch: dict,
        patch_new_attributes: PatchNewAttributeMode = PatchNewAttributeMode.ERROR,
        current_path: str = "",
    ) -> None:
        visited_children = set()
        for child in element:
            if child.tag in patch and isinstance(patch[child.tag], dict):
                self._patch_template(
                    child,
                    patch[child.tag],
                    patch_new_attributes,
                    f"{current_path}/{child.tag}",
                )
                visited_children.add(child.tag)
        for name, value in patch.items():
            if name in visited_children:
                continue

            if isinstance(value, list):
                raise ValueError(
                    f"Applying lists is unsupported: {current_path}/{name}"
                )

            current_value = element.get(name)
            if current_value is None:
                if patch_new_attributes == PatchNewAttributeMode.ERROR:
                    raise ValueError(f"Unknown attribute: {current_path}/{name}")
                if patch_new_attributes == PatchNewAttributeMode.IGNORE:
                    continue
            else:
                value = self._normalize_conf_value(current_value, value)
            element.set(name, str(value))
            x_name = f"x-{name}"
            if x_name not in patch and x_name in element.attrib:
                element.set(x_name, str(value))

    async def _update_wlan_template(self, wlansvc: ET.Element):
        """Update WLAN template"""
        await self._do_conf(
            f"<ajax-request action='updobj' updater='wlan' comp='wlansvc-list'>"
            f"{ET.tostring(wlansvc, encoding='unicode')}</ajax-request>",
            timeout=20,
        )

    async def _add_wlan_template(self, wlansvc: ET.Element):
        """Add WLAN template"""
        await self._do_conf(
            f"<ajax-request action='addobj' updater='wlansvc-list' comp='wlansvc-list'>"
            f"{ET.tostring(wlansvc, encoding='unicode')}</ajax-request>",
            timeout=20,
        )

    async def _find_ap_by_mac(self, mac: str) -> Ap | None:
        """Find AP by MAC"""
        return next((ap for ap in await self.get_aps() if ap["mac"] == mac), None)

    async def _find_ap_group_by_name(self, name: str) -> ApGroup | None:
        """Find AP group by name"""
        return next(
            (
                ap_group
                for ap_group in await self.get_ap_groups()
                if ap_group["name"] == name
            ),
            None,
        )

    async def _find_wlan_by_name(self, name: str) -> Wlan | None:
        """Find WLAN by name"""
        return next(
            (wlan for wlan in await self.get_wlans() if wlan["name"] == name), None
        )

    async def _find_wlan_group_by_name(self, name: str) -> WlanGroup | None:
        """Find WLAN group by name"""
        return next(
            (wlang for wlang in await self.get_wlan_groups() if wlang["name"] == name),
            None,
        )

    async def _find_acl_by_name(self, name: str) -> L2Policy | None:
        """Find L2 ACL by name"""
        return next((acl for acl in await self.get_acls() if acl["name"] == name), None)

    async def _get_timestamp_at_controller(self) -> int:
        """Get timestamp at controller"""
        time_info = await self._getstat(dict, "<time/>", comp="system")
        return int(time_info["time"]["time"])

    async def _getstat(
        self,
        target_type: type[D],
        stat: str | ET.Element | None = None,
        *,
        comp: str | StatComp = StatComp.STAMGR,
        timeout: int | None = None,
    ) -> D:
        return await self.__session.getstat(
            target_type, stat, comp=comp, timeout=timeout
        )

    async def _getconf(
        self,
        comp: str | ConfigItem,
        *,
        timeout: int | None = None,
    ) -> str:
        return await self.__session.getconf(comp, timeout=timeout)

    async def _cmdstat_noparse(self, data: str, timeout: int | None = None) -> str:
        """Call cmdstat without parsing response"""
        assert self.__session is not None
        return await self.__session._ajax_request("_cmdstat.jsp", data, timeout=timeout)

    async def cmdstat(self, data: str, timeout: int | None = None) -> Any:
        """Call cmdstat and parse xml result"""
        result_text = await self._cmdstat_noparse(data, timeout)
        return parse_ajax_response(result_text)

    async def cmdstat_piecewise(
        self,
        comp: str,
        element_type: str,
        element_collection: str | None = None,
        filters: dict[str, Any] | None = None,
        limit: int = 300,
        page_size: int | None = None,
        updater: str | None = None,
        timeout: int | None = None,
    ) -> AsyncIterator[Any]:
        """Call cmdstat and parse piecewise xml results"""

        ts_time = ruckus_timestamp(random_part=False)
        ts_random = ruckus_timestamp(time_part=False)
        updater = updater or comp
        page_size = page_size or limit

        piece_stat = {
            "@pid": 0,
            "@start": 0,
            "@number": page_size,
            "@requestId": f"{updater}.{ts_time}",
            "@cleanupId": f"{updater}.{ts_time}.{ts_random}",
        }

        request = {
            "ajax-request": {
                "@action": "getstat",
                "@comp": comp,
                "@updater": f"{updater}.{ts_time}.{ts_random}",
                element_type: self._get_filter_object(filters),
                "pieceStat": piece_stat,
            }
        }

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

            request_xml = xmltodict.unparse(
                request, full_document=False, short_empty_elements=True
            )
            response = (
                await self.cmdstat(request_xml, [element_type], aggressive_unwrap=False)
            )[element_collection]

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
    def _get_filter_object(
        filters: dict[str, Any] | None = None,
        sort_by: str = "time",
        sort_descending: bool = True,
    ) -> dict:

        result = {"@sortBy": sort_by, "@sortDirection": -1 if sort_descending else 1}
        if filters is not None:
            for key, values in filters.items():
                if isinstance(values, str):
                    result[f"@{key}"] = values
                else:
                    joined_values = f"|{'|'.join(values)}|"
                    result[f"@{key}"] = joined_values
        return result

    async def conf(self, data: str, *, timeout: int | None = None) -> Any:
        """Call conf and parse xml result"""
        return await self.__session.getconf(list, data, timeout=timeout)

    async def _do_conf(self, data: str, timeout: int | None = None) -> None:
        """Call conf and confirm success"""
        result = await self.conf(data, timeout=timeout)
        if "xmsg" in result:
            raise ValueError(result["xmsg"]["lmsg"])

    async def _get_conf(self, item: ConfigItem) -> Any:
        return await self.__session.conf_getconf(list, item)
