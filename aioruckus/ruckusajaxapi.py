"""Adds AJAX Statistics and Command methods to RuckusApi"""
from __future__ import annotations

import datetime
import xml.etree.ElementTree as ET
from typing import Any, overload
from xml.sax import saxutils

from .abcsession import ConfigItem
from .ajaxsession import AjaxSession
from .ajaxtyping import (
    Alarm,
    Ap,
    ApGroup,
    ApStats,
    Client,
    DocmdResponse,
    Dpsk,
    Event,
    L2Policy,
    Rogue,
    SystemInfo,
    TimeInfo,
    Vap,
    Wlan,
    WlanGroup,
)
from .const import (
    ERROR_ACL_NOT_FOUND,
    ERROR_ACL_SYSTEM,
    ERROR_ACL_TOO_BIG,
    ERROR_INVALID_WLAN,
    ERROR_PASSPHRASE_MISSING,
    ERROR_PASSPHRASE_NAME,
    ERROR_SAEPASSPHRASE_MISSING,
    PatchNewAttributeMode,
    StatsLevel,
    SystemStat,
    WlanEncryption,
)
from .ruckusconfigurationapi import RuckusConfigurationApi
from .unleashedsession import UnleashedSession
from .unleashedtojson import parse_ajax_response
from .utility import *


def _coerce_stats_level(stats_level: StatsLevel | bool) -> StatsLevel:
    """Map a legacy boolean ``interval_stats`` flag onto a StatsLevel."""
    if isinstance(stats_level, bool):
        return StatsLevel.L3 if stats_level else StatsLevel.L1
    return stats_level


class RuckusAjaxApi(RuckusConfigurationApi):
    """Ruckus ZoneDirector or Unleashed Configuration, Statistics and Commands API"""
    session: AjaxSession
    __session: UnleashedSession | None = None

    def __init__(self, session: AjaxSession):
        """Initialize the API with the given AjaxSession."""
        super().__init__(session)

    async def login(self) -> RuckusAjaxApi:
        """Create an Unleashed/ZoneDirector HTTPS session and log in."""
        self.__session = await UnleashedSession(
            self.session.host,
            self.session.username,
            self.session.password,
            self.session.websession,
        ).login()
        return self

    async def close(self) -> None:
        """Close the underlying HTTPS session."""
        if self.__session:
            await self.__session.close()

    async def _get_conf_str(self, item: ConfigItem, timeout: int | None = None) -> str:
        """Return the relevant config xml, given a configuration key"""
        assert self.__session is not None
        return await self.__session.get_conf_str(item, timeout)

    async def get_system_info(self, *sections: SystemStat) -> dict:
        """Return system information, optionally limited to the given sections.

        Args:
            sections: SystemStat sections to fetch; defaults to all sections.
        """
        section_keys: list[str]
        if sections:
            section_keys = [s for section_list in sections for s in section_list.value]
        else:
            section_keys = SystemStat.DEFAULT.value
            
        section = ''.join(f"<{s}/>" for s in section_keys)
        sysinfo = await self.cmdstat(
            f"<ajax-request action='getstat' comp='system'>{section}</ajax-request>",
            target_type=SystemInfo,
        )
        return sysinfo

    @overload
    async def get_active_clients(self, stats_level: StatsLevel = StatsLevel.L1) -> list[Client]: ...

    @overload
    async def get_active_clients(self, interval_stats: bool) -> list[Client]: ...

    async def get_active_clients(
        self, stats_level: StatsLevel | bool = StatsLevel.L1
    ) -> list[Client]:
        """Return a list of active clients

        Args:
            stats_level: Level 1 (basic), Level 2 (extended), or Level 3
                (interval stats). A boolean is accepted for backwards
                compatibility: True requests interval stats (L3), False
                requests basic stats (L1).
        """
        return await self._get_entity_stats("client", _coerce_stats_level(stats_level), list[Client])

    async def get_inactive_clients(self) -> list[Client]:
        """Return a list of inactive clients"""
        return await self.cmdstat("<ajax-request action='getstat' comp='stamgr' enable-gzip='0'><clientlist period='0' /></ajax-request>", target_type=list[Client])

    @overload
    async def get_ap_stats(self, stats_level: StatsLevel = StatsLevel.L1) -> list[ApStats]: ...

    @overload
    async def get_ap_stats(self, interval_stats: bool) -> list[ApStats]: ...

    async def get_ap_stats(self, stats_level: StatsLevel | bool = StatsLevel.L1) -> list[ApStats]:
        """Return a list of AP statistics

        Args:
            stats_level: Level 1 (basic), Level 2 (extended), or Level 3
                (interval stats). A boolean is accepted for backwards
                compatibility: True requests interval stats (L3), False
                requests basic stats (L1).
        """
        return await self._get_entity_stats("ap", _coerce_stats_level(stats_level), list[ApStats])

    async def get_ap_group_stats(self) -> list[ApGroup]:
        """Return a list of AP group statistics"""
        return await self.cmdstat(
            "<ajax-request action='getstat' comp='stamgr' enable-gzip='0'>"
            "<apgroup /></ajax-request>", target_type=list[ApGroup]
        )

    async def get_vap_stats(self) -> list[Vap]:
        """Return a list of Virtual AP (per-radio WLAN) statistics"""
        return await self.cmdstat(
            "<ajax-request action='getstat' comp='stamgr' enable-gzip='0' caller='SCI'>"
            "<vap INTERVAL-STATS='no' LEVEL='1' /></ajax-request>", target_type=list[Vap]
        )

    async def get_wlan_group_stats(self) -> list[WlanGroup]:
        """Return a list of WLAN group statistics"""
        return await self.cmdstat(
            "<ajax-request action='getstat' comp='stamgr' enable-gzip='0' caller='SCI'>"
            "<wlangroup /></ajax-request>", target_type=list[WlanGroup]
        )

    async def get_dpsk_stats(self) -> list[Dpsk]:
        """Return a list of DPSK statistics"""
        return await self.cmdstat(
            "<ajax-request action='getstat' comp='stamgr' enable-gzip='0'>"
            "<dpsklist /></ajax-request>", target_type=list[Dpsk]
        )

    async def get_active_rogues(self) -> list[Rogue]:
        """Return a list of currently active rogue devices"""
        return await self.cmdstat(
            "<ajax-request action='getstat' comp='stamgr' enable-gzip='0'>"
            "<rogue LEVEL='1' recognized='!true'/></ajax-request>", target_type=list[Rogue]
        )

    async def get_known_rogues(self, limit: int = 300) -> list[Rogue]:
        """Return a list of known/recognized rogues devices"""
        return await self.cmdstat_piecewise("stamgr", "rogue", "apstamgr-stat", filters={"LEVEL": "1", "recognized": "true"}, updater="krogue", limit=limit, target_type=list[Rogue])

    async def get_blocked_rogues(self, limit: int = 300) -> list[Rogue]:
        """Return a list of user blocked rogues devices"""
        return await self.cmdstat_piecewise("stamgr", "rogue", "apstamgr-stat", filters={"LEVEL": "1", "blocked": "true"}, updater="brogue", limit=limit, target_type=list[Rogue])

    async def get_alarms(self, limit: int = 300, filters: dict | None = None) -> list[Alarm]:
        """Return a list of alarms"""
        return await self.cmdstat_piecewise("eventd", "alarm", updater="page", filters=filters, limit=limit, target_type=list[Alarm])

    async def get_events(self, limit: int = 300, filters: dict | None = None)-> list[Event]:
        """Return a list of events"""
        return await self.cmdstat_piecewise("eventd", "xevent", filters=filters, limit=limit, target_type=list[Event])

    async def get_wlan_events(self, *wlan_ids, limit: int = 300) -> list[Event]:
        """Return a list of WLAN events"""
        return await self.get_events(limit, {"wlan": list(wlan_ids) if wlan_ids else "*"})

    async def get_ap_events(self, *ap_macs, limit: int = 300) -> list[Event]:
        """Return a list of AP events"""
        return await self.get_events(limit, {"ap": list(normalize_mac_lower(mac) for mac in ap_macs) if ap_macs else "*"})

    async def get_client_events(self, limit: int = 300) -> list[Event]:
        """Return a list of client events"""
        return await self.get_events(limit, {"c": "user"})

    async def get_wired_client_events(self, limit: int = 300) -> list[Event]:
        """Return a list of wired client events"""
        return await self.get_events(limit, {"c": "wire"})

    async def get_syslog(self) -> str:
        """Return the syslog as a single string"""
        ts = ruckus_timestamp()
        syslog = await self.cmdstat(
            f"<ajax-request action='docmd' xcmd='get-syslog' updater='system.{ts}' comp='system'>"
            f"<xcmd cmd='get-syslog' type='sys'/></ajax-request>",
            target_type=DocmdResponse,
        )
        return syslog["xmsg"]["res"]

    async def get_backup(self) -> bytes:
        """Return the controller backup as raw bytes"""
        assert self.__session is not None and self.__session.base_url is not None
        backup_timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%m%d%y_%H_%M")
        request = (self.__session.base_url / "_savebackup.jsp").with_query({"time": backup_timestamp})
        return await self.__session._request_file(request, timeout=60)

    async def do_block_client(self, mac: str) -> None:
        """Block a client"""
        mac = normalize_mac_lower(mac)
        result = await self.cmdstat(
            f"<ajax-request action='docmd' xcmd='block' checkAbility='10' comp='stamgr'>"
            f"<xcmd check-ability='10' tag='client' acl-id='1' client='{mac}' cmd='block'>"
            f"<client client='{mac}' acl-id='1' hostname=''></client></xcmd></ajax-request>",
            target_type=DocmdResponse,
        )
        if "xmsg" in result and result["xmsg"].get("type") == "-1":
            await self.cmdstat(
                f"<ajax-request action='docmd' xcmd='block-client' comp='stamgr'>"
                f"<xcmd cmd='block-client'><client mac='{mac}'></client></xcmd>"
                f"</ajax-request>",
                target_type=DocmdResponse,
            )

    async def do_unblock_client(self, mac: str) -> None:
        """Unblock a client"""
        mac = normalize_mac_lower(mac)
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

        acl = ET.Element("acl", {
            "id": acl["id"],
            "name": acl["name"],
            "description": acl["description"],
            "default-mode": acl["default-mode"]
        })
        for mac in macs:
            ET.SubElement(acl, acl_tag, {"mac": mac})

        await self._do_conf(
            f"<ajax-request action='updobj' comp='acl-list' updater='acl-list'>"
            f"{ET.tostring(acl).decode('utf-8')}</ajax-request>"
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
        self,
        name: str,
        passphrase: str,
        sae_passphrase: str | None = None
    ) -> None:
        """Set a WLAN password"""
        sae_passphrase = sae_passphrase or passphrase
        await self.do_edit_wlan(
            name, {"wpa": {"passphrase": passphrase, "sae-passphrase": sae_passphrase}}, PatchNewAttributeMode.ADD
        )

    async def do_add_wlan(
        self,
        name: str,
        encryption: WlanEncryption = WlanEncryption.WPA2,
        passphrase: str | None = None,
        sae_passphrase: str | None = None,
        ssid_override: str | None = None,
        ignore_unknown_attributes: bool = False
    ) -> None:
        """Add a WLAN"""
        patch: dict[str, Any] = {"name": name, "ssid": ssid_override or name, "encryption": encryption.value}
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
            self._patch_template(wlansvc, {"name": new_name, "ssid": new_ssid or new_name})
        await self._add_wlan_template(wlansvc)

    async def do_edit_wlan(
        self, name: str, patch: dict, patch_new_attributes: PatchNewAttributeMode = PatchNewAttributeMode.ERROR
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
            f"<wlansvc id='{wlan['id']}'/></ajax-request>", timeout=20
        )
        return True

    async def do_add_wlan_group(self, name: str, description: str = "", wlans: list | None = None) -> None:
        """Add a WLAN group"""
        wlangroup = ET.Element("wlangroup", {"name": name, "description": description or ""})
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
            f"{ET.tostring(wlangroup).decode('utf-8')}</ajax-request>"
        )

    async def do_clone_wlan_group(self, template: dict, name: str, description: str | None = None) -> None:
        """Clone a WLAN group"""
        wlangroup = ET.Element("wlangroup", {
            "name": name,
            "description": description or template.get("description", "")
        })
        if "wlan" in template:
            wlan_map = {wlan["name"]: wlan["id"] for wlan in await self.get_wlans()}
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

    async def _get_default_apgroup_template(self) -> ET.Element:
        """Get default AP group template"""
        assert self.__session is not None
        xml = await self.__session.get_conf_str(ConfigItem.APGROUP_TEMPLATE)
        root = ET.fromstring(xml)
        apgroup = root.find(".//apgroup")
        if apgroup is None:
            raise ValueError("Could not find apgroup in template")
        return apgroup

    async def _get_default_wlan_template(self) -> ET.Element:
        """Get default WLAN template"""
        assert self.__session is not None
        xml = await self.__session.get_conf_str(ConfigItem.WLANSVC_STANDARD_TEMPLATE)
        root = ET.fromstring(xml)
        wlansvc = root.find(".//wlansvc")
        if wlansvc is not None:
            return wlansvc
        return self._get_default_cli_wlan_template()

    @staticmethod
    def _get_default_cli_wlan_template() -> ET.Element:
        """Default WLAN for when (very old) ZDs don't provide one via AJAX"""
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
        """Return the WLAN template element with the given name, or None."""
        assert self.__session is not None
        xml = await self.__session.get_conf_str(ConfigItem.WLANSVC_LIST)
        root = ET.fromstring(xml)
        wlansvc = root.find(f".//wlansvc[@name='{saxutils.escape(name)}']")
        return wlansvc

    def _normalize_encryption(self, wlansvc: ET.Element, patch: dict):
        """Apply encryption and passphrase changes from the patch to the template.

        Validates passphrases, updates the `encryption` attribute and rebuilds
        the `wpa` child element to match the requested encryption mode.
        """
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

            if new_encryption in (WlanEncryption.WPA2.value, WlanEncryption.WPA23_MIXED.value):
                passphrase = wpa.get("passphrase") if wpa is not None else None
                if not (patch_wpa and patch_wpa.get("passphrase")) and passphrase is None:
                    raise ValueError(ERROR_PASSPHRASE_MISSING)
                new_wpa["passphrase"] = passphrase or "<passphrase>"
            if new_encryption in (WlanEncryption.WPA3.value, WlanEncryption.WPA23_MIXED.value):
                sae_passphrase = wpa.get("sae_passphrase") if wpa is not None else None
                if not (patch_wpa and patch_wpa.get("sae_passphrase")) and sae_passphrase is None:
                    raise ValueError(ERROR_SAEPASSPHRASE_MISSING)
                new_wpa["sae-passphrase"] = sae_passphrase or "<passphrase>"

            if wpa is not None:
                wlansvc.remove(wpa)
            if new_encryption != WlanEncryption.NONE.value:
                ET.SubElement(wlansvc, "wpa", new_wpa)

    def _patch_template(
        self,
        element: ET.Element,
        patch: dict,
        patch_new_attributes: PatchNewAttributeMode = PatchNewAttributeMode.ERROR,
        current_path: str = ""
    ) -> None:
        """Apply a patch dict to an XML element, recursing into child elements.

        Args:
            element: the XML element to patch in place.
            patch: mapping of attribute name to new value; dict values patch
                child elements recursively.
            patch_new_attributes: how to handle attributes not present on the
                element (ERROR, IGNORE or ADD).
            current_path: path prefix used in error messages.
        """
        visited_children = set()
        for child in element:
            if child.tag in patch and isinstance(patch[child.tag], dict):
                self._patch_template(
                    child,
                    patch[child.tag],
                    patch_new_attributes,
                    f"{current_path}/{child.tag}"
                )
                visited_children.add(child.tag)
        for name, value in patch.items():
            if name in visited_children:
                continue

            if isinstance(value, list):
                raise ValueError(f"Applying lists is unsupported: {current_path}/{name}")

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

    async def _find_ap_by_mac(self, mac: str) -> Ap | None:
        """Find AP by MAC"""
        return next((ap for ap in await self.get_aps() if ap["mac"] == mac), None)

    async def _find_ap_group_by_name(self, name: str) -> ApGroup | None:
        """Find AP group by name"""
        return next((
            ap_group for ap_group in await self.get_ap_groups() if ap_group["name"] == name
        ), None)

    async def _find_wlan_by_name(self, name: str) -> Wlan | None:
        """Find WLAN by name"""
        return next((
            wlan for wlan in await self.get_wlans() if wlan["name"] == name
        ), None)

    async def _find_wlan_group_by_name(self, name: str) -> WlanGroup | None:
        """Find WLAN group by name"""
        return next((
            wlang for wlang in await self.get_wlan_groups() if wlang["name"] == name
        ), None)

    async def _find_acl_by_name(self, name: str) -> L2Policy | None:
        """Find L2 ACL by name"""
        return next((
            acl for acl in await self.get_acls() if acl["name"] == name
        ), None)

    async def _get_timestamp_at_controller(self) -> int:
        """Get timestamp at controller"""
        ts = ruckus_timestamp()
        time_info = await self.cmdstat(
            f"<ajax-request action='getstat' updater='system.{ts}' comp='system'>"
            f"<time/></ajax-request>",
            target_type=TimeInfo,
        )
        return int(time_info["time"]["time"])

    async def _get_entity_stats(
        self,
        entity_name: str,
        stats_level: StatsLevel,
        target_type: type,
    ) -> Any:
        """Fetch entity statistics at the requested detail level.

        Level 3 requests 24 hours of interval statistics instead of a single
        LEVEL snapshot.
        """
        if stats_level == StatsLevel.L3:
            endtime = await self._get_timestamp_at_controller()
            starttime = endtime - 86400
            entityrequest = (
                f"<{entity_name} INTERVAL-STATS='yes' "
                f"INTERVAL-START='{starttime}' INTERVAL-STOP='{endtime}' />"
            )
        else:
            entityrequest = f"<{entity_name} LEVEL='{stats_level.value}' />"
        return await self.cmdstat(
            f"<ajax-request action='getstat' comp='stamgr' enable-gzip='0'>"
            f"{entityrequest}</ajax-request>",
            target_type=target_type,
        )

    async def _cmdstat_noparse(self, data: str, timeout: int | None = None) -> str:
        """Call cmdstat without parsing response"""
        assert self.__session is not None
        return await self.__session._ajax_request("_cmdstat.jsp", data, timeout=timeout)

    async def cmdstat(
        self, data: str, timeout: int | None = None, target_type: type | None = None
    ) -> Any:
        """Call cmdstat and parse xml result.

        The response is parsed via :func:`parse_ajax_response`; pass a
        TypedDict (or ``dict`` / ``list``) as ``target_type`` to describe
        the desired structure.
        """
        result_text = await self._cmdstat_noparse(data, timeout)
        return parse_ajax_response(result_text, target_type)

    async def cmdstat_piecewise(
        self,
        comp: str,
        element_type: str,
        element_collection: str | None = None,
        filters: dict[str, Any] | None = None,
        limit: int = 300,
        page_size: int | None = None,
        updater: str | None = None,
        target_type: type | None = None,
        timeout: int | None = None,
    ) -> list[Any]:
        """Call cmdstat and collect piecewise xml results via the session"""
        assert self.__session is not None
        return await self.__session.cmdstat_piecewise(
            comp,
            element_type,
            element_collection=element_collection,
            filters=filters,
            limit=limit,
            page_size=page_size,
            updater=updater,
            target_type=target_type,
            timeout=timeout,
        )

    async def _conf_noparse(self, data: str, timeout: int | None = None) -> str:
        """Call conf without parsing response"""
        assert self.__session is not None
        return await self.__session._ajax_request("_conf.jsp", data, timeout=timeout)

    async def conf(
        self, data: str, timeout: int | None = None, target_type: type | None = None
    ) -> Any:
        """Call conf and parse xml result.

        The response is parsed via :func:`parse_ajax_response`; pass a
        TypedDict (or ``dict`` / ``list``) as ``target_type`` to describe
        the desired structure.
        """
        result_text = await self._conf_noparse(data, timeout)
        return parse_ajax_response(result_text, target_type)

    async def _do_conf(
        self, data: str, timeout: int | None = None
    ) -> None:
        """Call conf and confirm success"""
        result = await self.conf(data, timeout=timeout, target_type=DocmdResponse)
        if "xmsg" in result:
            raise ValueError(result["xmsg"]["lmsg"])
