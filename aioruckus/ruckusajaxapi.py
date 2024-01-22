"""Adds AJAX Statistics and Command methods to RuckusApi"""

from abc import abstractmethod
from re import IGNORECASE, match
from typing import List

from .const import (
    ERROR_INVALID_MAC,
    ERROR_PASSPHRASE_LEN,
    ERROR_PASSPHRASE_JS,
    SystemStat
)
from .ruckusapi import RuckusApi

class RuckusAjaxApi(RuckusApi):
    """Ruckus Configuration, Statistics and Commands API"""
    
    @abstractmethod
    async def get_system_info(self, *sections: SystemStat) -> dict:
        pass

    @abstractmethod
    async def get_active_clients(self, interval_stats: bool = False) -> List:
        """Return a list of active clients"""
        pass

    @abstractmethod
    async def get_inactive_clients(self) -> List:
        """Return a list of inactive clients"""
        pass

    @abstractmethod
    async def get_ap_stats(self) -> List:
        """Return a list of AP statistics"""
        pass

    @abstractmethod
    async def get_ap_group_stats(self) -> List:
        """Return a list of AP group statistics"""
        pass

    @abstractmethod
    async def get_vap_stats(self) -> List:
        """Return a list of Virtual AP (per-radio WLAN) statistics"""
        pass

    @abstractmethod
    async def get_wlan_group_stats(self) -> List:
        """Return a list of WLAN group statistics"""
        pass

    @abstractmethod
    async def get_dpsk_stats(self) -> List:
        """Return a list of AP group statistics"""
        pass

    @abstractmethod
    async def get_active_rogues(self) -> list[dict]:
        """Return a list of currently active rogue devices"""
        pass

    @abstractmethod
    async def get_known_rogues(self, limit: int = 300) -> list[dict]:
        """Return a list of known/recognized rogues devices"""
        pass

    @abstractmethod
    async def get_blocked_rogues(self, limit: int = 300) -> list[dict]:
        """Return a list of user blocked rogues devices"""
        pass

    @abstractmethod
    async def get_all_alarms(self, limit: int = 300) -> list[dict]:
        """Return a list of all alerts"""
        pass

    @abstractmethod
    async def get_all_events(self, limit: int = 300) -> list[dict]:
        """Return a list of all events"""
        pass

    @abstractmethod
    async def get_wlan_events(self, *wlan_ids, limit: int = 300) -> list[dict]:
        """Return a list of WLAN events"""
        pass

    @abstractmethod
    async def get_ap_events(self, *ap_macs, limit: int = 300) -> list[dict]:
        """Return a list of AP events"""
        pass

    @abstractmethod
    async def get_client_events(self, limit: int = 300) -> list[dict]:
        """Return a list of client events"""
        pass

    @abstractmethod
    async def get_wired_client_events(self, limit: int = 300) -> list[dict]:
        """Return a list of wired client events"""
        pass

    @abstractmethod
    async def get_syslog(self) -> str:
        """Return a list of syslog entries"""
        pass

    @abstractmethod
    async def get_backup(self) -> bytes:
        """Return a backup"""
        pass

    @abstractmethod
    async def do_block_client(self, mac: str) -> None:
        """Block a client"""
        pass

    @abstractmethod
    async def do_unblock_client(self, mac: str) -> None:
        """Unblock a client"""
        pass

    @abstractmethod
    async def do_delete_ap_group(self, name: str) -> bool:
        """Delete an AP group"""
        pass

    @abstractmethod
    async def do_disable_wlan(self, name: str, disable_wlan: bool = True) -> None:
        """Disable a WLAN"""
        pass

    @abstractmethod
    async def do_enable_wlan(self, name: str) -> None:
        """Enable a WLAN"""
        pass

    @abstractmethod
    async def do_set_wlan_password(
        self,
        name: str,
        passphrase: str,
        sae_passphrase: str = None
    ) -> None:
        pass

    @abstractmethod
    async def do_hide_ap_leds(self, mac: str, leds_off: bool = True) -> None:
        """Hide AP LEDs"""
        pass

    @abstractmethod
    async def do_show_ap_leds(self, mac: str) -> None:
        """Show AP LEDs"""
        pass

    @abstractmethod
    async def do_restart_ap(self, mac: str) -> None:
        """Restart AP"""
        pass

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
    