"""Ruckus Session"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .ruckusapi import RuckusApi

class ConfigItem(Enum):
    """Ruckus configuration keys"""
    WLANSVC_LIST = "wlansvc-list"
    WLANSVC_STANDARD_TEMPLATE = "wlansvc-standard-template"
    WLANGROUP_LIST = "wlangroup-list"
    AP_LIST = "ap-list"
    APGROUP_LIST = "apgroup-list"
    APGROUP_TEMPLATE = "apgroup-template"
    MESH_LIST = "mesh-list"
    ZTMESHSERIAL_LIST = "ztmeshSerial-list"
    ACL_LIST = "acl-list"
    SYSTEM = "system"

class AbcSession(ABC):
    """Abstract Ajax Connection to Ruckus Unleashed or ZoneDirector"""
    def __init__(
        self
    ) -> None:
        self._api = None

    @property
    def api(self) -> "RuckusApi":
        """Return a RuckusApi instance."""
        if not self._api:
            # pylint: disable=import-outside-toplevel
            from .ruckusapi import RuckusApi
            self._api = RuckusApi(self)
        return self._api

    @abstractmethod
    async def get_conf_str(self, item: ConfigItem, timeout: int | None = None) -> str:
        """Return the relevant config xml, given a configuration key"""
        raise NotImplementedError(item)
