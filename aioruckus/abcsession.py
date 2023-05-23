from abc import ABC, abstractmethod
from enum import Enum

class ConfigItem(Enum):
    WLANSVC_LIST = "wlansvc-list"
    WLANGROUP_LIST = "wlangroup-list"
    AP_LIST = "ap-list"
    APGROUP_LIST = "apgroup-list"
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
    def api(self):
        """Return a RuckusApi instance."""
        if not self._api:
            # pylint: disable=import-outside-toplevel
            from .ruckusapi import RuckusApi
            self._api = RuckusApi(self)
        return self._api

    @abstractmethod
    async def get_conf_str(self, item: ConfigItem, timeout: int | None = None) -> str:
        raise NotImplementedError(item)