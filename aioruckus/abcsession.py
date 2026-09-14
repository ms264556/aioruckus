"""Abstract session interface and configuration keys for Ruckus controllers."""
from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .ruckusconfigurationapi import RuckusConfigurationApi

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
    DPSK_LIST = "dpsk-list"
    ROLE_LIST = "role-list"
    AVPPOLICY_LIST = "avppolicy-list"
    AVPAPPLICATION_LIST = "avpapplication-list"
    AVPPORT_LIST = "avpport-list"
    PRECEDENCE_LIST = "precedence-list"
    DEVICEPOLICY_LIST = "devicepolicy-list"
    URLFILTERINGPOLICY_LIST = "urlfilteringpolicy-list"
    URLFILTERINGCATEGORY_LIST = "urlfiltering-blockcategories-list"
    POLICY_LIST = "policy-list"
    POLICY6_LIST = "policy6-list"
    SYSTEM = "system"

class AbcSession(ABC):
    """Abstract Ajax Connection to Ruckus Unleashed or ZoneDirector"""
    def __init__(
        self
    ) -> None:
        """Initialize the session with no API attached yet."""
        self._api = None
        self._redact_secrets = False

    @property
    def decrypts_secrets(self) -> bool:
        """Whether obfuscated values in responses still need decrypting.

        A live controller asked to ``DECRYPT_X`` returns secrets already in the
        clear, so they must be passed through rather than decrypted again. A
        backup file always holds the obfuscated form and does need decrypting.
        """
        return True

    @property
    def redact_secrets(self) -> bool | str:
        """How secret values are presented in parsed responses.

        Secrets arrive as a pair of sibling attributes: the prefixed value
        (``x-psk``) and the plaintext under the bare name (``psk``). This
        setting decides what the caller sees:

        * ``False`` (the default) exposes the value under the bare name only.
        * ``True`` removes both spellings, so no key appears in the result.
        * a string replaces the bare value with that placeholder, keeping the
          field so its presence is still visible without revealing it.

        To avoid receiving secrets at all, prefer asking
        :meth:`get_system_info` for only the sections you need via
        :class:`SystemStat`.
        """
        return self._redact_secrets

    @redact_secrets.setter
    def redact_secrets(self, redact: bool | str) -> None:
        self._redact_secrets = redact

    @property
    @abstractmethod
    def api(self) -> RuckusConfigurationApi:
        """Return a RuckusApi instance."""
        raise NotImplementedError()

    @abstractmethod
    async def get_conf_str(self, item: ConfigItem, timeout: int | None = None) -> str:
        """Return the relevant config xml, given a configuration key"""
        raise NotImplementedError(item)
