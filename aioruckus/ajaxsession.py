"""Ruckus AbcSession which connects to Ruckus Unleashed, ZoneDirector, SmartZone or Ruckus One via HTTPS"""
from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any

import aiohttp
from yarl import URL

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from .abcsession import AbcSession, ConfigItem
from .const import ERROR_CONNECT_EOF, ERROR_NO_SESSION
from .exceptions import NotDirectorError
from .utility import *

if TYPE_CHECKING:
    from .ruckusajaxapi import RuckusAjaxApi

class AjaxSession(AbcSession):
    """Connect to a Ruckus controller. Provider-agnostic: auto-detects the underlying controller (Unleashed/ZoneDirector, SmartZone or Ruckus One) at login."""

    def __init__(
        self,
        websession: aiohttp.ClientSession,
        host: str,
        username: str,
        password: str,
        auto_cleanup_websession=False,
    ) -> None:
        """Initialize the session with connection parameters.

        Args:
            websession: aiohttp client session used for all HTTP requests.
            host: hostname or IP address of the Ruckus controller.
            username: controller login username.
            password: controller login password.
            auto_cleanup_websession: close `websession` when the session is closed.
        """
        super().__init__()

        self.websession = websession
        self.host = host
        self.username = username
        self.password = password
        self.__auto_cleanup_websession = auto_cleanup_websession

        # Common Session State
        self.base_url: URL | None = None
        self._api: RuckusAjaxApi | None = None

    async def __aenter__(self) -> AjaxSession:
        """Login and return this session for use as an async context manager."""
        await self.login()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        """Close the session when leaving the async context manager."""
        await self.close()

    @property
    @override
    def api(self) -> RuckusAjaxApi:
        """Return a RuckusApi instance. Raises RuntimeError if not logged in."""
        if not self._api:
            from .ruckusajaxapi import RuckusAjaxApi
            self._api = RuckusAjaxApi(self)
        return self._api

    @override
    async def get_conf_str(self, item: ConfigItem, timeout: aiohttp.ClientTimeout | int | None = None) -> str:
        """Return the relevant config xml, given a configuration key"""
        if not self._api:
            raise RuntimeError(ERROR_NO_SESSION)
        return await self._api._get_conf_str(item, timeout)

    async def login(self) -> AjaxSession:
        """Create HTTPS AJAX session, auto-detecting the provider."""
        target_url = get_host_url(self.host)
        assert target_url.host is not None

        # Short-circuit Ruckus One identification
        if target_url.host == "ruckus.cloud" or target_url.host.endswith(".ruckus.cloud"):
            return await self._r1_login()
        # Short-circuit SmartZone identification
        if target_url.port == 8443:
            return await self._sz_login()
        # Try Unleashed/ZoneDirector
        try:
            return await self._zd_login()
        except NotDirectorError:
            # Try SmartZone
            try:
                return await self._sz_login()
            except Exception as err:
                raise ConnectionError(ERROR_CONNECT_EOF) from err

    async def _zd_login(self) -> AjaxSession:
        """Login to an Unleashed or ZoneDirector controller."""
        from .ruckusajaxapi import RuckusAjaxApi
        self._api = await RuckusAjaxApi(self).login()
        return self

    async def _sz_login(self) -> AjaxSession:
        """Login to a SmartZone controller."""
        from .smartzoneajaxapi import SmartZoneAjaxApi
        self._api = await SmartZoneAjaxApi(self).login()
        return self

    async def _r1_login(self) -> AjaxSession:
        """Login to a Ruckus One controller."""
        from .ruckusoneajaxapi import RuckusOneAjaxApi
        self._api = await RuckusOneAjaxApi(self).login()
        return self

    async def close(self) -> None:
        """Logout and close websession"""
        if self.websession:
            try:
                if self._api:
                    await self._api.close()
            finally:
                if self.__auto_cleanup_websession:
                    await self.websession.close()

    @staticmethod
    def async_create(host: str, username: str, password: str) -> AjaxSession:
        """Create a default ClientSession & use this to create an AjaxSession instance"""
        return AjaxSession(create_legacy_client_session(), host, username, password, auto_cleanup_websession=True)
