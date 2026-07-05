"""Ruckus AbcSession which connects to Ruckus Unleashed or ZoneDirector via HTTPS AJAX"""

from __future__ import annotations
import sys
import aiohttp
from yarl import URL
from .abcsession import AbcSession, ConfigItem
from .const import ERROR_NO_SESSION, ERROR_POST_NORESULT, ERROR_POST_REDIRECTED
from .exceptions import AuthenticationError, NotDirectorError
from .utility import *

if sys.version_info >= (3, 11):
    from typing import TYPE_CHECKING, Any, override
else:
    from typing_extensions import TYPE_CHECKING, Any, override


if TYPE_CHECKING:
    from .ruckusajaxapi import RuckusAjaxApi


class AjaxSession(AbcSession):
    """Connect to Ruckus Unleashed or ZoneDirector via HTTPS AJAX"""

    def __init__(
        self,
        websession: aiohttp.ClientSession,
        host: str,
        username: str,
        password: str,
        auto_cleanup_websession=False,
    ) -> None:
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
        await self.login()
        return self

    async def __aexit__(self, *exc: Any) -> None:
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
    async def getconf(
        self, item: ConfigItem, timeout: aiohttp.ClientTimeout | int | None = None
    ) -> str:
        if not self.base_url:
            raise RuntimeError(ERROR_NO_SESSION)

        return await self.request(
            self.base_url / "_conf.jsp",
            f"<ajax-request action='getconf' DECRYPT_X='true' "
            f"updater='{item}.0.5' comp='{item}'/>",
            timeout,
        )

    async def login(self) -> AjaxSession:
        """Create HTTPS AJAX session."""
        target_url = get_host_url(self.host)
        assert target_url.host is not None
        # Short-circuit Ruckus One identification
        if target_url.host == "ruckus.cloud" or target_url.host.endswith(
            ".ruckus.cloud"
        ):
            return await self._r1_login()
        # Short-circuit SmartZone identification
        if target_url.port == 8443:
            return await self._sz_login()
        # Try Unleashed/ZoneDirector
        try:
            return await self._zd_login()
        except NotDirectorError:
            # Try SmartZone
            return await self._sz_login()

    async def _zd_login(self) -> AjaxSession:
        from .ruckusajaxapi import RuckusAjaxApi

        self._api = await RuckusAjaxApi(self).login()
        return self

    async def _sz_login(self) -> AjaxSession:
        from .smartzoneajaxapi import SmartZoneAjaxApi

        self._api = await SmartZoneAjaxApi(self).login()
        return self

    async def _r1_login(self) -> AjaxSession:
        from .ruckusoneajaxapi import RuckusOneAjaxApi

        self._api = await RuckusOneAjaxApi(self).login()
        return self

    async def close(self) -> None:
        """Logout and close websession"""
        if self.websession:
            try:
                await self.api.close()
            finally:
                if self.__auto_cleanup_websession:
                    await self.websession.close()

    async def request(
        self,
        cmd: URL,
        data: str,
        timeout: aiohttp.ClientTimeout | int | None = None,
        retrying: bool = False,
    ) -> str:
        """Request data"""
        if isinstance(timeout, int):
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
        else:
            timeout_obj = timeout

        async with self.websession.post(
            cmd,
            data=data,
            headers={"Content-Type": "text/xml"},
            timeout=timeout_obj,
            allow_redirects=False,
        ) as response:
            if response.status == 302:
                # if the session is dead then we're redirected to the login page
                if retrying:
                    # we tried logging in again, but the redirect still happens - maybe password
                    # changed?
                    raise AuthenticationError(ERROR_POST_REDIRECTED)
                await self.login()  # try logging in again, then retry post
                return await self.request(cmd, data, timeout, retrying=True)
            result_text = await response.text(errors="replace")
            if not result_text or result_text == "\n":
                # if the ajax request payload wasn't understood then we get an empty page back
                raise RuntimeError(ERROR_POST_NORESULT)
            return result_text

    @staticmethod
    def async_create(host: str, username: str, password: str) -> AjaxSession:
        """Create a default ClientSession & use this to create an AjaxSession instance"""
        return AjaxSession(
            create_legacy_client_session(),
            host,
            username,
            password,
            auto_cleanup_websession=True,
        )

    async def request_file(
        self,
        file_url: str | URL,
        timeout: aiohttp.ClientTimeout | int | None = None,
        retrying: bool = False,
    ) -> bytes:
        """File Download"""
        if isinstance(timeout, int):
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
        else:
            timeout_obj = timeout

        async with self.websession.get(
            file_url, timeout=timeout_obj, allow_redirects=False
        ) as response:
            if response.status == 302:
                # if the session is dead then we're redirected to the login page
                if retrying:
                    # we tried logging in again, but the redirect still happens - maybe password
                    # changed?
                    raise AuthenticationError(ERROR_POST_REDIRECTED)
                await self.login()  # try logging in again, then retry post
                return await self.request_file(file_url, timeout, retrying=True)
            return await response.read()
