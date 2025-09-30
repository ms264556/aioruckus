"""Ruckus AbcSession which connects to Ruckus Unleashed or ZoneDirector via HTTPS AJAX"""
from __future__ import annotations
from typing import Any, TYPE_CHECKING, override
from yarl import URL
import asyncio
import ssl
import aiohttp
import xml.etree.ElementTree as ET
import xmltodict

from .abcsession import AbcSession, ConfigItem
from .exceptions import AuthenticationError
from .const import (
    ERROR_POST_NORESULT,
    ERROR_POST_REDIRECTED,
    ERROR_CONNECT_EOF,
    ERROR_CONNECT_TEMPORARY,
    ERROR_CONNECT_TIMEOUT,
    ERROR_LOGIN_INCORRECT,
    ERROR_NO_SESSION
)
from .utility import *

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

        # ZoneDirector / Unleashed Session State
        self.__login_url: URL | None = None

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
    async def get_conf_str(self, item: ConfigItem, timeout: aiohttp.ClientTimeout | int | None = None) -> str:
        if not self.base_url:
            raise RuntimeError(ERROR_NO_SESSION)
        
        return await self.request(
            self.base_url / "_conf.jsp",
            f"<ajax-request action='getconf' DECRYPT_X='true' "
            f"updater='{item.value}.0.5' comp='{item.value}'/>",
            timeout
        )

    async def login(self) -> AjaxSession:
        """Create HTTPS AJAX session."""
        target_url = get_host_url(self.host)
        assert target_url.host is not None

        # Short-circuit Ruckus One identification
        if target_url.host == "ruckus.cloud" or target_url.host.endswith(".ruckus.cloud"):
            return await self.r1_login()
        # Short-circuit SmartZone identification
        if target_url.port == 8443:
            return await self.sz_login()
        
        login_request_timeout = aiohttp.ClientTimeout(total=3)

        # locate the admin pages: /admin/* for Unleashed and ZD 9.x, /admin10/* for ZD 10.x
        try:
            async with self.websession.head(
                target_url, timeout=login_request_timeout, allow_redirects=False
            ) as head:
                if 400 <= head.status < 500:
                    # Request Refused - maybe one-interface SmartZone
                    return await self.sz_login()
                # Resolve the redirect URL against the request URL to handle relative paths
                login_candidate_url = head.url.join(URL(head.headers["Location"]))

            # Handle Unleashed Member -> Master redirect, which might be a two-step redirect
            if login_candidate_url.path == '/':
                async with self.websession.head(
                    login_candidate_url, timeout=login_request_timeout, allow_redirects=False
                ) as head:
                    self.__login_url = head.url.join(URL(head.headers["Location"]))
            else:
                self.__login_url = login_candidate_url

            if not self.__login_url:
                raise ConnectionError(ERROR_CONNECT_EOF)

            self.base_url = self.__login_url.parent
            login_page = self.__login_url.name
            if login_page in ("index.html", "wizard.jsp"):
                # Unleashed Rebuilding or Setup Wizard
                raise ConnectionRefusedError(ERROR_CONNECT_TEMPORARY)
        except KeyError as kerr:
            raise ConnectionError(ERROR_CONNECT_EOF) from kerr
        except aiohttp.ClientConnectorError as cerr:
            # Connection Error - maybe three-interface SmartZone
            try:
                return await self.sz_login()
            except Exception:
                raise ConnectionError(ERROR_CONNECT_EOF) from cerr
        except asyncio.exceptions.TimeoutError as terr:
            raise ConnectionError(ERROR_CONNECT_TIMEOUT) from terr

        # login and collect CSRF token
        async with self.websession.head(
            self.__login_url,
            params={
                "username": self.username,
                "password": self.password,
                "ok": "Log In",
            },
            timeout=login_request_timeout,
            allow_redirects=False,
        ) as head:
            if head.status == 200:
                # if username/password were valid we'd be redirected to the main admin page
                raise AuthenticationError(ERROR_LOGIN_INCORRECT)
            if "HTTP_X_CSRF_TOKEN" in head.headers:
                # modern ZD and Unleashed return CSRF token in header
                self.websession.headers["X-CSRF-Token"] = head.headers["HTTP_X_CSRF_TOKEN"]
            else:
                # older ZD and Unleashed require you to scrape the CSRF token from a page's
                # javascript
                if not self.base_url:
                    raise ConnectionError("Login failed: could not determine base URL for CSRF token.")
                async with self.websession.get(
                    self.base_url / "_csrfTokenVar.jsp",
                    timeout=login_request_timeout,
                    allow_redirects=False,
                ) as response:
                    if response.status == 200:
                        csrf_token = (
                            xmltodict.parse(await response.text())["script"].split("=").pop()[2:12]
                        )
                        self.websession.headers["X-CSRF-Token"] = csrf_token
                    elif response.status == 500:
                        # really ancient ZD don't use CSRF tokens at all
                        pass
                    else:
                        # token page is a redirect, maybe temporary Unleashed Rebuilding placeholder
                        # page is showing
                        raise ConnectionRefusedError(ERROR_CONNECT_TEMPORARY)
                    
            # fail if we're connected to standby controller
            async with self.websession.post(
                self.base_url / "_cmdstat.jsp",
                data='<ajax-request action="getstat" comp="cluster"/>',
                headers={"Content-Type": "text/xml"},
                timeout=login_request_timeout,
                allow_redirects=False,
            ) as response:
                if response.status == 200:
                    response_text = await response.text()
                    if response_text and response_text != "\n":
                        try:
                            root = ET.fromstring(response_text)
                            standby_xmsg = root.find(".//xmsg[@to-state='1']")
                        except ET.ParseError:
                            standby_xmsg = None
                        if standby_xmsg is not None:
                            peer_ip = standby_xmsg.get("peer-ip")
                            mgmt_ip = standby_xmsg.get("mgmt-ip")
                            if mgmt_ip:
                                raise ConnectionError(f"Connected to standby node - please connect to Management Interface at {mgmt_ip}")
                            else:
                                raise ConnectionError(f"Connected to standby node - please connect to Peer Interface at {peer_ip}")
        return self

    async def sz_login(self) -> AjaxSession:
        from .smartzoneajaxapi import SmartZoneAjaxApi
        self._api = await SmartZoneAjaxApi(self).login()
        return self

    async def r1_login(self) -> AjaxSession:
        from .ruckusoneajaxapi import RuckusOneAjaxApi
        self._api = await RuckusOneAjaxApi(self).login()
        return self

    async def close(self) -> None:
        """Logout of ZoneDirector/Unleashed and close websession"""
        if self.websession:
            try:
                if self.__login_url:
                    async with self.websession.head(
                        self.__login_url,
                        params={"logout": "1"},
                        timeout=aiohttp.ClientTimeout(total=3),
                        allow_redirects=False,
                    ):
                        pass
                else:
                    await self.api.close()
            finally:
                if self.__auto_cleanup_websession:
                    await self.websession.close()

    async def request(
        self,
        cmd: URL,
        data: str,
        timeout: aiohttp.ClientTimeout | int | None = None,
        retrying: bool = False
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
            allow_redirects=False
        ) as response:
            if response.status == 302:
                # if the session is dead then we're redirected to the login page
                if retrying:
                    # we tried logging in again, but the redirect still happens - maybe password
                    # changed?
                    raise AuthenticationError(ERROR_POST_REDIRECTED)
                await self.login()  # try logging in again, then retry post
                return await self.request(cmd, data, timeout, retrying=True)
            result_text = await response.text()
            if not result_text or result_text == "\n":
                # if the ajax request payload wasn't understood then we get an empty page back
                raise RuntimeError(ERROR_POST_NORESULT)
            return result_text

    @staticmethod
    def async_create(host: str, username: str, password: str) -> AjaxSession:
        """Create a default ClientSession & use this to create an AjaxSession instance"""
        return AjaxSession(create_legacy_client_session(), host, username, password, auto_cleanup_websession=True)

    async def request_file(self, file_url: str | URL, timeout: aiohttp.ClientTimeout | int | None = None, retrying: bool = False) -> bytes:
        """File Download"""
        if isinstance(timeout, int):
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
        else:
            timeout_obj = timeout

        async with self.websession.get(
            file_url,
            timeout=timeout_obj,
            allow_redirects=False
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
