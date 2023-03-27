import asyncio
import ssl
from typing import Any

import aiohttp
import xmltodict
from .exceptions import AuthenticationError

from .const import (
    AJAX_POST_NORESULT_ERROR,
    AJAX_POST_REDIRECTED_ERROR,
    CONNECT_ERROR_EOF,
    CONNECT_ERROR_TEMPORARY,
    CONNECT_ERROR_TIMEOUT,
    LOGIN_ERROR_LOGIN_INCORRECT,
)


class AjaxSession:
    """Connect to Ruckus Unleashed or ZoneDirector via HTTPS AJAX"""

    def __init__(
        self,
        websession: aiohttp.ClientSession,
        host: str,
        username: str,
        password: str,
        auto_cleanup_websession=False,
    ) -> None:
        self.websession = websession
        self.host = host
        self.username = username
        self.password = password
        self.__auto_cleanup_websession = auto_cleanup_websession

        self.__api = None

        self.__login_url = None
        self.base_url = None
        self.cmdstat_url = None
        self.conf_url = None

    async def __aenter__(self) -> "AjaxSession":
        await self.login()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def login(self) -> None:
        """Create HTTPS AJAX session."""
        # locate the admin pages: /admin/* for Unleashed and ZD 9.x, /admin10/* for ZD 10.x
        try:
            async with self.websession.head(f"https://{self.host}", timeout=3, allow_redirects=False) as head:
                self.__login_url = head.headers["Location"]
                self.base_url, login_page = self.__login_url.rsplit("/", 1)
                if login_page == "index.html": # maybe temporary Unleashed Rebuilding placeholder page is showing
                    raise ConnectionRefusedError(CONNECT_ERROR_TEMPORARY)
                self.cmdstat_url = self.base_url + "/_cmdstat.jsp"
                self.conf_url = self.base_url + "/_conf.jsp"
        except aiohttp.client_exceptions.ClientConnectorError as cerr:
            raise ConnectionError(CONNECT_ERROR_EOF) from cerr
        except asyncio.exceptions.TimeoutError as terr:
            raise ConnectionError(CONNECT_ERROR_TIMEOUT) from terr

        # login and collect CSRF token
        async with self.websession.head(
            self.__login_url,
            params={
                "username": self.username,
                "password": self.password,
                "ok": "Log In",
            },
            timeout=3,
            allow_redirects=False,
        ) as head:
            if head.status == 200:  # if username/password were valid we'd be redirected to the main admin page
                raise AuthenticationError(LOGIN_ERROR_LOGIN_INCORRECT)
            if "HTTP_X_CSRF_TOKEN" in head.headers:  # modern ZD and Unleashed return CSRF token in header
                self.websession.headers["X-CSRF-Token"] = head.headers["HTTP_X_CSRF_TOKEN"]
            else:  # older ZD and Unleashed require you to scrape the CSRF token from a page's javascript
                async with self.websession.get(
                    self.base_url + "/_csrfTokenVar.jsp",
                    timeout=3,
                    allow_redirects=False,
                ) as response:
                    if response.status == 200:
                        csrf_token = (xmltodict.parse(await response.text())["script"].split("=").pop()[2:12])
                        self.websession.headers["X-CSRF-Token"] = csrf_token
                    elif response.status == 500:  # even older ZD don't use CSRF tokens at all
                        pass
                    else:  # token page is a redirect, maybe temporary Unleashed Rebuilding placeholder page is showing
                        raise ConnectionRefusedError(CONNECT_ERROR_TEMPORARY)
            return self

    async def close(self) -> None:
        """Logout of ZoneDirector/Unleashed and close websessiom"""
        if self.websession:
            async with self.websession.head(
                self.__login_url,
                params={"logout": "1"},
                timeout=3,
                allow_redirects=False,
            ):
                pass
            if self.__auto_cleanup_websession:
                await self.websession.close()

    async def request(self, cmd: str, data: str, retrying: bool = False) -> str:
        """Request data"""
        async with self.websession.post(cmd, data=data, headers={"Content-Type": "text/xml"}, allow_redirects=False) as response:
            if response.status == 302:  # if the session is dead then we're redirected to the login page
                if retrying:  # we tried logging in again, but the redirect still happens - maybe password changed?
                    raise PermissionError(AJAX_POST_REDIRECTED_ERROR)
                await self.login()  # try logging in again, then retry post
                return await self.request(cmd, data, retrying=True)
            result_text = await response.text()
            if not result_text or result_text == "\n":  # if the ajax request payload wasn't understood then we get an empty page back
                raise RuntimeError(AJAX_POST_NORESULT_ERROR)
            return result_text

    @property
    def api(self):
        """Return a RuckusApi instance."""
        if not self.__api:
            # pylint: disable=import-outside-toplevel
            from .ruckusapi import RuckusApi
            self.__api = RuckusApi(self)
        return self.__api

    @classmethod
    def async_create(cls, host: str, username: str, password: str) -> "AjaxSession":
        """Create a default ClientSession & use this to create an AjaxSession instance"""
        # create ssl context so we ignore cert errors
        context = ssl.create_default_context()
        context.set_ciphers("DEFAULT")
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        # make ClientSession using ssl the above SSLContext, allowing cookies on IP address URLs, and with short keepalive for compatibility with old Unleashed versions
        websession = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            cookie_jar=aiohttp.CookieJar(unsafe=True),
            connector=aiohttp.TCPConnector(keepalive_timeout=5, ssl_context=context),
        )
        return AjaxSession(websession, host, username, password, auto_cleanup_websession=True)
