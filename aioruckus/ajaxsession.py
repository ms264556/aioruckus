"""Ruckus AbcSession which connects to Ruckus Unleashed or ZoneDirector via HTTPS AJAX"""

import asyncio
import ssl
from typing import Any, TYPE_CHECKING

import aiohttp
from urllib.parse import urlparse
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
)

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
            async with self.websession.head(
                f"https://{self.host}", timeout=3, allow_redirects=False
            ) as head:
                redirect_to = head.headers["Location"]
            if urlparse(redirect_to).path:
                self.__login_url = redirect_to
            else:
                # Unleashed Member has redirected to Unleashed Master
                async with self.websession.head(
                    redirect_to, timeout=3, allow_redirects=False
                ) as head:
                    self.__login_url = head.headers["Location"]
            self.base_url, login_page = self.__login_url.rsplit("/", 1)
            if login_page in ("index.html", "wizard.jsp"):
                # Unleashed Rebuilding or Setup Wizard
                raise ConnectionRefusedError(ERROR_CONNECT_TEMPORARY)
            self.cmdstat_url = self.base_url + "/_cmdstat.jsp"
            self.conf_url = self.base_url + "/_conf.jsp"
        except aiohttp.client_exceptions.ClientConnectorError as cerr:
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
            timeout=3,
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
                async with self.websession.get(
                    self.base_url + "/_csrfTokenVar.jsp",
                    timeout=3,
                    allow_redirects=False,
                ) as response:
                    if response.status == 200:
                        csrf_token = (
                            xmltodict.parse(await response.text())["script"].split("=").pop()[2:12]
                        )
                        self.websession.headers["X-CSRF-Token"] = csrf_token
                    elif response.status == 500:
                        # even older ZD don't use CSRF tokens at all
                        pass
                    else:
                        # token page is a redirect, maybe temporary Unleashed Rebuilding placeholder
                        # page is showing
                        raise ConnectionRefusedError(ERROR_CONNECT_TEMPORARY)
            return self

    async def close(self) -> None:
        """Logout of ZoneDirector/Unleashed and close websessiom"""
        if self.websession:
            try:
                if self.__login_url:
                    async with self.websession.head(
                        self.__login_url,
                        params={"logout": "1"},
                        timeout=3,
                        allow_redirects=False,
                    ):
                        pass
            finally:
                if self.__auto_cleanup_websession:
                    await self.websession.close()

    async def request(
        self,
        cmd: str,
        data: str,
        timeout: int | None = None,
        retrying: bool = False
    ) -> str:
        """Request data"""
        async with self.websession.post(
            cmd,
            data=data,
            headers={"Content-Type": "text/xml"},
            timeout=timeout,
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

    @property
    def api(self) -> "RuckusAjaxApi":
        """Return a RuckusApi instance."""
        if not self._api:
            # pylint: disable=import-outside-toplevel
            from .ruckusajaxapi import RuckusAjaxApi
            self._api = RuckusAjaxApi(self)
        return self._api

    @classmethod
    def async_create(cls, host: str, username: str, password: str) -> "AjaxSession":
        """Create a default ClientSession & use this to create an AjaxSession instance"""
        # create SSLContext which ignores certificate errors
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers("DEFAULT")
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        # create ClientSession using our SSLContext, allowing cookies on IP address URLs,
        # with a short keepalive for compatibility with old Unleashed versions
        websession = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            cookie_jar=aiohttp.CookieJar(unsafe=True),
            connector=aiohttp.TCPConnector(keepalive_timeout=5, ssl_context=ssl_context),
        )
        return AjaxSession(websession, host, username, password, auto_cleanup_websession=True)

    async def get_conf_str(self, item: ConfigItem, timeout: int | None = None) -> str:
        return await self.request(
            self.conf_url,
            f"<ajax-request action='getconf' DECRYPT_X='true' "
            f"updater='{item.value}.0.5' comp='{item.value}'/>",
            timeout
        )
    