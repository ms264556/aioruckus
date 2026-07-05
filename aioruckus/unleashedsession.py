"""UnleashedSession class."""

from __future__ import annotations
import asyncio
import sys
import xml.etree.ElementTree as ET
import aiohttp
import xmltodict
from yarl import URL
from .abcsession import ConfigItem, StatComp
from .const import (
    ERROR_CONNECT_EOF,
    ERROR_CONNECT_TEMPORARY,
    ERROR_CONNECT_TIMEOUT,
    ERROR_LOGIN_INCORRECT,
    ERROR_NO_SESSION,
    ERROR_NOT_ZD,
    ERROR_POST_NORESULT,
    ERROR_POST_REDIRECTED,
)
from .exceptions import AuthenticationError, NotDirectorError
from .smartzonetyping import SessionDict
from .utility import (
    cast_timeout,
    create_legacy_client_session,
    get_host_url,
    ruckus_timestamp,
)
from .unleashedtojson import parse_ajax_response

if sys.version_info >= (3, 11):
    from typing import Any, TypeVar
else:
    from typing_extensions import Any, TypeVar

D = TypeVar("D")

class UnleashedSession:
    """
    Manage sessions and make API requests to Ruckus Unleashed and ZoneDirector
    AJAX endpoints.
    """

    host: str
    username: str
    password: str
    session_info: SessionDict | None = None
    __client: aiohttp.ClientSession
    __login_url: URL | None = None
    __base_url: URL | None = None
    __login_request_timeout = aiohttp.ClientTimeout(total=3)

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        websession: aiohttp.ClientSession | None = None,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.__client = websession or create_legacy_client_session()
        self.__auto_cleanup_websession = not websession

    async def __aenter__(self) -> UnleashedSession:
        await self.login()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def login(self) -> UnleashedSession:
        """Create Unleashed/ZoneDirector session."""
        target_url = get_host_url(self.host)
        assert target_url.host is not None

        # locate the admin pages: /admin/* for Unleashed and ZD 9.x, /admin10/* for ZD 10.x
        try:
            async with self.__client.get(
                target_url, timeout=self.__login_request_timeout, allow_redirects=False
            ) as get:
                if 400 <= get.status < 500:
                    raise NotDirectorError(ERROR_NOT_ZD)
                login_candidate_url = get.url.join(URL(get.headers["Location"]))

            # Handle Unleashed Member -> Master redirect, which might be a two-step redirect
            if login_candidate_url.path == "/":
                async with self.__client.get(
                    login_candidate_url,
                    timeout=self.__login_request_timeout,
                    allow_redirects=False,
                ) as get:
                    self.__login_url = get.url.join(URL(get.headers["Location"]))
            else:
                self.__login_url = login_candidate_url

            if not self.__login_url:
                raise ConnectionError(ERROR_CONNECT_EOF)

            self.__base_url = self.__login_url.parent
            login_page = self.__login_url.name
            if login_page in ("index.html", "wizard.jsp"):
                # Unleashed Rebuilding or Setup Wizard
                raise ConnectionRefusedError(ERROR_CONNECT_TEMPORARY)
        except KeyError as kerr:
            raise ConnectionError(ERROR_CONNECT_EOF) from kerr
        except aiohttp.ClientConnectorError as cerr:
            raise NotDirectorError(ERROR_NOT_ZD) from cerr
        except asyncio.exceptions.TimeoutError as terr:
            raise ConnectionError(ERROR_CONNECT_TIMEOUT) from terr

        # login and collect CSRF token
        async with self.__client.get(
            self.__login_url,
            params={
                "username": self.username,
                "password": self.password,
                "ok": "Log In",
            },
            timeout=self.__login_request_timeout,
            allow_redirects=False,
        ) as get:
            if get.status == 200:
                # if username/password were valid we'd be redirected to the main admin page
                raise AuthenticationError(ERROR_LOGIN_INCORRECT)
            if "HTTP_X_CSRF_TOKEN" in get.headers:
                # modern ZD and Unleashed return CSRF token in header
                self.__client.headers["X-CSRF-Token"] = get.headers[
                    "HTTP_X_CSRF_TOKEN"
                ]
            else:
                # older ZD and Unleashed require you to scrape the CSRF token from a page's
                # javascript
                if not self.__base_url:
                    raise ConnectionError(
                        "Login failed: could not determine base URL for CSRF token."
                    )
                async with self.__client.get(
                    self.__base_url / "_csrfTokenVar.jsp",
                    timeout=self.__login_request_timeout,
                    allow_redirects=False,
                ) as response:
                    if response.status == 200:
                        csrf_token = (
                            xmltodict.parse(await response.text())["script"]
                            .split("=")
                            .pop()[2:12]
                        )
                        self.__client.headers["X-CSRF-Token"] = csrf_token
                    elif response.status == 500:
                        # really ancient ZD don't use CSRF tokens at all
                        pass
                    else:
                        # token page is a redirect, maybe temporary Unleashed Rebuilding
                        # placeholder page is showing
                        raise ConnectionRefusedError(ERROR_CONNECT_TEMPORARY)

            # fail if we're connected to standby controller
            async with self.__client.post(
                self.__base_url / "_cmdstat.jsp",
                data='<ajax-request action="getstat" comp="cluster"/>',
                headers={"Content-Type": "text/xml"},
                timeout=self.__login_request_timeout,
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
                                raise ConnectionError(
                                    f"Connected to Standby Node. "
                                    f"Management Interface is at {mgmt_ip}."
                                )
                            raise ConnectionError(
                                f"Connected to Standby Node. "
                                f"Active Node is at {peer_ip}."
                            )
        return self

    async def close(self) -> None:
        """Logout of Unleashed and close websession"""
        if self.__client:
            try:
                if self.__login_url:
                    await self.__client.get(
                        self.__login_url,
                        params={"logout": "1"},
                        timeout=self.__login_request_timeout,
                        allow_redirects=False,
                    )
            finally:
                if self.__auto_cleanup_websession:
                    await self.__client.close()

    # ajax request
    # always POST, always text/xml
    # command: str, action: str, comp: str, attributes: dict[str, str] = {}, payload: str | dict | dict[] | ElementTree | None = None, query: dict[str, str] | None = None
    # attributes:
    #    If action == "getconf" and then add DECRYPT_X='true'.
    #    If action == "cmdstat" then add enable-gzip='0' caller='SCI'.
    #    If no updater, default to f"{comp}.{ts}".
    # payload: elementtree, string, json (with @ prefix for attributes)

    # async def ajax_request(self, cmd: str, *, action:str | None, comp: str | None, updater: str | None, payload: str | dict | list[dict] | ElementTree | None) -> str:
    #     """Make an ajax-request and return the raw XML string"""
    #     print("ajax_request not implemented")
    #     return ""

    async def getconf(
        self,
        comp: str | ConfigItem,
        *,
        timeout: int | None = None,
    ) -> str:
        return await self._ajax_request(
            "_conf.jsp",
            f"<ajax-request action='getconf' DECRYPT_X='true' "
            f"updater='{comp}.{ruckus_timestamp()}' comp='{comp}'/>",
            timeout=timeout,
        )

    async def conf_updobj(
        self,
        obj: ET.Element,
        *,
        timeout: int | None = None,
    ) -> None:
        xml = obj if isinstance(obj, ET.Element) else ET.fromstring(obj)
        payload = obj if isinstance(obj, str) else ET.tostring(obj, encoding="unicode")
        comp = f"{xml.tag}-list"
        await self._ajax_request(
            "_conf.jsp",
            f"<ajax-request action='updobj' updater='{comp}.{ruckus_timestamp()}' comp='{comp}'>"
            f"{payload}</ajax-request>",
            timeout=timeout,
        )

    async def conf_addobj(
        self,
        obj: ET.Element | str,
        *,
        timeout: int | None = None,
    ) -> None:
        xml = obj if isinstance(obj, ET.Element) else ET.fromstring(obj)
        payload = obj if isinstance(obj, str) else ET.tostring(obj, encoding="unicode")
        comp = f"{xml.tag}-list"
        await self._ajax_request(
            "_conf.jsp",
            f"<ajax-request action='addobj' updater='{comp}.{ruckus_timestamp()}' comp='{comp}'>"
            f"{payload}</ajax-request>",
            timeout=timeout,
        )

    async def conf_delobj(
        self,
        obj: ET.Element | str,
        *,
        timeout: int | None = None,
    ) -> None:
        xml = obj if isinstance(obj, ET.Element) else ET.fromstring(obj)
        payload = obj if isinstance(obj, str) else ET.tostring(obj, encoding="unicode")
        comp = f"{xml.tag}-list"
        id = xml.get("id")
        if id is None:
            raise ValueError("obj must have an id attribute")
        await self._ajax_request(
            "_conf.jsp",
            f"<ajax-request action='delobj' updater='{comp}.{ruckus_timestamp()}' comp='{comp}'>"
            f"{payload}</ajax-request>",
            timeout=timeout,
        )

    async def getstat(
        self,
        target_type: type[D],
        stat: str | ET.Element | None = None,
        *,
        comp: str | StatComp = StatComp.STAMGR,
        timeout: int | None = None,
    ) -> D:
        if isinstance(stat, ET.Element):
            stat = ET.tostring(stat, encoding="unicode")
        result = await self._ajax_request(
            "_cmdstat.jsp",
            f"<ajax-request action='getstat' enable-gzip='0' updater='{comp}.{ruckus_timestamp()}' comp='{comp}'>"
            f"{stat or ''}"
            f"</ajax-request>",
            timeout=timeout,
        )
        return parse_ajax_response(result, target_type)

    async def _ajax_request(
        self,
        cmd: str,
        data: str,
        *,
        timeout: aiohttp.ClientTimeout | int | None = None,
        retrying: bool = False,
    ) -> str:
        """Request data"""
        if not self.__base_url:
            raise RuntimeError(ERROR_NO_SESSION)

        async with self.__client.post(
            self.__base_url / cmd,
            data=data,
            headers={"Content-Type": "text/xml"},
            timeout=cast_timeout(timeout),
            allow_redirects=False,
        ) as response:
            if response.status == 302:
                if retrying:
                    raise AuthenticationError(ERROR_POST_REDIRECTED)
                await self.login()
                return await self._ajax_request(
                    cmd, data, timeout=timeout, retrying=True
                )
            result_text = await response.text()
            if not result_text or result_text == "\n":
                raise RuntimeError(ERROR_POST_NORESULT)
            return result_text

    async def _request_file(
        self,
        file_url: str,
        *,
        timeout: aiohttp.ClientTimeout | int | None = None,
        retrying: bool = False,
    ) -> bytes:
        """File Download"""
        if not self.__base_url:
            raise RuntimeError(ERROR_NO_SESSION)

        async with self.__client.get(
            self.__base_url / file_url,
            timeout=cast_timeout(timeout),
            allow_redirects=False,
        ) as response:
            if response.status == 302:
                if retrying:
                    raise AuthenticationError(ERROR_POST_REDIRECTED)
                await self.login()
                return await self._request_file(
                    file_url, timeout=timeout, retrying=True
                )
            return await response.read()
