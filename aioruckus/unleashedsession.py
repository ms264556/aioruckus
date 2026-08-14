"""Ruckus Unleashed / ZoneDirector AJAX session."""

from __future__ import annotations

import asyncio
import sys
import xml.etree.ElementTree as ET

import aiohttp
import xmltodict
from yarl import URL

from .abcsession import ConfigItem
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
from .unleashedtojson import _restructure, parse_ajax_response
from .utility import (
    cast_timeout,
    create_legacy_client_session,
    get_host_url,
    ruckus_timestamp,
)

if sys.version_info >= (3, 11):
    from typing import Any
else:
    from typing_extensions import Any


class UnleashedSession:
    """Manage sessions and make API requests to Ruckus Unleashed and ZoneDirector AJAX endpoints."""

    host: str
    username: str
    password: str
    base_url: URL | None = None
    __client: aiohttp.ClientSession
    __login_url: URL | None = None

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        websession: aiohttp.ClientSession | None = None,
    ) -> None:
        """Initialize the session with connection parameters.

        Args:
            host: hostname or IP address of the Ruckus controller.
            username: controller login username.
            password: controller login password.
            websession: optional aiohttp client session; one is created
                (and closed on logout) if not provided.
        """
        self.host = host
        self.username = username
        self.password = password
        self.__client = websession or create_legacy_client_session()
        self.__auto_cleanup_websession = not websession

    async def __aenter__(self) -> UnleashedSession:
        """Login and return this session for use as an async context manager."""
        await self.login()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        """Close the session when leaving the async context manager."""
        await self.close()

    async def login(self) -> UnleashedSession:
        """Create Unleashed/ZoneDirector HTTPS AJAX session."""
        target_url = get_host_url(self.host)
        assert target_url.host is not None

        login_request_timeout = aiohttp.ClientTimeout(total=3)

        # locate the admin pages: /admin/* for Unleashed and ZD 9.x, /admin10/* for ZD 10.x
        try:
            async with self.__client.get(
                target_url, timeout=login_request_timeout, allow_redirects=False
            ) as get:
                if 400 <= get.status < 500:
                    # Request Refused - maybe one-interface SmartZone
                    raise NotDirectorError(ERROR_NOT_ZD)
                # Resolve the redirect URL against the request URL to handle relative paths
                login_candidate_url = get.url.join(URL(get.headers["Location"]))

            # Handle Unleashed Member -> Master redirect, which might be a two-step redirect
            if login_candidate_url.path == "/":
                async with self.__client.get(
                    login_candidate_url,
                    timeout=login_request_timeout,
                    allow_redirects=False,
                ) as get:
                    self.__login_url = get.url.join(URL(get.headers["Location"]))
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
            timeout=login_request_timeout,
            allow_redirects=False,
        ) as get:
            if get.status == 200:
                # if username/password were valid we'd be redirected to the main admin page
                raise AuthenticationError(ERROR_LOGIN_INCORRECT)
            if "HTTP_X_CSRF_TOKEN" in get.headers:
                # modern ZD and Unleashed return CSRF token in header
                self.__client.headers["X-CSRF-Token"] = get.headers["HTTP_X_CSRF_TOKEN"]
            else:
                # older ZD and Unleashed require you to scrape the CSRF token from a page's
                # javascript
                if not self.base_url:
                    raise ConnectionError("Login failed: could not determine base URL for CSRF token.")
                async with self.__client.get(
                    self.base_url / "_csrfTokenVar.jsp",
                    timeout=login_request_timeout,
                    allow_redirects=False,
                ) as response:
                    if response.status == 200:
                        csrf_token = (
                            xmltodict.parse(await response.text())["script"].split("=").pop()[2:12]
                        )
                        self.__client.headers["X-CSRF-Token"] = csrf_token
                    elif response.status == 500:
                        # really ancient ZD don't use CSRF tokens at all
                        pass
                    else:
                        # token page is a redirect, maybe temporary Unleashed Rebuilding placeholder
                        # page is showing
                        raise ConnectionRefusedError(ERROR_CONNECT_TEMPORARY)

            # fail if we're connected to standby controller
            async with self.__client.post(
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
                                raise ConnectionError(
                                    f"Connected to standby node - please connect to Management Interface at {mgmt_ip}"
                                )
                            else:
                                raise ConnectionError(
                                    f"Connected to standby node - please connect to Peer Interface at {peer_ip}"
                                )
        return self

    async def close(self) -> None:
        """Logout of Unleashed/ZoneDirector and close websession"""
        if self.__client:
            try:
                if self.__login_url:
                    async with self.__client.get(
                        self.__login_url,
                        params={"logout": "1"},
                        timeout=aiohttp.ClientTimeout(total=3),
                        allow_redirects=False,
                    ):
                        pass
            finally:
                if self.__auto_cleanup_websession:
                    await self.__client.close()

    async def get_conf_str(
        self,
        item: ConfigItem,
        timeout: aiohttp.ClientTimeout | int | None = None,
    ) -> str:
        """Return the relevant config xml, given a configuration key"""
        return await self._ajax_request(
            "_conf.jsp",
            f"<ajax-request action='getconf' DECRYPT_X='true' "
            f"updater='{item.value}.0.5' comp='{item.value}'/>",
            timeout=timeout,
        )

    async def _ajax_request(
        self,
        cmd: str,
        data: str,
        *,
        timeout: aiohttp.ClientTimeout | int | None = None,
        retrying: bool = False,
    ) -> str:
        """Request data from an AJAX endpoint"""
        if not self.base_url:
            raise RuntimeError(ERROR_NO_SESSION)

        async with self.__client.post(
            self.base_url / cmd,
            data=data,
            headers={"Content-Type": "text/xml"},
            timeout=cast_timeout(timeout),
            allow_redirects=False,
        ) as response:
            if response.status == 302:
                # if the session is dead then we're redirected to the login page
                if retrying:
                    # we tried logging in again, but the redirect still happens - maybe password
                    # changed?
                    raise AuthenticationError(ERROR_POST_REDIRECTED)
                await self.login()  # try logging in again, then retry post
                return await self._ajax_request(cmd, data, timeout=timeout, retrying=True)
            result_text = await response.text(errors="replace")
            if not result_text or result_text == "\n":
                # if the ajax request payload wasn't understood then we get an empty page back
                raise RuntimeError(ERROR_POST_NORESULT)
            return result_text

    @staticmethod
    def _get_filter_object(
        filters: dict[str, Any] | None = None,
        sort_by: str = "time",
        sort_descending: bool = True,
    ) -> dict:
        """Build the XML attribute dict for piecewise cmdstat filters.

        Args:
            filters: mapping of attribute name to a single value or a list of
                alternatives; list values are joined with ``|``.
            sort_by: attribute used to sort the result.
            sort_descending: sort newest-first when True.
        """
        result = {"@sortBy": sort_by, "@sortDirection": -1 if sort_descending else 1}
        if filters is not None:
            for key, values in filters.items():
                if isinstance(values, str):
                    result[f"@{key}"] = values
                else:
                    joined_values = f"|{'|'.join(values)}|"
                    result[f"@{key}"] = joined_values
        return result

    async def cmdstat_piecewise(
        self,
        comp: str,
        element_type: str,
        element_collection: str | None = None,
        filters: dict[str, Any] | None = None,
        limit: int = 300,
        page_size: int | None = None,
        updater: str | None = None,
        target_type: type | None = None,
        timeout: aiohttp.ClientTimeout | int | None = None,
    ) -> list[Any]:
        """Call cmdstat and collect piecewise xml results, paging until done.

        Mirrors the R1/SZ session ``query`` paging: pages are fetched until
        the controller reports ``done`` or ``limit`` elements are collected.
        """
        ts_time = ruckus_timestamp(random_part=False)
        ts_random = ruckus_timestamp(time_part=False)
        updater = updater or comp
        page_size = page_size or limit

        piece_stat = {
            "@pid": 0,
            "@start": 0,
            "@number": page_size,
            "@requestId": f"{updater}.{ts_time}",
            "@cleanupId": f"{updater}.{ts_time}.{ts_random}",
        }
        request = {
            "ajax-request": {
                "@action": "getstat",
                "@comp": comp,
                "@updater": f"{updater}.{ts_time}.{ts_random}",
                element_type: self._get_filter_object(filters),
                "pieceStat": piece_stat,
            }
        }

        element_collection = element_collection or "response"
        results: list[Any] = []
        pid = 0
        item_number = 0

        while True:
            pid += 1
            if page_size > limit > 0:
                page_size = limit

            piece_stat["@pid"] = pid
            piece_stat["@start"] = item_number
            piece_stat["@number"] = page_size

            request_xml = xmltodict.unparse(
                request, full_document=False, short_empty_elements=True
            )
            result_text = await self._ajax_request("_cmdstat.jsp", request_xml, timeout=timeout)
            page = parse_ajax_response(result_text)

            elements = page.get(element_type) if isinstance(page, dict) else None
            if elements is None:
                break  # page has no elements of this type - we're done
            if isinstance(elements, dict):
                elements = [elements]
            if target_type is not None:
                elements = _restructure(target_type, elements)
            results.extend(elements)
            item_number += len(elements)

            if len(results) >= limit:
                break
            if page.get("done") == "true":
                break

        return results[:limit]

    async def _request_file(
        self,
        file_url: str | URL,
        *,
        timeout: aiohttp.ClientTimeout | int | None = None,
        retrying: bool = False,
    ) -> bytes:
        """Download a file from the controller"""
        if not self.base_url:
            raise RuntimeError(ERROR_NO_SESSION)
        url = self.base_url / file_url if isinstance(file_url, str) else file_url

        async with self.__client.get(
            url,
            timeout=cast_timeout(timeout),
            allow_redirects=False,
        ) as response:
            if response.status == 302:
                # if the session is dead then we're redirected to the login page
                if retrying:
                    # we tried logging in again, but the redirect still happens - maybe password
                    # changed?
                    raise AuthenticationError(ERROR_POST_REDIRECTED)
                await self.login()  # try logging in again, then retry post
                return await self._request_file(file_url, timeout=timeout, retrying=True)
            return await response.read()
