from __future__ import annotations
from math import ceil

import aiohttp
import asyncio
from typing import Any, cast

from .const import ERROR_CONNECT_EOF, ERROR_CONNECT_TIMEOUT, ERROR_NO_SESSION, ERROR_POST_REDIRECTED
from .exceptions import AuthenticationError, AuthorizationError, BusinessRuleError
from .smartzonetyping import PermissionCategoriesDict, SessionDict
from .utility import *

class SmartZoneSession:
    host: str
    username: str
    password: str
    session_info: SessionDict | None = None
    __client: aiohttp.ClientSession
    __base_url: URL | None = None
    __service_ticket: str | None = None

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        websession: aiohttp.ClientSession | None = None
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.__client = websession or create_legacy_client_session()
        self.__auto_cleanup_websession = not websession

    async def __aenter__(self) -> SmartZoneSession:
        await self.login()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def login(self) -> SmartZoneSession:
        """Create SmartZone session."""
        try:
            target_url = get_host_url(self.host)
            assert target_url.host is not None

            base_url = URL.build(scheme="https", host=target_url.host, port=8443, path="/wsg/api/public")
            async with self.__client.get(
                base_url / "apiInfo", timeout=aiohttp.ClientTimeout(total=3), allow_redirects=False
            ) as api_info:
                if api_info.status != 200:
                    raise ConnectionError(ERROR_CONNECT_EOF)
                api_versions = await api_info.json()
                supported_versions = api_versions.get('apiSupportVersions')
                if not isinstance(supported_versions, list) or not supported_versions:
                    raise ConnectionError("SmartZone controller did not return a list of supported API versions.")
                latest_version = supported_versions[-1]
                if not isinstance(latest_version, str):
                    raise ConnectionError(f"SmartZone controller returned an invalid API version format: {latest_version!r}.")

                self.__base_url = base_url / latest_version
                self.__client.headers["Content-Type"] = "application/json;charset=UTF-8"

                async with self.__client.post(
                    self.__base_url / "serviceTicket",
                    json={
                        "username": self.username,
                        "password": self.password
                    },
                    timeout=aiohttp.ClientTimeout(total=3),
                    allow_redirects=False
                ) as service_ticket:
                    ticket_info = await service_ticket.json()
                    if service_ticket.status != 200:
                        error_code = ticket_info["errorCode"]
                        if 200 <= error_code < 300:
                            raise AuthenticationError(ticket_info["errorType"])
                        raise ConnectionError(ticket_info["errorType"])
                    self.__service_ticket = ticket_info["serviceTicket"]
                    assert self.__service_ticket
                    controller_version = ticket_info["controllerVersion"]

                async with self.__client.get(
                    self.__base_url / "userGroups/currentUser/permissionCategories",
                    params={"serviceTicket": self.__service_ticket},
                    allow_redirects=False
                ) as user_permissions:
                    permission_categories = cast(PermissionCategoriesDict, await user_permissions.json())

                async with self.__client.get(
                    self.__base_url / "session",
                    params={"serviceTicket": self.__service_ticket},
                    allow_redirects=False
                ) as logon_session:
                    session_info = await logon_session.json()
                    session_info["apiVersion"] = latest_version
                    session_info["controllerVersion"] = controller_version
                    session_info["permissionCategories"] = permission_categories
                    if session_info['domainId'] != "8b2081d5-9662-40d9-a3db-2a3cf4dde3f7" and "@" in self.username:
                        session_info["partnerDomain"] = self.username.rsplit("@", 1)[1]

                if any(d.get("resource") == "CLUSTER_CATEGORY" for d in permission_categories["list"]):
                    cp_id = session_info["cpId"]
                    async with self.__client.get(
                        self.__base_url / "controlPlanes",
                        params={"serviceTicket": self.__service_ticket},
                        allow_redirects=False
                    ) as control_planes:
                        planes = await control_planes.json()
                        plane = next((p for p in planes["list"] if p["id"] == cp_id), None)
                        if plane:
                            session_info["cpName"] = plane["name"]
                            session_info["cpSerialNumber"] = plane["serialNumber"]

                self.session_info = cast(SessionDict, session_info)
                return self
        except KeyError as kerr:
            raise ConnectionError(ERROR_CONNECT_EOF) from kerr
        except IndexError as ierr:
            raise ConnectionError(ERROR_CONNECT_EOF) from ierr
        except aiohttp.ContentTypeError as cterr:
            raise ConnectionError(ERROR_CONNECT_EOF) from cterr
        except aiohttp.ClientConnectorError as cerr:
            raise ConnectionError(ERROR_CONNECT_EOF) from cerr
        except asyncio.exceptions.TimeoutError as terr:
            raise ConnectionError(ERROR_CONNECT_TIMEOUT) from terr

    async def close(self) -> None:
        """Logout of SmartZone and close websessiom"""
        if self.__client:
            try:
                if self.__base_url and self.__service_ticket:
                    await self.__client.delete(
                        self.__base_url / "serviceTicket",
                        params={"serviceTicket": self.__service_ticket},
                        timeout=cast_timeout(3),
                        allow_redirects=False
                    )
            finally:
                if self.__auto_cleanup_websession:
                    await self.__client.close()

    async def get(self, cmd: str, params: dict | None = None, timeout: aiohttp.ClientTimeout | int | None = None) -> Any:
        return await self._request("get", cmd, uri_params=params, timeout=cast_timeout(timeout))

    async def post(self, cmd: str, params: dict | None = None, timeout: aiohttp.ClientTimeout | int | None = None) -> Any:
        return await self._request("post", cmd, json=params or {}, timeout=cast_timeout(timeout))

    async def put(self, cmd: str, params: dict | None = None, timeout: aiohttp.ClientTimeout | int | None = None) -> Any:
        return await self._request("put", cmd, json=params or {}, timeout=cast_timeout(timeout))

    async def patch(self, cmd: str, params: dict | None = None, timeout: aiohttp.ClientTimeout | int | None = None) -> Any:
        return await self._request("patch", cmd, json=params or {}, timeout=cast_timeout(timeout))

    async def delete(self, cmd: str, params: dict | None = None, timeout: aiohttp.ClientTimeout | int | None = None) -> Any:
        return await self._request("delete", cmd, json=params or {}, timeout=cast_timeout(timeout))

    async def query(self, cmd: str, params: dict | None = None, page_size: int = 5, pages_limit: int = 100, timeout: aiohttp.ClientTimeout | int | None = None) -> list:
        query = params or {}
        timeout = cast_timeout(timeout)

        first_page = await self.post(cmd, {**query, "page": 1, "limit": page_size}, timeout)
        results: list[Any] = first_page.get("list", [])
        if not results or not first_page.get("hasMore"):
            return results
        page_count = min(pages_limit, ceil(first_page["totalCount"] / page_size))
        if page_count < 2:
            return results
        for page in await asyncio.gather(*[
            # _request() rather than post(), so we can turn off retries
            self._request("post",
                cmd,
                json={**query, "page": page_num, "limit": page_size},
                timeout=timeout,
                retrying=True,
            )
            for page_num in range(2, page_count + 1)
        ]):
            results.extend(page["list"])
        return results

    async def _request(
        self,
        method: str,
        cmd: str,
        uri_params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        timeout: aiohttp.ClientTimeout | None = None,
        retrying: bool = False,
    ) -> Any:
        if not self.__base_url or not self.__service_ticket:
            raise RuntimeError(ERROR_NO_SESSION)

        params = {"serviceTicket": self.__service_ticket}
        if uri_params:
            params |= uri_params

        kwargs: dict[str, Any] = {
            "params": params,
            "timeout": cast_timeout(timeout),
            "allow_redirects": False,
        }
        if json is not None:
            kwargs["json"] = json

        client_method = getattr(self.__client, method)
        async with client_method(self.__base_url / cmd, **kwargs) as response:
            if response.status == 401:
                if retrying:
                    raise AuthorizationError(ERROR_POST_REDIRECTED)
                await self.login()
                return await self._request(method, cmd, uri_params, json, timeout, True)
            return await self._parse_response(response)

    @staticmethod
    async def _parse_response(response: aiohttp.ClientResponse) -> Any:
        if response.status == 200:
            return await response.json() if response.content_type == "application/json" else None
        elif response.status in (201, 202, 204):
            return None
        elif response.status == 403:
            raise AuthorizationError(ERROR_POST_REDIRECTED)
        try:
            response_json = await response.json()
            error_code = response_json["errorCode"]
        except:
            raise RuntimeError(response.status)
        raise BusinessRuleError(response_json["message"] if error_code == 0 else f"{response_json["errorType"]}: {response_json["message"]}")

