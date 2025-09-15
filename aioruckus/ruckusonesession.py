from __future__ import annotations
import asyncio
from math import ceil
from typing import Any

import aiohttp
from yarl import URL

from .const import ERROR_CONNECT_EOF, ERROR_CONNECT_TIMEOUT, ERROR_LOGIN_INCORRECT, ERROR_NO_SESSION, ERROR_POST_BADRESULT, ERROR_POST_REDIRECTED
from .exceptions import AuthenticationError, AuthorizationError, BusinessRuleError
from .utility import *

class RuckusOneSession:
    host: str
    username: str
    password: str
    __client: aiohttp.ClientSession
    __base_url: URL | None = None
    __tenant_id: str | None = None
    __bearer_token: str | None = None

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

    async def __aenter__(self) -> RuckusOneSession:
        await self.login()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def login(self) -> RuckusOneSession:
        """Create Ruckus One session."""
        try:
            parsed_url = get_host_url(self.host)
            assert parsed_url.host is not None

            api_netloc = "api.ruckus.cloud"
            if parsed_url.host.endswith("eu.ruckus.cloud"):
                api_netloc = "api.eu.ruckus.cloud"
            elif parsed_url.host.endswith("asia.ruckus.cloud"):
                api_netloc = "api.asia.ruckus.cloud"
            self.__base_url = URL.build(scheme=parsed_url.scheme or "https", host=api_netloc)
            self.__tenant_id = parsed_url.path.strip('/')[0:32]

            async with self.__client.post(
                self.__base_url / "oauth2/token" / self.__tenant_id,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={"grant_type": "client_credentials", "client_id": self.username, "client_secret": self.password},
                timeout=aiohttp.ClientTimeout(total=20),
                allow_redirects=False
            ) as oauth2:
                if oauth2.status != 200:
                    raise AuthenticationError(ERROR_LOGIN_INCORRECT)
                oauth_info = await oauth2.json()
                self.__bearer_token = f"Bearer {oauth_info['access_token']}"
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
        """Logout of Ruckus One and close websession"""
        if self.__auto_cleanup_websession:
            await self.__client.close()

    async def get(self, cmd: str, params: dict | None = None, timeout: aiohttp.ClientTimeout | int | None = None) -> Any:
        return await self._request("get", cmd, uri_params=params, timeout=timeout)

    async def post(self, cmd: str, json: dict | None = None, timeout: aiohttp.ClientTimeout | int | None = None) -> Any:
        return await self._request("post", cmd, json=json, timeout=timeout)

    async def put(self, cmd: str, json: dict | None = None,timeout: aiohttp.ClientTimeout | int | None = None, fire_and_forget: bool = False) -> Any:
        return await self._request("put", cmd, json=json, timeout=timeout, fire_and_forget=fire_and_forget)

    async def patch(self, cmd: str, json: dict | None = None, timeout: aiohttp.ClientTimeout | int | None = None, fire_and_forget: bool = False) -> Any:
        return await self._request("patch", cmd, json=json, timeout=timeout, fire_and_forget=fire_and_forget)

    async def delete(self, cmd: str, json: dict | None = None, timeout: aiohttp.ClientTimeout | int | None = None, fire_and_forget: bool = False) -> Any:
        return await self._request("delete", cmd, json=json, timeout=timeout, fire_and_forget=fire_and_forget)

    async def query(self, cmd: str, params: dict | None = None, page_size: int = 5, pages_limit: int = 100, timeout: aiohttp.ClientTimeout | int | None = None) -> list:
        query = params or {}
        timeout = cast_timeout(timeout)

        first_page = await self.post(cmd, {**query, "page": 1, "pageSize": page_size}, timeout)
        results: list[Any] = first_page.get("data", [])
        if not results:
            return results
        page_count = min(pages_limit, ceil(first_page["totalCount"] / page_size))
        if page_count < 2:
            return results
        for page in await asyncio.gather(*[
            # _request() rather than post(), so we can turn off retries
            self._request("post",
                cmd,
                json={**query, "page": page_num, "pageSize": page_size},
                timeout=timeout,
                retrying=True,
            )
            for page_num in range(2, page_count + 1)
        ]):
            results.extend(page["data"])
        return results

    async def _request(
        self,
        method: str,
        cmd: str,
        uri_params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        timeout: aiohttp.ClientTimeout | int | None = None,
        fire_and_forget: bool = False,
        retrying: bool = False,
    ) -> Any:
        if not self.__base_url or not self.__bearer_token:
            raise RuntimeError(ERROR_NO_SESSION)

        kwargs: dict[str, Any] = {
            "headers": {"Authorization": self.__bearer_token},
            "timeout": cast_timeout(timeout),
            "allow_redirects": False,
        }
        if uri_params:
            kwargs["params"] = uri_params
        if json is not None:
            kwargs["json"] = json or {}

        client_method = getattr(self.__client, method)
        async with client_method(self.__base_url / cmd, **kwargs) as response:
            if response.status == 401:
                if retrying:
                    # Already tried logging in again - give up
                    raise AuthorizationError(ERROR_POST_REDIRECTED)
                await self.login()
                return await self._request(method, cmd, uri_params, json, timeout, fire_and_forget, retrying=True)
            return await self._parse_response(response, fire_and_forget)
    
    async def _parse_response(self, response: aiohttp.ClientResponse, fire_and_forget: bool = False) -> Any:
        assert self.__base_url and self.__bearer_token
        if response.status == 200:
            return await response.json() if response.content_type.endswith("json") else None
        elif response.status == 202 and not fire_and_forget:
            request_id = (await response.json())["requestId"]
            for i in range(4):
                await asyncio.sleep(i)
                async with self.__client.get(
                    self.__base_url / f"activities/{request_id}",
                    headers={"Authorization": self.__bearer_token},
                    timeout=cast_timeout(3),
                    allow_redirects=False
                ) as activity_update:
                    activity_json = await activity_update.json()
                    activity_status = activity_json.get("status")
                    if activity_status == "SUCCESS":
                        return
                    if activity_status == "FAIL":
                        raise RuntimeError(activity_json.get("error", ERROR_POST_BADRESULT))
            raise RuntimeError(ERROR_CONNECT_TIMEOUT)
        elif response.status in (201, 202, 204):
            return None
        elif response.status == 403:
            raise AuthorizationError(ERROR_POST_REDIRECTED)
        elif response.status == 400:
            response_json = await response.json()
            raise BusinessRuleError(f"{response_json["error"]}: {response_json["path"]}")
        try:
            response_json = await response.json()
            response_error = response_json["errors"][0]
        except:
            raise RuntimeError(response.status)
        raise BusinessRuleError(f"{response_error["message"]}: {response_error["reason"]}")

