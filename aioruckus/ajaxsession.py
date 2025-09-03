"""Ruckus AbcSession which connects to Ruckus Unleashed or ZoneDirector via HTTPS AJAX"""
from __future__ import annotations
from typing import Any, TYPE_CHECKING, cast
from yarl import URL
import asyncio
import ssl
import aiohttp
import xmltodict

from .smartzonetyping import SzPermissionCategories, SzSession
from .abcsession import AbcSession, ConfigItem
from .exceptions import AuthenticationError, AuthorizationError, BusinessRuleError
from .const import (
    ERROR_POST_NORESULT,
    ERROR_POST_REDIRECTED,
    ERROR_CONNECT_EOF,
    ERROR_CONNECT_NOPARSE,
    ERROR_CONNECT_TEMPORARY,
    ERROR_CONNECT_TIMEOUT,
    ERROR_LOGIN_INCORRECT,
    ERROR_NO_SESSION
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

        # Common Session State
        self.base_url: URL | None = None
        self._api: RuckusAjaxApi | None = None

        # ZoneDirector / Unleashed Session State
        self.__login_url: URL | None = None

        # SmartZone State
        self.__service_ticket: str | None = None
        self.smartzone_session: SzSession | None = None

        # Ruckus One State
        self.__tenant_id: str | None = None
        self.__bearer_token: str | None = None

    async def __aenter__(self) -> AjaxSession:
        await self.login()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def login(self) -> None:
        """Create HTTPS AJAX session."""
        target_url = self._get_host_url()
        assert target_url.host is not None

        # Short-circuit Ruckus One identification
        if target_url.host == "ruckus.cloud" or target_url.host.endswith(".ruckus.cloud"):
            return await self.r1_login()
        # Short-circuit SmartZone identification
        if target_url.port == 8443:
            return await self.sz_login()

        # locate the admin pages: /admin/* for Unleashed and ZD 9.x, /admin10/* for ZD 10.x
        try:
            async with self.websession.head(
                target_url, timeout=aiohttp.ClientTimeout(total=3), allow_redirects=False
            ) as head:
                if 400 <= head.status < 500:
                    # Request Refused - maybe one-interface SmartZone
                    return await self.sz_login()
                # Resolve the redirect URL against the request URL to handle relative paths
                login_candidate_url = head.url.join(URL(head.headers["Location"]))

            # Handle Unleashed Member -> Master redirect, which might be a two-step redirect
            if login_candidate_url.path == '/':
                async with self.websession.head(
                    login_candidate_url, timeout=aiohttp.ClientTimeout(total=3), allow_redirects=False
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
            timeout=aiohttp.ClientTimeout(total=3),
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
                    timeout=aiohttp.ClientTimeout(total=3),
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

    async def r1_login(self) -> None:
        """Create Ruckus One session."""
        try:
            parsed_url = self._get_host_url()
            assert parsed_url.host is not None

            api_netloc = "api.ruckus.cloud"
            if parsed_url.host.endswith("eu.ruckus.cloud"):
                api_netloc = "api.eu.ruckus.cloud"
            elif parsed_url.host.endswith("asia.ruckus.cloud"):
                api_netloc = "api.asia.ruckus.cloud"
            self.base_url = URL.build(scheme=parsed_url.scheme or "https", host=api_netloc)
            self.__tenant_id = parsed_url.path.strip('/')[0:32]

            async with self.websession.post(
                self.base_url / "oauth2/token" / self.__tenant_id,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={"grant_type": "client_credentials", "client_id": self.username, "client_secret": self.password},
                timeout=aiohttp.ClientTimeout(total=20),
                allow_redirects=False
            ) as oauth2:
                if oauth2.status != 200:
                    raise AuthenticationError(ERROR_LOGIN_INCORRECT)
                oauth_info = await oauth2.json()
                self.__bearer_token = f"Bearer {oauth_info['access_token']}"
            # pylint: disable=import-outside-toplevel
            from .r1ajaxapi import R1AjaxApi
            self._api = R1AjaxApi(self)
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

    async def sz_login(self) -> None:
        """Create SmartZone session."""
        try:
            target_url = self._get_host_url()
            assert target_url.host is not None

            base_url = URL.build(scheme="https", host=target_url.host, port=8443, path="/wsg/api/public")
            async with self.websession.get(
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

                self.base_url = base_url / latest_version
                self.websession.headers["Content-Type"] = "application/json;charset=UTF-8"

                async with self.websession.post(
                    self.base_url / "serviceTicket",
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

                async with self.websession.get(
                    self.base_url / "userGroups/currentUser/permissionCategories",
                    params={"serviceTicket": self.__service_ticket},
                    allow_redirects=False
                ) as user_permissions:
                    permission_categories = cast(SzPermissionCategories, await user_permissions.json())

                async with self.websession.get(
                    self.base_url / "session",
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
                    async with self.websession.get(
                        self.base_url / "controlPlanes",
                        params={"serviceTicket": self.__service_ticket},
                        allow_redirects=False
                    ) as control_planes:
                        planes = await control_planes.json()
                        plane = next((p for p in planes["list"] if p["id"] == cp_id), None)
                        if plane:
                            session_info["cpName"] = plane["name"]
                            session_info["cpSerialNumber"] = plane["serialNumber"]

                self.smartzone_session = cast(SzSession, session_info)
            # pylint: disable=import-outside-toplevel
            from .smartzoneajaxapi import SmartZoneAjaxApi
            self._api = SmartZoneAjaxApi(self)
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

    def _get_host_url(self) -> URL:
        """Normalize the host input to a URL."""
        host_str = self.host
        if '://' not in host_str:
            host_str = f"https://{host_str}"
        parsed_url = URL(host_str)
        if not parsed_url.host:
            raise ConnectionError(ERROR_CONNECT_NOPARSE)
        return parsed_url

    async def close(self) -> None:
        """Logout of ZoneDirector/Unleashed and close websessiom"""
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

    @property
    def api(self) -> RuckusAjaxApi:
        """Return a RuckusApi instance. Raises RuntimeError if not logged in."""
        # This check acts as the main gatekeeper. If the session isn't
        # initialized, you can't get an API object to work with.
        if self.base_url is None:
            raise RuntimeError(ERROR_NO_SESSION)
        
        if not self._api:
            # pylint: disable=import-outside-toplevel
            from .ruckusajaxapi import RuckusAjaxApi
            self._api = RuckusAjaxApi(self)
        return self._api

    @staticmethod
    def async_create(host: str, username: str, password: str) -> AjaxSession:
        """Create a default ClientSession & use this to create an AjaxSession instance"""
        # create SSLContext which ignores certificate errors and allows old ciphers
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context.set_ciphers("DEFAULT")
        # create ClientSession using our SSLContext, allowing cookies on IP address URLs,
        # with a short keepalive for compatibility with old Unleashed versions
        websession = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            cookie_jar=aiohttp.CookieJar(unsafe=True),
            connector=aiohttp.TCPConnector(keepalive_timeout=5, ssl_context=ssl_context),
        )
        return AjaxSession(websession, host, username, password, auto_cleanup_websession=True)

    async def get_conf_str(self, item: ConfigItem, timeout: aiohttp.ClientTimeout | int | None = None) -> str:
        if not self.base_url:
            raise RuntimeError(ERROR_NO_SESSION)
        
        conf_url = self.base_url / "_conf.jsp"
        return await self.request(
            conf_url,
            f"<ajax-request action='getconf' DECRYPT_X='true' "
            f"updater='{item.value}.0.5' comp='{item.value}'/>",
            timeout
        )

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

    async def sz_query(
            self,
            cmd: str,
            query: dict | None = None,
            timeout: aiohttp.ClientTimeout | int | None = None
    ) -> list[Any]:
        """Query SZ Data"""
        return (await self.sz_post(f"query/{cmd}", query, timeout))["list"]

    async def r1_get(
        self,
        cmd: str,
        params: dict | None = None,
        timeout: aiohttp.ClientTimeout | int | None = None,
        retrying: bool = False
    ) -> Any:
        """Get R1 Data"""
        if not self.base_url or not self.__bearer_token:
            raise RuntimeError(ERROR_NO_SESSION)
        
        if isinstance(timeout, int):
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
        else:
            timeout_obj = timeout
            
        async with self.websession.get(
            self.base_url / cmd,
            headers={"Authorization": self.__bearer_token},
            params=params,
            timeout=timeout_obj,
            allow_redirects=False
        ) as response:
            if response.status != 200:
                # assume session is dead and re-login
                if retrying:
                    # we tried logging in again, but the redirect still happens.
                    # an exception should have been raised from the login!
                    raise AuthenticationError(ERROR_POST_REDIRECTED)
                await self.r1_login()  # try logging in again, then retry post
                return await self.r1_get(cmd, params, timeout, retrying=True)
            result_json = await response.json()
            return result_json

    async def sz_get(
        self,
        cmd: str,
        uri_params: dict | None = None,
        timeout: aiohttp.ClientTimeout | int | None = None,
        retrying: bool = False
    ) -> Any:
        """Get SZ Data"""
        if not self.base_url or not self.__service_ticket:
            raise RuntimeError(ERROR_NO_SESSION)
        
        params = {"serviceTicket": self.__service_ticket}
        if uri_params and isinstance(uri_params, dict):
            params.update(uri_params)

        async with self.websession.get(
            self.base_url / cmd,
            params=params,
            timeout=self._cast_timeout(timeout),
            allow_redirects=False
        ) as response:
            if response.status == 401:
                if retrying:
                    # already tried logging in again - give up
                    raise AuthorizationError(ERROR_POST_REDIRECTED)
                await self.sz_login()
                return await self.sz_get(cmd, uri_params, timeout, retrying=True)
            return await self._validate_sz_response(response)    

    async def sz_post(
        self,
        cmd: str,
        json: dict | None = None,
        timeout: aiohttp.ClientTimeout | int | None = None,
        retrying: bool = False
    ) -> Any:
        """Post SZ Data"""
        if not self.base_url or not self.__service_ticket:
            raise RuntimeError(ERROR_NO_SESSION)
        
        async with self.websession.post(
            self.base_url / cmd,
            params={"serviceTicket": self.__service_ticket},
            json=json or {},
            timeout=self._cast_timeout(timeout),
            allow_redirects=False
        ) as response:
            if response.status == 401:
                if retrying:
                   # already tried logging in again - give up
                   raise AuthorizationError(ERROR_POST_REDIRECTED)
                await self.sz_login()  # try logging in again, then retry post
                return await self.sz_post(cmd, json, timeout, retrying=True)
            return await self._validate_sz_response(response)

    async def sz_put(
        self,
        cmd: str,
        json: dict | None = None,
        timeout: aiohttp.ClientTimeout | int | None = None,
        retrying: bool = False
    ) -> None:
        """Put SZ Data"""
        if not self.base_url or not self.__service_ticket:
            raise RuntimeError(ERROR_NO_SESSION)
        
        async with self.websession.put(
            self.base_url / cmd,
            params={"serviceTicket": self.__service_ticket},
            json=json or {},
            timeout=self._cast_timeout(timeout),
            allow_redirects=False
        ) as response:
            if response.status == 401:
                if retrying:
                   # already tried logging in again - give up
                   raise AuthorizationError(ERROR_POST_REDIRECTED)
                await self.sz_login()  # try logging in again, then retry post
                return await self.sz_put(cmd, json, timeout, retrying=True)
            await self._validate_sz_response(response)

    async def sz_patch(
        self,
        cmd: str,
        json: dict | None = None,
        timeout: aiohttp.ClientTimeout | int | None = None,
        retrying: bool = False
    ) -> None:
        """Patch SZ Data"""
        if not self.base_url or not self.__service_ticket:
            raise RuntimeError(ERROR_NO_SESSION)
        
        async with self.websession.put(
            self.base_url / cmd,
            params={"serviceTicket": self.__service_ticket},
            json=json or {},
            timeout=self._cast_timeout(timeout),
            allow_redirects=False
        ) as response:
            if response.status == 401:
                if retrying:
                   # already tried logging in again - give up
                   raise AuthorizationError(ERROR_POST_REDIRECTED)
                await self.sz_login()  # try logging in again, then retry post
                return await self.sz_patch(cmd, json, timeout, retrying=True)
            await self._validate_sz_response(response)

    async def sz_delete(
        self,
        cmd: str,
        json: dict | None = None,
        timeout: aiohttp.ClientTimeout | int | None = None,
        retrying: bool = False
    ) -> None:
        """Put SZ Data"""
        if not self.base_url or not self.__service_ticket:
            raise RuntimeError(ERROR_NO_SESSION)

        async with self.websession.delete(
            self.base_url / cmd,
            params={"serviceTicket": self.__service_ticket},
            json=json or {},
            timeout=self._cast_timeout(timeout),
            allow_redirects=False
        ) as response:
            if response.status == 401:
                if retrying:
                   # already tried logging in again - give up
                   raise AuthorizationError(ERROR_POST_REDIRECTED)
                await self.sz_login()  # try logging in again, then retry post
                return await self.sz_delete(cmd, json, timeout, retrying=True)
            await self._validate_sz_response(response)
    
    @staticmethod
    async def _validate_sz_response(response: aiohttp.ClientResponse) -> Any:
        if response.status == 200:
            return await response.json() if response.content_type == "application/json" else None
        if response.status in (201, 204):
            return None
        if response.status == 403:
            raise AuthorizationError(ERROR_POST_REDIRECTED)
        try:
            response_json = await response.json()
            error_code = response_json["errorCode"]
        except:
            raise RuntimeError(response.status)
        raise BusinessRuleError(response_json["message"] if error_code == 0 else f"{response_json["errorType"]}: {response_json["message"]}")

    @staticmethod
    def _cast_timeout(timeout: aiohttp.ClientTimeout | int | None) -> aiohttp.ClientTimeout | None:
        return aiohttp.ClientTimeout(total=timeout) if isinstance(timeout, int) else timeout
    