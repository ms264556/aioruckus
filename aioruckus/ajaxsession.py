"""Ruckus AbcSession which connects to Ruckus Unleashed or ZoneDirector via HTTPS AJAX"""

from typing import Any, TYPE_CHECKING
from urllib.parse import urlparse
import asyncio
import ssl
import aiohttp
import xmltodict

from .abcsession import AbcSession, ConfigItem
from .exceptions import AuthenticationError
from .const import (
    ERROR_POST_NORESULT,
    ERROR_POST_REDIRECTED,
    ERROR_CONNECT_EOF,
    ERROR_CONNECT_TEMPORARY,
    ERROR_CONNECT_TIMEOUT,
    ERROR_LOGIN_INCORRECT
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
        self.base_url = None
        self._api = None

        # ZoneDirector / Unleashed Session State
        self.__login_url = None
        self.cmdstat_url = None
        self.conf_url = None

        # SmartZone State
        self.__service_ticket = None

        # Ruckus One State
        self.__tenant_id = None
        self.__bearer_token = None

        # API Implementation

    async def __aenter__(self) -> "AjaxSession":
        await self.login()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def login(self) -> None:
        """Create HTTPS AJAX session."""
        # locate the admin pages: /admin/* for Unleashed and ZD 9.x, /admin10/* for ZD 10.x
        try:
            if self.host.lower().startswith("https://"):
                parsed_url = urlparse(self.host)
                if (parsed_url.netloc == "ruckus.cloud" or parsed_url.netloc.endswith(".ruckus.cloud")):
                    return await self.r1_login()
            if self.host.endswith(":8443"):
                # Allow short-circuit SmartZone identification, in case
                # it's sharing a public IP address with other web services
                return await self.sz_login()
            async with self.websession.head(
                f"https://{self.host}", timeout=3, allow_redirects=False
            ) as head:
                if (head.status >= 400 and head.status < 500):
                    # Request Refused - maybe one-interface SmartZone
                    return await self.sz_login()
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
        except KeyError as kerr:
            raise ConnectionError(ERROR_CONNECT_EOF) from kerr
        except aiohttp.client_exceptions.ClientConnectorError as cerr:
            # Connection Error - maybe three-interface SmartZone
            try:
                return await self.sz_login()
            except:
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

    async def r1_login(self) -> None:
        """Create Ruckus One session."""
        try:
            parsed_url = urlparse(self.host)
            api_netloc = "api.ruckus.cloud"
            if parsed_url.netloc.endswith("eu.ruckus.cloud"):
                api_netloc = "api.eu.ruckus.cloud"
            elif parsed_url.netloc.endswith("asia.ruckus.cloud"):
                api_netloc = "api.asia.ruckus.cloud"
            self.base_url = f"{parsed_url.scheme}://{api_netloc}"
            self.__tenant_id = parsed_url.path[1:33]

            async with self.websession.post(
                f"{self.base_url}/oauth2/token/{self.__tenant_id}",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={"grant_type": "client_credentials", "client_id": self.username, "client_secret": self.password},
                timeout=20,
                allow_redirects=False
            ) as oauth2:
                if oauth2.status != 200:
                    raise AuthenticationError(ERROR_LOGIN_INCORRECT)
                oauth_info = await oauth2.json()
                self.__bearer_token = f"Bearer {oauth_info['access_token']}"
            # pylint: disable=import-outside-toplevel
            from .r1ajaxapi import R1AjaxApi
            self._api = R1AjaxApi(self)
            return self
        except KeyError as kerr:
            raise ConnectionError(ERROR_CONNECT_EOF) from kerr
        except IndexError as ierr:
            raise ConnectionError(ERROR_CONNECT_EOF) from ierr
        except aiohttp.ContentTypeError as cterr:
            raise ConnectionError(ERROR_CONNECT_EOF) from cterr
        except aiohttp.client_exceptions.ClientConnectorError as cerr:
            raise ConnectionError(ERROR_CONNECT_EOF) from cerr
        except asyncio.exceptions.TimeoutError as terr:
            raise ConnectionError(ERROR_CONNECT_TIMEOUT) from terr


    async def sz_login(self) -> None:
        """Create SmartZone session."""
        try:
            api_host = self.host.split(":")[0]
            base_url = f"https://{api_host}:8443/wsg/api/public"
            async with self.websession.get(
                f"{base_url}/apiInfo", timeout=3, allow_redirects=False
            ) as api_info:
                api_versions = await api_info.json()
                self.base_url = f"{base_url}/{api_versions['apiSupportVersions'][-1]}"
                jsessionid = api_info.cookies["JSESSIONID"]
                self.websession.cookie_jar.update_cookies({jsessionid.key: jsessionid.value})
                self.websession.headers["Content-Type"] = "application/json;charset=UTF-8"
                async with self.websession.post(
                    f"{self.base_url}/serviceTicket",
                    json={
                        "username": self.username,
                        "password": self.password
                    },
                    timeout=3,
                    allow_redirects=False
                ) as service_ticket:
                    ticket_info = await service_ticket.json()
                    if service_ticket.status != 200:
                        error_code = ticket_info["errorCode"]
                        if 200 <= error_code < 300:
                            raise AuthenticationError(ticket_info["errorType"])
                        raise ConnectionError(ticket_info["errorType"])
                    self.__service_ticket = ticket_info["serviceTicket"]
            # pylint: disable=import-outside-toplevel
            from .smartzoneajaxapi import SmartZoneAjaxApi
            self._api = SmartZoneAjaxApi(self)
            return self
        except KeyError as kerr:
            raise ConnectionError(ERROR_CONNECT_EOF) from kerr
        except IndexError as ierr:
            raise ConnectionError(ERROR_CONNECT_EOF) from ierr
        except aiohttp.ContentTypeError as cterr:
            raise ConnectionError(ERROR_CONNECT_EOF) from cterr
        except aiohttp.client_exceptions.ClientConnectorError as cerr:
            raise ConnectionError(ERROR_CONNECT_EOF) from cerr
        except asyncio.exceptions.TimeoutError as terr:
            raise ConnectionError(ERROR_CONNECT_TIMEOUT) from terr

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

    async def get_conf_str(self, item: ConfigItem, timeout: int | None = None) -> str:
        return await self.request(
            self.conf_url,
            f"<ajax-request action='getconf' DECRYPT_X='true' "
            f"updater='{item.value}.0.5' comp='{item.value}'/>",
            timeout
        )

    async def request_file(self, file_url: str, timeout: int | None = None, retrying: bool = False) -> str:
        """File Download"""
        async with self.websession.get(
            file_url,
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
                return await self.request_file(file_url, timeout, retrying=True)
            return await response.read()

    async def sz_query(
            self,
            cmd: str,
            query: dict = None,
            timeout: int | None = None
    ) -> dict:
        """Query SZ Data"""
        return (await self.sz_post(f"query/{cmd}", query, timeout))["list"]

    async def r1_get(
        self,
        cmd: str,
        params: dict = None,
        timeout: int | None = None,
        retrying: bool = False
    ) -> dict:
        """Get R1 Data"""
        async with self.websession.get(
            f"{self.base_url}/{cmd}",
            headers={"Authorization": self.__bearer_token},
            params=params,
            timeout=timeout,
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
        uri_params: dict = None,
        timeout: int | None = None,
        retrying: bool = False
    ) -> dict:
        """Get SZ Data"""
        params = {"serviceTicket": self.__service_ticket}
        if uri_params and isinstance(uri_params, dict):
            params.update(uri_params)
        async with self.websession.get(
            f"{self.base_url}/{cmd}",
            params=params,
            timeout=timeout,
            allow_redirects=False
        ) as response:
            if response.status != 200:
                # assume session is dead and re-login
                if retrying:
                    # we tried logging in again, but the redirect still happens.
                    # an exception should have been raised from the login!
                    raise AuthenticationError(ERROR_POST_REDIRECTED)
                await self.sz_login()  # try logging in again, then retry post
                return await self.sz_get(cmd, uri_params, timeout, retrying=True)
            result_json = await response.json()
            return result_json

    async def sz_post(
        self,
        cmd: str,
        json: dict = None,
        timeout: int | None = None,
        retrying: bool = False
    ) -> dict:
        """Post SZ Data"""
        async with self.websession.post(
            f"{self.base_url}/{cmd}",
            params={"serviceTicket": self.__service_ticket},
            json=json or {},
            timeout=timeout,
            allow_redirects=False
        ) as response:
            if response.status != 200:
                # assume session is dead and re-login
                if retrying:
                    # we tried logging in again, but the redirect still happens.
                    # an exception should have been raised from the login!
                    raise AuthenticationError(ERROR_POST_REDIRECTED)
                await self.sz_login()  # try logging in again, then retry post
                return await self.sz_post(cmd, json, timeout, retrying=True)
            result_json = await response.json()
            return result_json
